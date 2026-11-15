//go:build go1.24

package tls

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	mDNS "github.com/miekg/dns"
	"golang.org/x/crypto/cryptobyte"
)

const echCacheGracePeriod = 4 * time.Hour

func parseECHClientConfig(ctx context.Context, clientConfig ECHCapableConfig, options option.OutboundTLSOptions) (Config, error) {
	var echConfig []byte
	if len(options.ECH.Config) > 0 {
		echConfig = []byte(strings.Join(options.ECH.Config, "\n"))
	} else if options.ECH.ConfigPath != "" {
		content, err := filemanager.ReadFile(ctx, options.ECH.ConfigPath)
		if err != nil {
			return nil, E.Cause(err, "read ECH config")
		}
		echConfig = content
	}
	//nolint:staticcheck
	if options.ECH.PQSignatureSchemesEnabled || options.ECH.DynamicRecordSizingDisabled {
		return nil, E.New("legacy ECH options are deprecated in sing-box 1.12.0 and removed in sing-box 1.13.0")
	}
	if len(echConfig) > 0 {
		block, rest := pem.Decode(echConfig)
		if block == nil || block.Type != "ECH CONFIGS" || len(rest) > 0 {
			return nil, E.New("invalid ECH configs pem")
		}
		if len(block.Bytes) == 0 {
			return nil, E.New("empty ECH configs pem")
		}
		clientConfig.SetECHConfigList(block.Bytes)
		return clientConfig, nil
	} else {
		return &ECHClientConfig{
			ECHCapableConfig: clientConfig,
			dnsRouter:        service.FromContext[adapter.DNSRouter](ctx),
			queryServerName:  options.ECH.QueryServerName,
			cache:            &echConfigCache{},
		}, nil
	}
}

func parseECHServerConfig(ctx context.Context, options option.InboundTLSOptions, tlsConfig *tls.Config, echKeyPath *string) error {
	var echKey []byte
	if len(options.ECH.Key) > 0 {
		echKey = []byte(strings.Join(options.ECH.Key, "\n"))
	} else if options.ECH.KeyPath != "" {
		content, err := filemanager.ReadFile(ctx, options.ECH.KeyPath)
		if err != nil {
			return E.Cause(err, "read ECH keys")
		}
		echKey = content
		*echKeyPath = options.ECH.KeyPath
	} else {
		return E.New("missing ECH keys")
	}
	echKeys, err := parseECHKeys(echKey)
	if err != nil {
		return E.Cause(err, "parse ECH keys")
	}
	tlsConfig.EncryptedClientHelloKeys = echKeys
	//nolint:staticcheck
	if options.ECH.PQSignatureSchemesEnabled || options.ECH.DynamicRecordSizingDisabled {
		return E.New("legacy ECH options are deprecated in sing-box 1.12.0 and removed in sing-box 1.13.0")
	}
	return nil
}

func (c *STDServerConfig) setECHServerConfig(echKey []byte) error {
	echKeys, err := parseECHKeys(echKey)
	if err != nil {
		return err
	}
	c.access.Lock()
	config := c.config.Clone()
	config.EncryptedClientHelloKeys = echKeys
	c.config = config
	c.access.Unlock()
	return nil
}

func parseECHKeys(echKey []byte) ([]tls.EncryptedClientHelloKey, error) {
	block, _ := pem.Decode(echKey)
	if block == nil || block.Type != "ECH KEYS" {
		return nil, E.New("invalid ECH keys pem")
	}
	echKeys, err := UnmarshalECHKeys(block.Bytes)
	if err != nil {
		return nil, E.Cause(err, "parse ECH keys")
	}
	return echKeys, nil
}

type echCacheEntry struct {
	configList []byte
	expiresAt  time.Time
}

type echConfigCache struct {
	entry      atomic.Pointer[echCacheEntry]
	updateLock sync.Mutex
}

type ECHClientConfig struct {
	ECHCapableConfig
	dnsRouter       adapter.DNSRouter
	queryServerName string
	cache           *echConfigCache
}

func (s *ECHClientConfig) ECHConfigList() []byte {
	if s.cache != nil {
		if entry := s.cache.entry.Load(); entry != nil {
			return entry.configList
		}
	}
	return s.ECHCapableConfig.ECHConfigList()
}

func (s *ECHClientConfig) SetECHConfigList(configList []byte) {
	if s.cache != nil {
		copied := append([]byte(nil), configList...)
		ttl := time.Minute
		if old := s.cache.entry.Load(); old != nil {
			if remaining := time.Until(old.expiresAt); remaining > ttl {
				ttl = remaining
			}
		}
		s.cache.entry.Store(&echCacheEntry{
			configList: copied,
			expiresAt:  time.Now().Add(ttl),
		})
		return
	}
	s.ECHCapableConfig.SetECHConfigList(configList)
}

func (s *ECHClientConfig) Client(conn net.Conn) (aTLS.Conn, error) {
	if s.cache != nil {
		if entry := s.cache.entry.Load(); entry != nil && len(entry.configList) > 0 {
			cloned := s.ECHCapableConfig.Clone().(ECHCapableConfig)
			cloned.SetECHConfigList(entry.configList)
			return cloned.Client(conn)
		}
	}
	return s.ECHCapableConfig.Client(conn)
}

func (s *ECHClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	tlsConn, err := s.fetchAndHandshake(ctx, conn)
	if err != nil {
		return nil, err
	}
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func (s *ECHClientConfig) fetchAndHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	configList, err := s.resolveConfigList(ctx)
	if err != nil {
		return nil, err
	}
	cloned := s.ECHCapableConfig.Clone().(ECHCapableConfig)
	cloned.SetECHConfigList(configList)
	return cloned.Client(conn)
}

func (s *ECHClientConfig) resolveConfigList(ctx context.Context) ([]byte, error) {
	now := time.Now()
	if s.cache != nil {
		if entry := s.cache.entry.Load(); entry != nil && len(entry.configList) > 0 {
			if now.Before(entry.expiresAt) {
				return entry.configList, nil
			}
			if now.Before(entry.expiresAt.Add(echCacheGracePeriod)) {
				if s.cache.updateLock.TryLock() {
					go func() {
						defer s.cache.updateLock.Unlock()
						refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), C.DNSTimeout)
						defer cancel()
						if cfg, ttl, err := s.queryECH(refreshCtx); err == nil && len(cfg) > 0 {
							s.storeEntry(cfg, ttl)
						}
					}()
				}
				return entry.configList, nil
			}
		}
		s.cache.updateLock.Lock()
		defer s.cache.updateLock.Unlock()
		now = time.Now()
		if entry := s.cache.entry.Load(); entry != nil && len(entry.configList) > 0 && now.Before(entry.expiresAt.Add(echCacheGracePeriod)) {
			return entry.configList, nil
		}
	}
	configList, ttl, err := s.queryECH(ctx)
	if err != nil {
		return nil, err
	}
	if len(configList) == 0 {
		return nil, E.New("no ECH config found in DNS records")
	}
	s.storeEntry(configList, ttl)
	return configList, nil
}

func (s *ECHClientConfig) storeEntry(configList []byte, ttl time.Duration) {
	if s.cache == nil {
		return
	}
	copied := append([]byte(nil), configList...)
	s.cache.entry.Store(&echCacheEntry{
		configList: copied,
		expiresAt:  time.Now().Add(ttl),
	})
}

func (s *ECHClientConfig) queryECH(ctx context.Context) ([]byte, time.Duration, error) {
	if s.dnsRouter == nil {
		return nil, 0, E.New("missing DNS router for ECH query")
	}
	queryServerName := s.queryServerName
	if queryServerName == "" {
		queryServerName = s.ServerName()
	}
	if queryServerName == "" {
		return nil, 0, E.New("missing server name for ECH query")
	}
	message := &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			RecursionDesired: true,
		},
		Question: []mDNS.Question{
			{
				Name:   mDNS.Fqdn(queryServerName),
				Qtype:  mDNS.TypeHTTPS,
				Qclass: mDNS.ClassINET,
			},
		},
	}
	paddingLen := 100 + rand.Intn(201)
	message.SetEdns0(4096, false)
	if opt := message.IsEdns0(); opt != nil {
		opt.Option = append(opt.Option, &mDNS.EDNS0_PADDING{
			Padding: make([]byte, paddingLen),
		})
	}
	response, err := s.dnsRouter.Exchange(ctx, message, adapter.DNSQueryOptions{})
	if err != nil {
		return nil, 0, E.Cause(err, "fetch ECH config list")
	}
	if response.Rcode != mDNS.RcodeSuccess {
		return nil, 0, E.Cause(dns.RcodeError(response.Rcode), "fetch ECH config list")
	}
	for _, rr := range response.Answer {
		switch resource := rr.(type) {
		case *mDNS.HTTPS:
			for _, value := range resource.Value {
				if value.Key().String() == "ech" {
					echConfigList, err := base64.StdEncoding.DecodeString(value.String())
					if err != nil {
						return nil, 0, E.Cause(err, "decode ECH config")
					}
					if len(echConfigList) == 0 {
						return nil, 0, E.New("empty ECH config in DNS records")
					}
					ttl := time.Duration(rr.Header().Ttl) * time.Second
					return echConfigList, ttl, nil
				}
			}
		}
	}
	return nil, 0, E.New("no ECH config found in DNS records")
}

func (s *ECHClientConfig) Clone() Config {
	return &ECHClientConfig{
		ECHCapableConfig: s.ECHCapableConfig.Clone().(ECHCapableConfig),
		dnsRouter:        s.dnsRouter,
		queryServerName:  s.queryServerName,
		cache:            s.cache,
	}
}

func (s *ECHClientConfig) UTLSFingerprint() (string, string, bool) {
	return UTLSFingerprint(s.ECHCapableConfig)
}

func (s *ECHClientConfig) SupportsQUIC() bool {
	return SupportsQUIC(s.ECHCapableConfig)
}

func (s *ECHClientConfig) STDConfigForQUIC() (*STDConfig, error) {
	return s.STDConfigForQUICContext(context.Background())
}

// STDConfigForQUICContext resolves any dynamic DNS ECH configuration list using
// ctx and applies it to a cloned *STDConfig safe for QUIC/ChromeParrot dials.
func (s *ECHClientConfig) STDConfigForQUICContext(ctx context.Context) (*STDConfig, error) {
	if s.cache != nil {
		configList, err := s.resolveConfigList(ctx)
		if err != nil {
			return nil, err
		}
		stdCfg, err := STDConfigForQUICContext(ctx, s.ECHCapableConfig)
		if err != nil {
			return nil, err
		}
		cloned := stdCfg.Clone()
		cloned.EncryptedClientHelloConfigList = append([]byte(nil), configList...)
		return cloned, nil
	}
	return STDConfigForQUICContext(ctx, s.ECHCapableConfig)
}

// RefreshECHConfigList bypasses any fresh cache entry and fetches the latest ECH
// config list from DNS (no-op returning static config when caching is not used).
func (s *ECHClientConfig) RefreshECHConfigList(ctx context.Context) ([]byte, error) {
	if s.cache == nil {
		return s.ECHConfigList(), nil
	}
	s.cache.updateLock.Lock()
	defer s.cache.updateLock.Unlock()
	configList, ttl, err := s.queryECH(ctx)
	if err != nil {
		return nil, err
	}
	s.storeEntry(configList, ttl)
	return append([]byte(nil), configList...), nil
}

func UnmarshalECHKeys(raw []byte) ([]tls.EncryptedClientHelloKey, error) {
	var keys []tls.EncryptedClientHelloKey
	rawString := cryptobyte.String(raw)
	for !rawString.Empty() {
		var key tls.EncryptedClientHelloKey
		if !rawString.ReadUint16LengthPrefixed((*cryptobyte.String)(&key.PrivateKey)) {
			return nil, E.New("error parsing private key")
		}
		if !rawString.ReadUint16LengthPrefixed((*cryptobyte.String)(&key.Config)) {
			return nil, E.New("error parsing config")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, E.New("empty ECH keys")
	}
	return keys, nil
}
