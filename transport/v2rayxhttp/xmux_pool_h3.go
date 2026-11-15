//go:build with_quic

package v2rayxhttp

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"errors"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-mux"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	h3Supported                 = true
	chromeH3MaxFieldSectionSize = 262144
	h3DefaultKeepAlivePeriod    = 15 * time.Second
)

type h3ClientConn struct {
	cc        *http3.ClientConn
	qConn     *quic.Conn
	transport *http3.Transport
	udpConn   net.Conn
	closeOnce sync.Once
}

type quicSTDConfigAdapter struct {
	tls.Config
	stdCfg *stdtls.Config
}

func (a quicSTDConfigAdapter) STDConfig() (*stdtls.Config, error) {
	return a.stdCfg, nil
}

func chromeH3GreaseSetting() (uint64, uint64) {
	// RFC 9114 Section 7.2.4.1 GREASE identifier: 0x1f * N + 0x21.
	n := uint64(rand.Int63n(1<<20) + 1)
	id := 0x1f*n + 0x21
	val := uint64(rand.Uint32())
	return id, val
}

func buildXHTTPQUICConfig(opt *option.QUICOptions, idleTimeout, pingTimeout time.Duration, allow0RTT bool, isClient bool) *quic.Config {
	chromeParrot := isClient && (opt == nil || !opt.DisableChromeParrot)
	quicConfig := &quic.Config{
		Allow0RTT:       allow0RTT,
		ChromeParrot:    chromeParrot,
		EnableDatagrams: chromeParrot,
	}
	if idleTimeout > 0 {
		quicConfig.MaxIdleTimeout = idleTimeout
	}
	if pingTimeout > 0 {
		quicConfig.KeepAlivePeriod = pingTimeout
	} else if isClient {
		// Prevent carrier/NAT UDP mapping expiry on idle multiplexed H3 streams.
		quicConfig.KeepAlivePeriod = h3DefaultKeepAlivePeriod
	}
	if opt == nil {
		return quicConfig
	}
	var mapped qtls.QUICOptions
	mapped.IdleTimeout = time.Duration(opt.IdleTimeout)
	mapped.KeepAlivePeriod = time.Duration(opt.KeepAlivePeriod)
	if opt.StreamReceiveWindow != nil {
		mapped.StreamReceiveWindow = opt.StreamReceiveWindow.Value()
	}
	if opt.ConnectionReceiveWindow != nil {
		mapped.ConnectionReceiveWindow = opt.ConnectionReceiveWindow.Value()
	}
	mapped.MaxConcurrentStreams = opt.MaxConcurrentStreams
	mapped.InitialPacketSize = opt.InitialPacketSize
	mapped.DisablePathMTUDiscovery = opt.DisablePathMTUDiscovery
	qtls.ApplyQUICOptions(quicConfig, mapped)
	return quicConfig
}

func (p *xmuxHTTPPool) dialH3Conn(ctx context.Context, limit mux.XmuxSessionLimit) (*xmuxHTTPConn, error) {
	if p.tlsConfig == nil {
		return nil, http.ErrNotSupported
	}
	h3TLS := p.tlsConfig.Clone()
	h3TLS.SetNextProtos([]string{h3NextProto})
	if p.tlsConfig.ServerName() != "" {
		h3TLS.SetServerName(p.tlsConfig.ServerName())
	} else if !p.target.IsIP() && p.target.Fqdn != "" {
		h3TLS.SetServerName(p.target.Fqdn)
	}
	dialCtx := ctx
	var cancel context.CancelFunc
	if p.hasTCPFallback {
		// Fail fast when UDP is filtered so fallback to TCP H2 stays responsive.
		attemptTimeout := h3FallbackDialTimeout
		if ht := h3TLS.HandshakeTimeout(); ht > 0 && ht < attemptTimeout {
			attemptTimeout = ht
		}
		if deadline, hasDeadline := ctx.Deadline(); !hasDeadline || time.Until(deadline) > attemptTimeout {
			dialCtx, cancel = context.WithTimeout(ctx, attemptTimeout)
			defer cancel()
		}
	}

	stdCfg, err := tls.STDConfigForQUICContext(dialCtx, h3TLS)
	if err != nil {
		return nil, err
	}

	target := p.h3DialTarget()
	conn, err := p.dialH3Attempt(dialCtx, target, h3TLS, stdCfg, limit)
	if err == nil {
		return conn, nil
	}
	if dialCtx.Err() != nil {
		return nil, err
	}
	if retryList, ok := p.refreshRejectedECHConfigList(dialCtx, err, h3TLS, stdCfg.EncryptedClientHelloConfigList); ok {
		retryCfg := stdCfg.Clone()
		retryCfg.EncryptedClientHelloConfigList = append([]byte(nil), retryList...)
		return p.dialH3Attempt(dialCtx, target, h3TLS, retryCfg, limit)
	}
	return nil, err
}

func (p *xmuxHTTPPool) refreshRejectedECHConfigList(dialCtx context.Context, dialErr error, h3TLS tls.Config, attempted []byte) ([]byte, bool) {
	var echErr *stdtls.ECHRejectionError
	if errors.As(dialErr, &echErr) && len(echErr.RetryConfigList) > 0 {
		for _, cfg := range []tls.Config{p.tlsConfig, h3TLS} {
			if echCapable, ok := cfg.(tls.ECHCapableConfig); ok {
				echCapable.SetECHConfigList(echErr.RetryConfigList)
			}
		}
		return echErr.RetryConfigList, true
	}
	// quic-go converts *tls.ECHRejectionError (which does not unwrap to AlertError)
	// into a TransportError holding the message text; force-refresh dynamic DNS ECH.
	if strings.Contains(strings.ToLower(dialErr.Error()), "server rejected ech") {
		refreshed, supported, rErr := tls.RefreshECHConfigList(dialCtx, h3TLS)
		if supported && rErr == nil && len(refreshed) > 0 && !bytes.Equal(refreshed, attempted) {
			return refreshed, true
		}
	}
	return nil, false
}

func (p *xmuxHTTPPool) dialH3Attempt(dialCtx context.Context, target M.Socksaddr, h3TLS tls.Config, stdCfg *stdtls.Config, limit mux.XmuxSessionLimit) (*xmuxHTTPConn, error) {
	if err := dialCtx.Err(); err != nil {
		return nil, err
	}
	rawConn, err := p.dialer.DialContext(dialCtx, N.NetworkUDP, target)
	if err != nil {
		return nil, err
	}
	qtls.SetDesiredBufferSizes(rawConn)

	idleTimeout := p.idleTimeout
	pingTimeout := p.pingTimeout
	if limit.KeepAlivePeriod > 0 {
		idleTimeout = limit.KeepAlivePeriod
		if pingTimeout <= 0 {
			pingTimeout = 15 * time.Second
		}
	}
	quicConfig := buildXHTTPQUICConfig(p.quicOptions, idleTimeout, pingTimeout, false, true)
	if stdCfg.VerifyConnection != nil || len(stdCfg.Certificates) > 0 || stdCfg.GetConfigForClient != nil || stdCfg.GetCertificate != nil {
		// quic-go ChromeParrot uTLS conversion rejects VerifyConnection and certificate callbacks/fields.
		quicConfig.ChromeParrot = false
	}
	quicConn, err := qtls.DialEarly(dialCtx, rawConn, quicSTDConfigAdapter{Config: h3TLS, stdCfg: stdCfg}, quicConfig)
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	quicConn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(quicConn.InitialPacketSize(), congestion_meta2.ProfileStandard))

	tr := &http3.Transport{
		DisableCompression: true,
		QUICConfig:         quicConfig,
	}
	if quicConfig.ChromeParrot {
		greaseID, greaseVal := chromeH3GreaseSetting()
		tr.EnableDatagrams = true
		tr.MaxResponseHeaderBytes = chromeH3MaxFieldSectionSize
		tr.AdditionalSettings = map[uint64]uint64{greaseID: greaseVal}
	}
	h3cc := tr.NewClientConn(quicConn)
	return &xmuxHTTPConn{
		isH3: true,
		h3Conn: &h3ClientConn{
			cc:        h3cc,
			qConn:     quicConn,
			transport: tr,
			udpConn:   rawConn,
		},
		limit: limit,
	}, nil
}

func (c *h3ClientConn) roundTrip(req *http.Request) (*http.Response, error) {
	return c.cc.RoundTrip(req)
}

func (c *h3ClientConn) isAlive() bool {
	if c == nil || c.cc == nil || c.qConn == nil {
		return false
	}
	select {
	case <-c.cc.Context().Done():
		return false
	case <-c.qConn.Context().Done():
		return false
	default:
		return true
	}
}

func (c *h3ClientConn) close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		if c.cc != nil {
			_ = c.cc.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		}
		if c.qConn != nil {
			_ = c.qConn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "")
		}
		if c.transport != nil {
			_ = c.transport.Close()
		}
		if c.udpConn != nil {
			_ = c.udpConn.Close()
		}
	})
}
