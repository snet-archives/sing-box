//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mRand "math/rand"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/browserhdr"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/debug"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	aTLS "github.com/sagernet/sing/common/tls"

	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

var _ ConfigCompat = (*RealityClientConfig)(nil)

var oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}

type RealityClientConfig struct {
	ctx                   context.Context
	uClient               *UTLSClientConfig
	publicKey             []byte
	shortID               [8]byte
	mldsa65Verify         []byte
	disableX25519MLKEM768 bool
}

func NewRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions) (Config, error) {
	return newRealityClient(ctx, logger, serverAddress, options, false)
}

func newRealityClient(ctx context.Context, logger logger.ContextLogger, serverAddress string, options option.OutboundTLSOptions, allowEmptyServerName bool) (Config, error) {
	if options.Reality == nil || !options.Reality.Enabled {
		return nil, E.New("reality options required")
	}
	if options.UTLS == nil || !options.UTLS.Enabled {
		return nil, E.New("uTLS is required by reality client")
	}
	if options.Spoof != "" || options.SpoofMethod != "" {
		return nil, E.New("spoof is unsupported in reality")
	}

	uClient, err := newUTLSClient(ctx, logger, serverAddress, options, allowEmptyServerName)
	if err != nil {
		return nil, err
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(options.Reality.PublicKey)
	if err != nil {
		return nil, E.Cause(err, "decode public_key")
	}
	if len(publicKey) != 32 {
		return nil, E.New("invalid public_key")
	}
	var shortID [8]byte
	decodedLen, err := hex.Decode(shortID[:], []byte(options.Reality.ShortID))
	if err != nil {
		return nil, E.Cause(err, "decode short_id")
	}
	if decodedLen > 8 {
		return nil, E.New("invalid short_id")
	}
	var mldsa65Verify []byte
	if options.Reality.MLDSA65Verify != "" {
		mldsa65Verify, err = base64.RawURLEncoding.DecodeString(options.Reality.MLDSA65Verify)
		if err != nil {
			return nil, E.Cause(err, "decode mldsa65_verify")
		}
		if len(mldsa65Verify) != mldsa65.PublicKeySize {
			return nil, E.New("invalid mldsa65_verify")
		}
		var pk mldsa65.PublicKey
		if err = pk.UnmarshalBinary(mldsa65Verify); err != nil {
			return nil, E.Cause(err, "parse mldsa65_verify")
		}
	}

	var config Config = &RealityClientConfig{
		ctx:                   ctx,
		uClient:               uClient.(*UTLSClientConfig),
		publicKey:             publicKey,
		shortID:               shortID,
		mldsa65Verify:         mldsa65Verify,
		disableX25519MLKEM768: options.Reality.DisableX25519MLKEM768,
	}
	if options.KernelRx || options.KernelTx {
		if !C.IsLinux {
			return nil, E.New("kTLS is only supported on Linux")
		}
		config = &KTLSClientConfig{
			Config:   config,
			logger:   logger,
			kernelTx: options.KernelTx,
			kernelRx: options.KernelRx,
		}
	}
	return config, nil
}

func (e *RealityClientConfig) ServerName() string {
	return e.uClient.ServerName()
}

func (e *RealityClientConfig) SetServerName(serverName string) {
	e.uClient.SetServerName(serverName)
}

func (e *RealityClientConfig) NextProtos() []string {
	return e.uClient.NextProtos()
}

func (e *RealityClientConfig) SetNextProtos(nextProto []string) {
	e.uClient.SetNextProtos(nextProto)
}

func (e *RealityClientConfig) HandshakeTimeout() time.Duration {
	return e.uClient.HandshakeTimeout()
}

func (e *RealityClientConfig) SetHandshakeTimeout(timeout time.Duration) {
	e.uClient.SetHandshakeTimeout(timeout)
}

func (e *RealityClientConfig) STDConfig() (*STDConfig, error) {
	return nil, E.New("unsupported usage for reality")
}

func (e *RealityClientConfig) SupportsQUIC() bool {
	return false
}

func (e *RealityClientConfig) Client(conn net.Conn) (Conn, error) {
	return ClientHandshake(context.Background(), conn, e)
}

func (e *RealityClientConfig) ClientHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	serverName := e.uClient.ServerName()
	verifier := &realityVerifier{
		serverName:    serverName,
		mldsa65Verify: e.mldsa65Verify,
	}
	e.uClient.access.RLock()
	uConfig := e.uClient.config.Clone()
	uClientID := e.uClient.id
	e.uClient.access.RUnlock()
	uConfig.InsecureSkipVerify = true
	uConfig.SessionTicketsDisabled = true
	uConfig.VerifyPeerCertificate = verifier.VerifyPeerCertificate
	conn, err := e.uClient.wrapConn(ctx, conn)
	if err != nil {
		return nil, err
	}
	uConn := utls.UClient(conn, uConfig, uClientID)
	verifier.UConn = uConn

	err = uConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}
	needRebuild := false
	if e.disableX25519MLKEM768 {
		for _, extension := range uConn.Extensions {
			if ce, ok := extension.(*utls.SupportedCurvesExtension); ok {
				filtered := common.Filter(ce.Curves, func(curveID utls.CurveID) bool {
					return curveID != utls.X25519MLKEM768
				})
				if len(filtered) != len(ce.Curves) {
					ce.Curves = filtered
					needRebuild = true
				}
			}
			if ks, ok := extension.(*utls.KeyShareExtension); ok {
				filtered := common.Filter(ks.KeyShares, func(share utls.KeyShare) bool {
					return share.Group != utls.X25519MLKEM768
				})
				if len(filtered) != len(ks.KeyShares) {
					ks.KeyShares = filtered
					needRebuild = true
				}
			}
		}
	}
	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				needRebuild = true
				break
			}
		}
	}
	if needRebuild {
		err = uConn.BuildHandshakeState()
		if err != nil {
			return nil, err
		}
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)

	var nowTime time.Time
	if uConfig.Time != nil {
		nowTime = uConfig.Time()
	} else {
		nowTime = time.Now()
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(nowTime.Unix()))

	hello.SessionId[0] = 1
	hello.SessionId[1] = 8
	hello.SessionId[2] = 1
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(nowTime.Unix()))
	copy(hello.SessionId[8:], e.shortID[:])
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId[:16]: %v\n", hello.SessionId[:16])
	}
	publicKey, err := ecdh.X25519().NewPublicKey(e.publicKey)
	if err != nil {
		return nil, err
	}
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil {
		return nil, E.New("nil KeyShareKeys")
	}
	ecdheKey := keyShareKeys.Ecdhe
	if ecdheKey == nil {
		ecdheKey = keyShareKeys.MlkemEcdhe
	}
	if ecdheKey == nil {
		return nil, E.New("nil ecdheKey")
	}
	authKey, err := ecdheKey.ECDH(publicKey)
	if err != nil {
		return nil, err
	}
	if authKey == nil {
		return nil, E.New("nil auth_key")
	}
	verifier.authKey = authKey
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	if err != nil {
		return nil, err
	}
	aesBlock, _ := aes.NewCipher(authKey)
	aesGcmCipher, _ := cipher.NewGCM(aesBlock)
	aesGcmCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	if debug.Enabled {
		fmt.Printf("REALITY hello.sessionId: %v\n", hello.SessionId)
		fmt.Printf("REALITY uConn.AuthKey: %v\n", authKey)
	}

	err = uConn.HandshakeContext(ctx)
	if err != nil {
		return nil, err
	}

	if debug.Enabled {
		fmt.Printf("REALITY Conn.Verified: %v\n", verifier.verified)
	}

	if !verifier.verified {
		go realityClientFallback(e.ctx, uConn, serverName, uClientID)
		return nil, E.New("reality verification failed")
	}

	return &realityClientConnWrapper{UConn: uConn}, nil
}

func realityClientFallback(ctx context.Context, uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	client := &http.Client{
		Timeout: C.TCPTimeout,
		Transport: &http2.Transport{
			Fingerprint: browserhdr.HTTP2Fingerprint(nil, fingerprint.Client, fingerprint.Version, "document"),
			DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
			},
		},
	}
	serverAddress := M.ParseSocksaddrHostPort(serverName, 0)
	host := serverAddress.AddrString()
	if serverAddress.IsIPv6() {
		host = "[" + host + "]"
	}
	request, err := http.NewRequest("GET", "https://"+host, nil)
	if err != nil {
		return
	}
	browserhdr.ApplyForUTLS(request.Header, fingerprint.Client, fingerprint.Version, "nav")
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", mRand.Intn(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

func (e *RealityClientConfig) Clone() Config {
	return &RealityClientConfig{
		ctx:                   e.ctx,
		uClient:               e.uClient.Clone().(*UTLSClientConfig),
		publicKey:             bytes.Clone(e.publicKey),
		shortID:               e.shortID,
		mldsa65Verify:         bytes.Clone(e.mldsa65Verify),
		disableX25519MLKEM768: e.disableX25519MLKEM768,
	}
}

type realityVerifier struct {
	*utls.UConn
	serverName    string
	authKey       []byte
	mldsa65Verify []byte
	verified      bool
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeFor[utls.Conn]().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Add(unsafe.Pointer(c.Conn), p.Offset))
	if len(certs) == 0 {
		return E.New("empty peer certificates")
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			if len(c.mldsa65Verify) > 0 {
				var mldsaSig []byte
				for _, ext := range certs[0].Extensions {
					if ext.Id.Equal(oidMLDSA65) {
						mldsaSig = ext.Value
						break
					}
				}
				if len(mldsaSig) > 0 && c.HandshakeState.Hello != nil && c.HandshakeState.ServerHello != nil {
					h.Write(c.HandshakeState.Hello.Raw)
					h.Write(c.HandshakeState.ServerHello.Raw)
					var pk mldsa65.PublicKey
					if err := pk.UnmarshalBinary(c.mldsa65Verify); err == nil && mldsa65.Verify(&pk, h.Sum(nil), nil, mldsaSig) {
						c.verified = true
						return nil
					}
				}
			} else {
				c.verified = true
				return nil
			}
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

type realityClientConnWrapper struct {
	*utls.UConn
	closeNotifySuppressor
}

func (c *realityClientConnWrapper) Close() error {
	return c.closeConn(c.UConn, c.UConn.NetConn())
}

func (c *realityClientConnWrapper) ConnectionState() tls.ConnectionState {
	state := c.Conn.ConnectionState()
	//nolint:staticcheck
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func (c *realityClientConnWrapper) Upstream() any {
	return c.UConn
}

// Due to low implementation quality, the reality server intercepted half close and caused memory leaks.
// We fixed it by calling Close() directly.
func (c *realityClientConnWrapper) CloseWrite() error {
	if c.suppressed.Load() {
		return N.CloseWrite(c.UConn.NetConn())
	}
	return c.Close()
}

func (c *realityClientConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *realityClientConnWrapper) WriterReplaceable() bool {
	return false
}

func (c *RealityClientConfig) UTLSFingerprint() (string, string, bool) {
	if c.uClient == nil {
		return "", "", false
	}
	return c.uClient.UTLSFingerprint()
}
