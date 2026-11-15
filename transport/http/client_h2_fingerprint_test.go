//go:build with_utls

package http

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func generateTestCertPEM(t *testing.T, dnsName string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{dnsName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}

func TestHTTPProxyClientSyncsUTLSAndHTTP2WireFingerprint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	certPEM, keyPEM := generateTestCertPEM(t, "proxy.example")
	cert, err := stdtls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)

	stdClient, err := NewClientWithTLS(
		ctx,
		logger.NOP(),
		N.SystemDialer,
		option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		option.OutboundTLSOptions{
			Enabled:     true,
			ServerName:  "proxy.example",
			Certificate: []string{certPEM},
		},
		ClientOptions{Version: 2},
	)
	require.NoError(t, err)
	require.Nil(t, stdClient.http2Transport.Fingerprint)
	_ = stdClient.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	type wireResult struct {
		settings []http2.Setting
		connWU   uint32
		pseudo   []string
		err      error
	}
	ch := make(chan wireResult, 1)

	go func() {
		raw, err := ln.Accept()
		if err != nil {
			ch <- wireResult{err: err}
			return
		}
		tlsConn := stdtls.Server(raw, &stdtls.Config{
			Certificates: []stdtls.Certificate{cert},
			NextProtos:   []string{"h2"},
		})
		defer tlsConn.Close()
		if err := tlsConn.Handshake(); err != nil {
			ch <- wireResult{err: err}
			return
		}

		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(tlsConn, preface); err != nil {
			ch <- wireResult{err: err}
			return
		}
		fr := http2.NewFramer(tlsConn, tlsConn)
		fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
		if err := fr.WriteSettings(); err != nil {
			ch <- wireResult{err: err}
			return
		}

		var res wireResult
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				res.err = err
				ch <- res
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					_ = f.ForeachSetting(func(s http2.Setting) error {
						res.settings = append(res.settings, s)
						return nil
					})
					_ = fr.WriteSettingsAck()
				}
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 {
					res.connWU = f.Increment
				}
			case *http2.MetaHeadersFrame:
				for _, hf := range f.Fields {
					if hf.IsPseudo() {
						res.pseudo = append(res.pseudo, hf.Name)
					}
				}
				var buf bytes.Buffer
				enc := hpack.NewEncoder(&buf)
				_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				_ = fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      f.StreamID,
					BlockFragment: buf.Bytes(),
					EndStream:     false,
					EndHeaders:    true,
				})
				ch <- res
				return
			}
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	ffClient, err := NewClientWithTLS(
		ctx,
		logger.NOP(),
		N.SystemDialer,
		option.ServerOptions{Server: tcpAddr.IP.String(), ServerPort: uint16(tcpAddr.Port)},
		option.OutboundTLSOptions{
			Enabled:     true,
			ServerName:  "proxy.example",
			Certificate: []string{certPEM},
			UTLS: &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: "firefox",
			},
		},
		ClientOptions{Version: 2},
	)
	require.NoError(t, err)
	defer ffClient.Close()
	require.NotNil(t, ffClient.http2Transport.Fingerprint)
	require.Equal(t, "firefox", ffClient.http2Transport.Fingerprint.Name)

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tunnelConn, err := ffClient.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
	require.NoError(t, err)
	defer tunnelConn.Close()

	got := <-ch
	require.NoError(t, got.err)
	require.Equal(t, uint32(12517377), got.connWU)
	require.Equal(t, []string{":method", ":authority"}, got.pseudo)
	wantSettings := tls.HTTP2Fingerprint(func() tls.Config {
		cfg, _ := tls.NewClient(ctx, logger.NOP(), "proxy.example", option.OutboundTLSOptions{
			Enabled: true,
			UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "firefox"},
		})
		return cfg
	}()).Settings
	require.True(t, slices.Equal(wantSettings, got.settings), "settings mismatch: got %+v want %+v", got.settings, wantSettings)
}
