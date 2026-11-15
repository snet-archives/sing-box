//go:build with_utls

package v2raygrpclite

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

func TestV2RayGRPCLiteSyncsUTLSAndPreservesGRPC(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	certPEM, keyPEM := generateTestCertPEM(t, "grpc.example")
	cert, err := stdtls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	require.NoError(t, err)

	serverAddr := M.ParseSocksaddrHostPort("127.0.0.1", 443)

	// Nil TLS leaves vanilla Go transport fingerprint unset.
	plainClient := NewClient(ctx, N.SystemDialer, serverAddr, option.V2RayGRPCOptions{ServiceName: "GunService"}, nil).(*Client)
	require.Nil(t, plainClient.transport.Fingerprint)
	_ = plainClient.Close()

	// Standard TLS without uTLS leaves HTTP/2 fingerprint unset.
	stdTLS, err := tls.NewClient(ctx, logger.NOP(), serverAddr.AddrString(), option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "grpc.example",
		Certificate: []string{certPEM},
	})
	require.NoError(t, err)
	stdClient := NewClient(ctx, N.SystemDialer, serverAddr, option.V2RayGRPCOptions{ServiceName: "GunService"}, stdTLS).(*Client)
	require.Nil(t, stdClient.transport.Fingerprint)
	_ = stdClient.Close()

	// uTLS Firefox synchronizes H2 wire fingerprint while preserving gRPC headers.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	type wireResult struct {
		settings []http2.Setting
		connWU   uint32
		pseudo   []string
		headers  map[string]string
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
		res.headers = make(map[string]string)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				ch <- wireResult{err: err}
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					_ = f.ForeachSetting(func(s http2.Setting) error {
						res.settings = append(res.settings, s)
						return nil
					})
					if err := fr.WriteSettingsAck(); err != nil {
						ch <- wireResult{err: err}
						return
					}
				}
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 {
					res.connWU = f.Increment
				}
			case *http2.MetaHeadersFrame:
				for _, hf := range f.Fields {
					if hf.IsPseudo() {
						res.pseudo = append(res.pseudo, hf.Name)
					} else {
						res.headers[hf.Name] = hf.Value
					}
				}
				var hdrBuf bytes.Buffer
				enc := hpack.NewEncoder(&hdrBuf)
				_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				_ = fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      f.StreamID,
					BlockFragment: hdrBuf.Bytes(),
					EndStream:     true,
					EndHeaders:    true,
				})
				ch <- res
				return
			}
		}
	}()

	listenAddr := M.SocksaddrFromNet(ln.Addr())
	utlsCfg, err := tls.NewClient(ctx, logger.NOP(), listenAddr.AddrString(), option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "grpc.example",
		Certificate: []string{certPEM},
		UTLS: &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "firefox",
		},
	})
	require.NoError(t, err)

	client := NewClient(ctx, N.SystemDialer, listenAddr, option.V2RayGRPCOptions{ServiceName: "GunService"}, utlsCfg).(*Client)
	defer client.Close()
	require.NotNil(t, client.transport.Fingerprint)

	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()

	// Trigger early header flush by sending initial payload bytes or reading status.
	_, _ = conn.Write([]byte("ping"))

	res := <-ch
	require.NoError(t, res.err)

	want := http2.FingerprintFirefox()
	require.True(t, slices.Equal(res.settings, want.Settings), "settings=%v want=%v", res.settings, want.Settings)
	require.Equal(t, want.ConnectionFlow, res.connWU)
	require.Equal(t, want.PseudoHeaderOrder, res.pseudo)
	require.Equal(t, "application/grpc", res.headers["content-type"])
	require.Equal(t, "trailers", res.headers["te"])
	require.Equal(t, "grpc-go/1.48.0", res.headers["user-agent"])
}
