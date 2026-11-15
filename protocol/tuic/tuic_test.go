//go:build with_quic && with_utls

package tuic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type tuicEchoRouter struct {
	adapter.Router
}

func (tuicEchoRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
		if onClose != nil {
			onClose(nil)
		}
	}()
}

func generateSelfSignedPEMPair(t *testing.T, dnsName string) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certBytes), string(keyBytes)
}

func TestTUICChromeParrotAndUTLSHandshake(t *testing.T) {
	const testUUID = "11111111-2222-3333-4444-555555555555"
	const testPassword = "tuic-chrome-parrot-test"
	const testServer = "cdn.example.com"
	certPEM, keyPEM := generateSelfSignedPEMPair(t, testServer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := adapter.NewScope(ctx, logger.NOP())
	defer scope.Close()

	inbound, err := NewInbound(ctx, tuicEchoRouter{}, logger.NOP(), "tuic-in", option.TUICInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: 0,
		},
		Users: []option.TUICUser{{
			Name:     "test",
			UUID:     testUUID,
			Password: testPassword,
		}},
		CongestionControl: "bbr",
		ZeroRTTHandshake:  true,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:     true,
				ALPN:        []string{"h3"},
				Certificate: []string{certPEM},
				Key:         []string{keyPEM},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, inbound.Start(adapter.StartStateStart, scope))

	port := uint16(inbound.(*Inbound).listener.UDPConn().LocalAddr().(*net.UDPAddr).Port)

	for _, tc := range []struct {
		name                string
		disableChromeParrot bool
		utls                *option.OutboundUTLSOptions
	}{
		{name: "DefaultChromeParrot", disableChromeParrot: false, utls: nil},
		{name: "ExplicitUTLSChrome", disableChromeParrot: false, utls: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"}},
		{name: "DisabledChromeParrotFallback", disableChromeParrot: true, utls: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := NewOutbound(ctx, nil, logger.NOP(), "tuic-out", option.TUICOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: port,
				},
				UUID:              testUUID,
				Password:          testPassword,
				CongestionControl: "bbr",
				ZeroRTTHandshake:  true,
				QUICOptions: option.QUICOptions{
					DisableChromeParrot: tc.disableChromeParrot,
				},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: &option.OutboundTLSOptions{
						Enabled:    true,
						ServerName: testServer,
						Insecure:   true,
						ALPN:       []string{"h3"},
						UTLS:       tc.utls,
					},
				},
			})
			require.NoError(t, err)

			c, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
			require.NoError(t, err)
			defer c.Close()

			msg := []byte("tuic-chrome-parrot-ekm-echo-ok")
			_, err = c.Write(msg)
			require.NoError(t, err)
			got := make([]byte, len(msg))
			_, err = io.ReadFull(c, got)
			require.NoError(t, err)
			require.Equal(t, msg, got)
		})
	}
}
