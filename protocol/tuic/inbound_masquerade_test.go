//go:build with_quic && with_utls

package tuic

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestTUICHTTP3MasqueradeAndStrictSNI(t *testing.T) {
	const testUUID = "11111111-2222-3333-4444-555555555555"
	const testPassword = "tuic-masquerade-password"
	const testServer = "dd.example.com"
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
		AuthTimeout:       badoption.Duration(2 * time.Second),
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:     true,
				ServerName:  testServer,
				StrictSNI:   true,
				ALPN:        []string{"h3"},
				Certificate: []string{certPEM},
				Key:         []string{keyPEM},
			},
		},
		Masquerade: &option.Hysteria2Masquerade{
			Type: "string",
			StringOptions: option.Hysteria2MasqueradeString{
				StatusCode: 200,
				Headers: badoption.HTTPHeader{
					"Content-Type": {"text/plain; charset=utf-8"},
				},
				Content: "hello from masquerade",
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, inbound.Start(adapter.StartStateStart, scope))

	port := uint16(inbound.(*Inbound).listener.UDPConn().LocalAddr().(*net.UDPAddr).Port)

	// 1. Real HTTP/3 request with valid SNI gets masquerade response without TUIC version/auth errors.
	h3TrValid := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         testServer,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, qCfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", port), tlsCfg, qCfg)
		},
	}
	defer h3TrValid.Close()
	h3Client := &http.Client{Transport: h3TrValid, Timeout: 3 * time.Second}
	resp, err := h3Client.Get(fmt.Sprintf("https://%s:%d/", testServer, port))
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	require.Equal(t, "hello from masquerade", string(body))

	// 2. HTTP/3 probe with mismatched SNI must fail TLS handshake via strict_sni.
	h3TrWrong := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         "wrong.example.com",
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
	}
	defer h3TrWrong.Close()
	wrongClient := &http.Client{Transport: h3TrWrong, Timeout: 2 * time.Second}
	_, wrongErr := wrongClient.Get(fmt.Sprintf("https://127.0.0.1:%d/", port))
	require.Error(t, wrongErr)

	// 3. Genuine TUIC v5 client still authenticates and relays traffic on the same listener.
	out, err := NewOutbound(ctx, nil, logger.NOP(), "tuic-out", option.TUICOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: port,
		},
		UUID:              testUUID,
		Password:          testPassword,
		CongestionControl: "bbr",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: testServer,
				Insecure:   true,
				ALPN:       []string{"h3"},
			},
		},
	})
	require.NoError(t, err)
	c, err := out.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr("example.com:80"))
	require.NoError(t, err)
	defer c.Close()

	msg := []byte("tuic-with-masquerade-works")
	_, err = c.Write(msg)
	require.NoError(t, err)
	got := make([]byte, len(msg))
	_, err = io.ReadFull(c, got)
	require.NoError(t, err)
	require.Equal(t, msg, got)
}
