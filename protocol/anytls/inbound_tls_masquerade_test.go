//go:build with_utls

package anytls

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	sTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestAnyTLSMasqueradeHTTP1AndH2AndStrictSNI(t *testing.T) {
	const testServer = "anytls.example.com"
	priv, pub, err := sTLS.GenerateCertificate(nil, nil, time.Now, testServer, time.Now().Add(time.Hour))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := adapter.NewScope(ctx, logger.NOP())
	defer scope.Close()

	inbound, err := NewInbound(ctx, nil, logger.NOP(), "anytls-in", option.AnyTLSInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: 0,
		},
		Users: []option.AnyTLSUser{{
			Name:     "u1",
			Password: "secret-password",
		}},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:     true,
				ServerName:  testServer,
				StrictSNI:   true,
				ALPN:        []string{"h2", "http/1.1"},
				Certificate: []string{string(pub)},
				Key:         []string{string(priv)},
			},
		},
		Masquerade: &option.Hysteria2Masquerade{
			Type: "string",
			StringOptions: option.Hysteria2MasqueradeString{
				StatusCode: 200,
				Headers: badoption.HTTPHeader{
					"Content-Type": {"text/plain; charset=utf-8"},
				},
				Content: "anytls-masquerade-ok",
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, inbound.Start(adapter.StartStateStart, scope))

	addr := inbound.(*Inbound).listener.TCPListener().Addr().String()

	// 1. HTTPS HTTP/1.1 request with matching SNI receives masquerade 200 OK.
	h1Client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&tls.Dialer{Config: &tls.Config{
					ServerName:         testServer,
					InsecureSkipVerify: true,
					NextProtos:         []string{"http/1.1"},
				}}).DialContext(ctx, network, addr)
			},
		},
	}
	defer h1Client.CloseIdleConnections()
	resp1, err := h1Client.Get("https://" + testServer + "/")
	require.NoError(t, err)
	body1, err := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	require.NoError(t, err)
	require.Equal(t, 200, resp1.StatusCode)
	require.Equal(t, "HTTP/1.1", resp1.Proto)
	require.Equal(t, "anytls-masquerade-ok", string(body1))

	// 2. HTTPS HTTP/2 request with matching SNI negotiates ALPN h2 and receives masquerade 200 OK.
	h2Client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&tls.Dialer{Config: &tls.Config{
					ServerName:         testServer,
					InsecureSkipVerify: true,
					NextProtos:         []string{"h2", "http/1.1"},
				}}).DialContext(ctx, network, addr)
			},
		},
	}
	defer h2Client.CloseIdleConnections()
	resp2, err := h2Client.Get("https://" + testServer + "/")
	require.NoError(t, err)
	body2, err := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	require.NoError(t, err)
	require.Equal(t, 200, resp2.StatusCode)
	require.Equal(t, "HTTP/2.0", resp2.Proto)
	require.Equal(t, "anytls-masquerade-ok", string(body2))

	// 3. Wrong SNI rejected by strict_sni.
	_, err = tls.Dial("tcp", addr, &tls.Config{
		ServerName:         "invalid.example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	require.Error(t, err)
}
