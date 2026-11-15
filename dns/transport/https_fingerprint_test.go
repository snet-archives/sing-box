//go:build with_utls

package transport

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestHTTPSTransportSyncsUTLSAndResetPreservesFingerprint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	u, err := url.Parse("https://dns.example/dns-query")
	require.NoError(t, err)
	addr := M.ParseSocksaddr("dns.example:443")

	tlsCfg, err := tls.NewClientWithOptions(tls.ClientOptions{
		Context:       ctx,
		Logger:        logger.NOP(),
		ServerAddress: "dns.example",
		Options: option.OutboundTLSOptions{
			Enabled: true,
			UTLS: &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: "firefox",
			},
		},
	})
	require.NoError(t, err)

	tr := NewHTTPSRaw(
		dns.NewTransportAdapter("https", "test-doh", nil),
		logger.NOP(),
		N.SystemDialer,
		u,
		http.Header{},
		addr,
		tlsCfg,
	)
	require.NotNil(t, tr.h2Fingerprint)
	require.Equal(t, "firefox", tr.h2Fingerprint.Name)
	require.NotNil(t, tr.transport.http2Transport.Fingerprint)
	require.Equal(t, "firefox", tr.transport.http2Transport.Fingerprint.Name)

	tr.Reset()
	require.NotNil(t, tr.transport.http2Transport.Fingerprint)
	require.Equal(t, "firefox", tr.transport.http2Transport.Fingerprint.Name)
}
