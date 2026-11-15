//go:build with_utls

package httpclient

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestHTTP2TransportSyncsUTLSFingerprint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dialer := N.SystemDialer

	for _, tc := range []struct {
		name   string
		utlsFP string
		want   string
	}{
		{name: "chrome", utlsFP: "chrome", want: "chrome"},
		{name: "firefox", utlsFP: "firefox", want: "firefox"},
		{name: "safari_16", utlsFP: "safari_16_0", want: "safari_16"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tlsCfg, err := tls.NewClientWithOptions(tls.ClientOptions{
				Context:       ctx,
				Logger:        logger.NOP(),
				ServerAddress: "example.com",
				Options: option.OutboundTLSOptions{
					Enabled: true,
					UTLS: &option.OutboundUTLSOptions{
						Enabled:     true,
						Fingerprint: tc.utlsFP,
					},
				},
			})
			require.NoError(t, err)

			tr, err := newHTTP2Transport(dialer, tlsCfg, option.HTTP2Options{})
			require.NoError(t, err)
			require.NotNil(t, tr.h2Transport.Fingerprint)
			require.Equal(t, tc.want, tr.h2Transport.Fingerprint.Name)

			cloned := CloneHTTP2Transport(tr.h2Transport)
			require.NotNil(t, cloned)
			require.NotNil(t, cloned.Fingerprint)
			require.Equal(t, tc.want, cloned.Fingerprint.Name)
			origFirst := tr.h2Transport.Fingerprint.PseudoHeaderOrder[0]
			cloned.Fingerprint.PseudoHeaderOrder[0] = ":other"
			require.Equal(t, origFirst, tr.h2Transport.Fingerprint.PseudoHeaderOrder[0])

			fbTr, err := newHTTP2FallbackTransport(dialer, tlsCfg, option.HTTP2Options{})
			require.NoError(t, err)
			require.NotNil(t, fbTr.h2Transport.Fingerprint)
			require.Equal(t, tc.want, fbTr.h2Transport.Fingerprint.Name)
		})
	}

	stdCfg, err := tls.NewClientWithOptions(tls.ClientOptions{
		Context:       ctx,
		Logger:        logger.NOP(),
		ServerAddress: "example.com",
		Options:       option.OutboundTLSOptions{Enabled: true},
	})
	require.NoError(t, err)
	stdTr, err := newHTTP2Transport(dialer, stdCfg, option.HTTP2Options{})
	require.NoError(t, err)
	require.Nil(t, stdTr.h2Transport.Fingerprint)
	require.Nil(t, CloneHTTP2Transport(nil))
}
