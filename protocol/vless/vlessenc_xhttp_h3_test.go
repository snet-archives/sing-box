//go:build with_quic

package vless

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/vlessenc"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func reserveLocalDualPort(t *testing.T) uint16 {
	t.Helper()
	for i := 0; i < 16; i++ {
		tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		port := tcpLn.Addr().(*net.TCPAddr).Port
		udpPC, udpErr := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		_ = tcpLn.Close()
		if udpErr == nil {
			_ = udpPC.Close()
			return uint16(port)
		}
	}
	t.Fatal("failed to reserve matching local TCP+UDP port")
	return 0
}

func TestVLESSXHTTPHTTP3AndResiliencyE2E(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		alpn []string
		mode string
	}{
		{name: "pure_h3_stream_one", alpn: []string{"h3"}, mode: "stream-one"},
		{name: "pure_h3_stream_up", alpn: []string{"h3"}, mode: "stream-up"},
		{name: "pure_h3_packet_up", alpn: []string{"h3"}, mode: "packet-up"},
		{name: "h3_h2_packet_up", alpn: []string{"h3", "h2"}, mode: "packet-up"},
		{name: "h3_h2_stream_up", alpn: []string{"h3", "h2"}, mode: "stream-up"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			uid, kp := mustVLESSKeypairAndUUID(t)
			decOpts, encOpts := makeVLESSEncConfigs(kp, vlessenc.XorRandom, "", "")
			certPEM, keyPEM, pin := certPEMPairFromStrings(t)
			port := reserveLocalDualPort(t)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			scope := adapter.NewScope(ctx, logger.NOP())
			defer scope.Close()

			xhttpOpts := option.V2RayXHTTPOptions{
				Path:                 "/xhttp-h3",
				Mode:                 tc.mode,
				ScMaxEachPostBytes:   option.XmuxRange{From: 2048, To: 2048},
				ScMaxConcurrentPosts: option.XmuxRange{From: 4, To: 4},
				ScDownlinkServerSecs: option.XmuxRange{From: 1, To: 1},
				QUIC: &option.QUICOptions{
					HTTP2Options: option.HTTP2Options{
						MaxConcurrentStreams: 32,
					},
				},
			}

			in, err := NewInbound(ctx, vlessEncEchoRouter{}, logger.NOP(), "vless-xhttp-h3-in", option.VLESSInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
					ListenPort: port,
				},
				Users:      []option.VLESSUser{{UUID: uid}},
				Decryption: decOpts,
				InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
					TLS: &option.InboundTLSOptions{
						Enabled:     true,
						ServerName:  "localhost",
						ALPN:        tc.alpn,
						Certificate: badoption.Listable[string]{certPEM},
						Key:         badoption.Listable[string]{keyPEM},
					},
				},
				Transport: &option.V2RayTransportOptions{
					Type:         C.V2RayTransportTypeXHTTP,
					XHTTPOptions: xhttpOpts,
				},
			})
			require.NoError(t, err)
			require.NoError(t, in.Start(adapter.StartStateStart, scope))

			out, err := NewOutbound(ctx, nil, logger.NOP(), "vless-xhttp-h3-out", option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: port,
				},
				UUID:       uid,
				Encryption: encOpts,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: &option.OutboundTLSOptions{
						Enabled:                    true,
						ServerName:                 "localhost",
						ALPN:                       tc.alpn,
						CertificatePublicKeySHA256: [][]byte{pin},
					},
				},
				Transport: &option.V2RayTransportOptions{
					Type:         C.V2RayTransportTypeXHTTP,
					XHTTPOptions: xhttpOpts,
				},
			})
			require.NoError(t, err)
			require.NoError(t, out.(*Outbound).Start(adapter.StartStateInitialize, scope))

			large := bytes.Repeat([]byte("VLESS_XHTTP_H3_E2E_"), 900) // ~17 KB
			assertVLESSOutboundEcho(t, out, []byte("xhttp-h3-1rtt"), []byte("xhttp-h3-0rtt"), large)
		})
	}
}
