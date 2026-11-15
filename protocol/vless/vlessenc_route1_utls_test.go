//go:build with_utls

package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	stdtls "crypto/tls"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/vlessenc"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestVLESSRoute1RealityWithVLESSEnc(t *testing.T) {
	t.Parallel()
	targetPort, _ := startLocalTLSTarget(t, "edge.example.com")
	uid, kp := mustVLESSKeypairAndUUID(t)
	decOpts, encOpts := makeVLESSEncConfigs(kp, vlessenc.XorRandom, "", "")

	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	privB64 := base64.RawURLEncoding.EncodeToString(xPriv.Bytes())
	pubB64 := base64.RawURLEncoding.EncodeToString(xPriv.PublicKey().Bytes())
	const shortID = "0123456789abcdef"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := adapter.NewScope(ctx, logger.NOP())
	defer scope.Close()

	in, err := NewInbound(ctx, vlessEncEchoRouter{}, logger.NOP(), "vless-reality-in", option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: 0,
		},
		Users:      []option.VLESSUser{{UUID: uid}},
		Decryption: decOpts,
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:    true,
				ServerName: "edge.example.com",
				Reality: &option.InboundRealityOptions{
					Enabled: true,
					Handshake: option.InboundRealityHandshakeOptions{
						ServerOptions: option.ServerOptions{
							Server:     "127.0.0.1",
							ServerPort: targetPort,
						},
					},
					ShortID:    badoption.Listable[string]{shortID},
					PrivateKey: privB64,
				},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, in.Start(adapter.StartStateStart, scope))

	inAddr := in.(*Inbound).listener.TCPListener().Addr().String()
	tapPort, getFlights := startTCPWireTap(t, inAddr)

	out, err := NewOutbound(ctx, nil, logger.NOP(), "vless-reality-out", option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: tapPort,
		},
		UUID:       uid,
		Encryption: encOpts,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "edge.example.com",
				Reality: &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: pubB64,
					ShortID:   shortID,
				},
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: "chrome",
				},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, out.(*Outbound).Start(adapter.StartStateInitialize, scope))

	// 1. Both 1-RTT & 0-RTT vlessenc succeed cleanly inside Reality + uTLS without flow.
	assertVLESSOutboundEcho(t, out, []byte("reality-vlessenc-1rtt"), []byte("reality-vlessenc-0rtt"))

	flights := getFlights()
	require.Len(t, flights, 2)
	for _, f := range flights {
		require.Greater(t, len(f), 5)
		require.Equal(t, []byte{0x16, 0x03, 0x01}, f[:3])
	}

	// 2. Active probe without valid Reality auth gets transparently relayed to the target site's TLS cert.
	rawProbe, err := net.DialTimeout("tcp", inAddr, 5*time.Second)
	require.NoError(t, err)
	defer rawProbe.Close()
	tlsProbe := stdtls.Client(rawProbe, &stdtls.Config{
		ServerName:         "edge.example.com",
		InsecureSkipVerify: true,
		MinVersion:         stdtls.VersionTLS13,
	})
	require.NoError(t, tlsProbe.Handshake())
	state := tlsProbe.ConnectionState()
	require.NotEmpty(t, state.PeerCertificates)
	require.Contains(t, state.PeerCertificates[0].DNSNames, "edge.example.com")
	_ = tlsProbe.Close()
}

func TestVLESSRoute1ShadowTLSv3UTLSWithVLESSEnc(t *testing.T) {
	t.Parallel()
	runShadowTLSv3VLESSEncTest(t, true)
}
