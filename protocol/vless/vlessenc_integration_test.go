package vless

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/vlessenc"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type vlessEncEchoRouter struct {
	adapter.Router
	replySuffix []byte
}

func (r vlessEncEchoRouter) RouteConnection(context.Context, net.Conn, adapter.InboundContext) error {
	return nil
}

func (r vlessEncEchoRouter) RoutePacketConnection(context.Context, N.PacketConn, adapter.InboundContext) error {
	return nil
}

func (r vlessEncEchoRouter) RouteConnectionEx(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	go func() {
		defer func() {
			_ = conn.Close()
			if onClose != nil {
				onClose(nil)
			}
		}()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				_, wErr := conn.Write(append(append([]byte(nil), buf[:n]...), r.replySuffix...))
				if wErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
}

func (vlessEncEchoRouter) RoutePacketConnectionEx(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

type wireRecorderConn struct {
	net.Conn
	mu   *sync.Mutex
	wire *bytes.Buffer
}

func (c *wireRecorderConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		_, _ = c.wire.Write(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *wireRecorderConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	_, _ = c.wire.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func TestVLESSHybridEncryptionValidationRejectsFlow(t *testing.T) {
	t.Parallel()

	kp, err := vlessenc.GenerateKeyPair()
	require.NoError(t, err)
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()

	_, err = NewInbound(ctx, vlessEncEchoRouter{}, logger, "in-bad", option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: 443},
		Users: []option.VLESSUser{
			{Name: "u1", UUID: "a8098c1a-f86e-11da-bd1a-00112444be1e", Flow: "xtls-rprx-vision"},
		},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{Enabled: true},
		},
		Decryption: &option.VLESSDecryptionOptions{
			Enabled:      true,
			PrivateKey:   kp.PrivateKey,
			MLKEM768Seed: kp.MLKEM768Seed,
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "flow is incompatible with vless decryption")

	_, err = NewOutbound(ctx, nil, logger, "out-bad", option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		UUID:          "a8098c1a-f86e-11da-bd1a-00112444be1e",
		Flow:          "xtls-rprx-vision",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{Enabled: true, ServerName: "example.com"},
		},
		Encryption: &option.VLESSEncryptionOptions{
			Enabled:          true,
			PublicKey:        kp.PublicKey,
			MLKEM768EncapKey: kp.MLKEM768EncapKey,
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "flow is incompatible with vless encryption")
}

func TestVLESSEndToEndHybridEncryptionAnd0RTTWithoutTLS(t *testing.T) {
	t.Parallel()

	kp, err := vlessenc.GenerateKeyPair()
	require.NoError(t, err)

	const testUUID = "a8098c1a-f86e-11da-bd1a-00112444be1e"
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()

	inb, err := NewInbound(ctx, vlessEncEchoRouter{replySuffix: []byte("|pong-secret")}, logger, "vless-enc-in", option.VLESSInboundOptions{
		Users: []option.VLESSUser{{Name: "alice", UUID: testUUID}},
		Decryption: &option.VLESSDecryptionOptions{
			Enabled:      true,
			PrivateKey:   kp.PrivateKey,
			MLKEM768Seed: kp.MLKEM768Seed,
			TicketSecret: kp.TicketSecret,
			XorMode:      vlessenc.XorRandom,
			XorPSK:       kp.XorPSK,
		},
	})
	require.NoError(t, err)
	inbound := inb.(*Inbound)

	// Start a plain TCP listener delivering accepted raw sockets directly into Inbound.NewConnection
	// (no TLS configured: certificate-less Hybrid KEM + AEAD provides full wire confidentiality).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	var wireMu sync.Mutex
	var wireBuf bytes.Buffer
	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				if errors.Is(aErr, net.ErrClosed) {
					return
				}
				continue
			}
			rec := &wireRecorderConn{Conn: c, mu: &wireMu, wire: &wireBuf}
			go inbound.NewConnection(ctx, rec, adapter.InboundContext{
				Source: M.SocksaddrFrom(M.AddrFromIP(net.ParseIP("127.0.0.1")), 12345),
			}, nil)
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	outb, err := NewOutbound(ctx, nil, logger, "vless-enc-out", option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(tcpAddr.Port)},
		UUID:          testUUID,
		Encryption: &option.VLESSEncryptionOptions{
			Enabled:          true,
			PublicKey:        kp.PublicKey,
			MLKEM768EncapKey: kp.MLKEM768EncapKey,
			Mode:             vlessenc.ModeZeroRTT,
			XorMode:          vlessenc.XorRandom,
			XorPSK:           kp.XorPSK,
		},
	})
	require.NoError(t, err)
	outbound := outb.(*Outbound)

	// Run 2 sequential VLESS connections: first negotiates 1-RTT + ticket, second uses 0-RTT.
	dest := M.ParseSocksaddrHostPort("echo.example.org", 8080)
	for i, msg := range []string{"secret-vless-payload-1", "secret-vless-payload-2"} {
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, dErr := outbound.DialContext(dialCtx, N.NetworkTCP, dest)
		cancel()
		require.NoError(t, dErr, "conn %d", i)

		_, wErr := conn.Write([]byte(msg))
		require.NoError(t, wErr)

		expected := msg + "|pong-secret"
		got := make([]byte, len(expected))
		_, rErr := io.ReadFull(conn, got)
		require.NoError(t, rErr)
		require.Equal(t, expected, string(got))
		require.NoError(t, conn.Close())
	}

	wireMu.Lock()
	captured := append([]byte(nil), wireBuf.Bytes()...)
	wireMu.Unlock()
	require.NotEmpty(t, captured)
	require.False(t, bytes.Contains(captured, []byte("secret-vless-payload")))
	require.False(t, bytes.Contains(captured, []byte("pong-secret")))
	require.False(t, bytes.Contains(captured, []byte("echo.example.org")))
	// Ensure no plaintext TLS ClientHello header (0x16 0x03) appears at byte 0.
	require.False(t, len(captured) >= 2 && captured[0] == 0x16 && captured[1] == 0x03)
}
