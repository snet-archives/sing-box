//go:build with_quic

package vless

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/vlessenc"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

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

func startVLESSXHTTPH3Pair(t *testing.T, router adapter.Router, alpn []string, mode string) adapter.Outbound {
	t.Helper()
	uid, kp := mustVLESSKeypairAndUUID(t)
	decOpts, encOpts := makeVLESSEncConfigs(kp, vlessenc.XorRandom, "", "")
	certPEM, keyPEM, pin := certPEMPairFromStrings(t)
	port := reserveLocalDualPort(t)

	ctx, cancel := context.WithCancel(context.Background())
	scope := adapter.NewScope(ctx, logger.NOP())

	xhttpOpts := option.V2RayXHTTPOptions{
		Path:                 "/xhttp-h3",
		Mode:                 mode,
		ScMaxEachPostBytes:   option.XmuxRange{From: 2048, To: 2048},
		ScMaxConcurrentPosts: option.XmuxRange{From: 4, To: 4},
		ScDownlinkServerSecs: option.XmuxRange{From: 1, To: 1},
		QUIC: &option.QUICOptions{
			HTTP2Options: option.HTTP2Options{
				MaxConcurrentStreams: 32,
			},
		},
	}

	in, err := NewInbound(ctx, router, logger.NOP(), "vless-xhttp-h3-in", option.VLESSInboundOptions{
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
				ALPN:        alpn,
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
				ALPN:                       alpn,
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

	t.Cleanup(func() {
		scope.Close()
		cancel()
	})
	return out
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
			out := startVLESSXHTTPH3Pair(t, vlessEncEchoRouter{}, tc.alpn, tc.mode)
			large := bytes.Repeat([]byte("VLESS_XHTTP_H3_E2E_"), 900) // ~17 KB
			assertVLESSOutboundEcho(t, out, []byte("xhttp-h3-1rtt"), []byte("xhttp-h3-0rtt"), large)
		})
	}
}

type copyOriginRouter struct {
	adapter.Router
	originAddr string
	errCh      chan error
}

func (r *copyOriginRouter) RouteConnection(context.Context, net.Conn, adapter.InboundContext) error {
	return nil
}

func (r *copyOriginRouter) RoutePacketConnection(context.Context, N.PacketConn, adapter.InboundContext) error {
	return nil
}

func (r *copyOriginRouter) RoutePacketConnectionEx(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func (r *copyOriginRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	go func() {
		remote, err := net.Dial("tcp", r.originAddr)
		if err != nil {
			_ = conn.Close()
			if onClose != nil {
				onClose(err)
			}
			r.errCh <- err
			return
		}
		err = bufio.CopyConn(ctx, conn, remote)
		if onClose != nil {
			onClose(err)
		}
		r.errCh <- err
	}()
}

func readAllWithTimeout(t *testing.T, r io.Reader, timeout time.Duration) []byte {
	t.Helper()
	type res struct {
		data []byte
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		data, err := io.ReadAll(r)
		ch <- res{data: data, err: err}
	}()
	select {
	case out := <-ch:
		require.NoError(t, out.err)
		return out.data
	case <-time.After(timeout):
		t.Fatalf("timed out after %v waiting for io.ReadAll EOF", timeout)
		return nil
	}
}

func TestVLESSXHTTPHTTP3HalfCloseAndOriginEOF(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, err := c.Read(buf)
				if err != nil && n == 0 {
					return
				}
				first := buf[:n]
				if bytes.HasPrefix(first, []byte("ORIGIN_EOF:")) {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n35.212.247.146\n"))
					return
				}
				rest, _ := io.ReadAll(c)
				_, _ = c.Write(append([]byte("CLIENT_FIN_ACK:"), append(first, rest...)...))
			}(c)
		}
	}()

	dst := M.ParseSocksaddrHostPort("origin.local", 80)
	for _, tc := range []struct {
		name string
		alpn []string
		mode string
	}{
		{name: "pure_h3_stream_one", alpn: []string{"h3"}, mode: "stream-one"},
		{name: "h3_h2_stream_one", alpn: []string{"h3", "h2"}, mode: "stream-one"},
		{name: "pure_h3_stream_up", alpn: []string{"h3"}, mode: "stream-up"},
		{name: "pure_h3_packet_up", alpn: []string{"h3"}, mode: "packet-up"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			errCh := make(chan error, 8)
			router := &copyOriginRouter{originAddr: ln.Addr().String(), errCh: errCh}
			out := startVLESSXHTTPH3Pair(t, router, tc.alpn, tc.mode)

			t.Run("origin_closes_first", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := out.(N.Dialer).DialContext(ctx, N.NetworkTCP, dst)
				require.NoError(t, err)
				defer conn.Close()

				_, err = conn.Write([]byte("ORIGIN_EOF:GET / HTTP/1.1\r\n\r\n"))
				require.NoError(t, err)
				got := readAllWithTimeout(t, conn, 5*time.Second)
				require.Equal(t, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n35.212.247.146\n", string(got))

				require.NoError(t, N.CloseWrite(conn))
				select {
				case copyErr := <-errCh:
					if copyErr != nil && !E.IsClosed(copyErr) {
						t.Fatalf("unexpected server CopyConn error: %v", copyErr)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("timed out waiting for server CopyConn shutdown")
				}
			})

			t.Run("client_half_close", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := out.(N.Dialer).DialContext(ctx, N.NetworkTCP, dst)
				require.NoError(t, err)
				defer conn.Close()

				req := []byte("CLIENT_FIN:halfclose-payload")
				_, err = conn.Write(req)
				require.NoError(t, err)
				require.NoError(t, N.CloseWrite(conn))

				got := readAllWithTimeout(t, conn, 5*time.Second)
				require.Equal(t, "CLIENT_FIN_ACK:CLIENT_FIN:halfclose-payload", string(got))

				select {
				case copyErr := <-errCh:
					if copyErr != nil && !E.IsClosed(copyErr) {
						t.Fatalf("unexpected server CopyConn error: %v", copyErr)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("timed out waiting for server CopyConn shutdown")
				}
			})
		})
	}
}
