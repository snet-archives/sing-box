package anytls_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type fakeRouter struct {
	adapter.Router
	onRoute func(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc)
}

func (f *fakeRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	f.onRoute(ctx, conn, metadata, onClose)
}

func TestAnyTLSInboundMasqueradeStringFallback(t *testing.T) {
	inbound, err := anytls.NewInbound(
		context.Background(),
		&fakeRouter{},
		log.NewNOPFactory().Logger(),
		"anytls-in",
		option.AnyTLSInboundOptions{
			Masquerade: &option.Hysteria2Masquerade{
				Type: "string",
				StringOptions: option.Hysteria2MasqueradeString{
					StatusCode: http.StatusTeapot,
					Headers: badoption.HTTPHeader{
						"X-Camouflage": badoption.Listable[string]{"nginx"},
					},
					Content: "hello fallback",
				},
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go inbound.(adapter.TCPInjectableInbound).NewConnection(context.Background(), c2, adapter.InboundContext{
		Source: M.ParseSocksaddr("127.0.0.1:40000"),
	}, func(err error) {
		close(done)
	})

	if _, err := io.WriteString(c1, "GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c1), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = c1.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("expected status 418, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Camouflage") != "nginx" {
		t.Fatalf("expected header X-Camouflage=nginx, got %q", resp.Header.Get("X-Camouflage"))
	}
	if string(body) != "hello fallback" {
		t.Fatalf("expected body %q, got %q", "hello fallback", string(body))
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("onClose not invoked after masquerade connection closed")
	}
}

func TestAnyTLSInboundTCPFallbackRouting(t *testing.T) {
	routed := make(chan M.Socksaddr, 1)
	received := make(chan string, 1)
	inbound, err := anytls.NewInbound(
		context.Background(),
		&fakeRouter{
			onRoute: func(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
				defer conn.Close()
				routed <- metadata.Destination
				buf := make([]byte, 64)
				n, _ := conn.Read(buf)
				received <- string(buf[:n])
				_, _ = conn.Write([]byte("PONG"))
				if onClose != nil {
					onClose(nil)
				}
			},
		},
		log.NewNOPFactory().Logger(),
		"anytls-in",
		option.AnyTLSInboundOptions{
			Fallback: &option.ServerOptions{
				Server:     "127.0.0.1",
				ServerPort: 8080,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()
	go inbound.(adapter.TCPInjectableInbound).NewConnection(context.Background(), c2, adapter.InboundContext{
		Source: M.ParseSocksaddr("127.0.0.1:40001"),
	}, nil)

	const probe = "GET / HTTP/1.0\r\n\r\n"
	if _, err := io.WriteString(c1, probe); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(c1, reply); err != nil {
		t.Fatal(err)
	}
	_ = c1.Close()

	if dest := <-routed; dest.String() != "127.0.0.1:8080" {
		t.Fatalf("unexpected fallback destination: %s", dest)
	}
	if got := <-received; got != probe {
		t.Fatalf("expected replayed fallback bytes %q, got %q", probe, got)
	}
	if string(reply) != "PONG" {
		t.Fatalf("unexpected reply %q", reply)
	}
}
