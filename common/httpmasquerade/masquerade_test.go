package httpmasquerade

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	aTLS "github.com/sagernet/sing/common/tls"
)

type stubTLSConn struct {
	net.Conn
	state tls.ConnectionState
}

func (c *stubTLSConn) NetConn() net.Conn {
	return c.Conn
}

func (c *stubTLSConn) HandshakeContext(context.Context) error {
	return nil
}

func (c *stubTLSConn) ConnectionState() aTLS.ConnectionState {
	return c.state
}

func TestServeConnPlainTCPDisablesKeepAliveForReverseProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var acceptCount atomic.Int32
	fallbackClosed := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n := acceptCount.Add(1)
			go func(c net.Conn, idx int32) {
				if idx == 1 {
					ServeConn(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						_, _ = io.WriteString(w, "fallback")
					}), c, func(error) {
						close(fallbackClosed)
					})
					return
				}
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				_ = req.Body.Close()
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nprotocol-ok")
			}(conn, n)
		}
	}()

	targetURL, err := url.Parse("http://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxyTransport := &http.Transport{
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 10,
	}
	proxy.Transport = proxyTransport
	t.Cleanup(proxyTransport.CloseIdleConnections)

	frontServer := httptest.NewServer(proxy)
	t.Cleanup(frontServer.Close)

	client := &http.Client{Timeout: 5 * time.Second}

	resp1, err := client.Get(frontServer.URL + "/probe")
	if err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK || string(body1) != "fallback" {
		t.Fatalf("unexpected request 1 response: status=%d body=%q", resp1.StatusCode, body1)
	}

	select {
	case <-fallbackClosed:
	case <-time.After(3 * time.Second):
		t.Fatal("fallback backend connection did not close after HTTP/1.1 plain-TCP response")
	}

	resp2, err := client.Get(frontServer.URL + "/real")
	if err != nil {
		t.Fatalf("request 2 failed: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || string(body2) != "protocol-ok" {
		t.Fatalf("reverse proxy reused poisoned fallback socket: status=%d body=%q", resp2.StatusCode, body2)
	}
	if got := acceptCount.Load(); got != 2 {
		t.Fatalf("expected 2 backend accepts without connection pooling reuse, got %d", got)
	}
}

func TestServeConnPlainTCPSendsConnectionClose(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	closedCh := make(chan struct{})
	go ServeConn(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "masq")
	}), serverConn, func(error) {
		close(closedCh)
	})

	_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err := io.WriteString(clientConn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "masq" {
		t.Fatalf("unexpected body %q", body)
	}
	if !resp.Close {
		t.Fatalf("expected Connection: close on plain-TCP fallback response, got headers %v", resp.Header)
	}

	select {
	case <-closedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("plain-TCP ServeConn did not close socket without client closing first")
	}
}

func TestServeConnTLSAllowsKeepAlive(t *testing.T) {
	rawServerConn, clientConn := net.Pipe()
	defer clientConn.Close()

	tlsServerConn := &stubTLSConn{
		Conn: rawServerConn,
		state: tls.ConnectionState{
			NegotiatedProtocol: "",
		},
	}

	closedCh := make(chan struct{})
	go ServeConn(context.Background(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	}), tlsServerConn, func(error) {
		close(closedCh)
	})

	_ = clientConn.SetDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(clientConn)

	if _, err := io.WriteString(clientConn, "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("write first request: %v", err)
	}
	resp1, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if string(body1) != "/first" || resp1.Close {
		t.Fatalf("expected TLS HTTP/1.1 keep-alive on first request, got close=%v body=%q", resp1.Close, body1)
	}

	if _, err := io.WriteString(clientConn, "GET /second HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write second request: %v", err)
	}
	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read second response: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if string(body2) != "/second" {
		t.Fatalf("unexpected second body %q", body2)
	}

	select {
	case <-closedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("TLS ServeConn did not close after second request with Connection: close")
	}
}
