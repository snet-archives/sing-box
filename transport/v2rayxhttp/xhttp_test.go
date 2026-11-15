package v2rayxhttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck
)

type testDialer struct {
	dialCount atomic.Int32
	onDial    func(addr M.Socksaddr)
}

func (d *testDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dialCount.Add(1)
	if d.onDial != nil {
		d.onDial(destination)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, destination.String())
}

func (d *testDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

type handlerFunc func(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc)

type testServerHandler struct {
	fn handlerFunc
}

func (h testServerHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.fn(ctx, conn, adapter.InboundContext{
		Source:      source,
		Destination: destination,
	}, onClose)
}

func halfCloseEchoHandler() adapter.V2RayServerTransportHandler {
	return testServerHandler{
		fn: func(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
			go func() {
				defer func() {
					_ = conn.Close()
					if onClose != nil {
						onClose(nil)
					}
				}()
				data, err := io.ReadAll(conn)
				if err != nil {
					return
				}
				resp := append([]byte("echo:"), data...)
				_, _ = conn.Write(resp)
			}()
		},
	}
}

func streamingEchoHandler() adapter.V2RayServerTransportHandler {
	return testServerHandler{
		fn: func(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
			go func() {
				defer func() {
					_ = conn.Close()
					if onClose != nil {
						onClose(nil)
					}
				}()
				_, _ = io.Copy(conn, conn)
			}()
		},
	}
}

func generateCertPair(t *testing.T, dnsName string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{dnsName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}

func newTLSPair(t *testing.T, serverName string, alpn []string) (tls.ServerConfig, tls.Config, option.OutboundTLSOptions) {
	t.Helper()
	certPEM, keyPEM := generateCertPair(t, serverName)
	srvCfg, err := tls.NewServerWithOptions(tls.ServerOptions{
		Context: context.Background(),
		Logger:  logger.NOP(),
		Options: option.InboundTLSOptions{
			Enabled:     true,
			ServerName:  serverName,
			ALPN:        alpn,
			Certificate: []string{certPEM},
			Key:         []string{keyPEM},
		},
	})
	require.NoError(t, err)
	require.NoError(t, srvCfg.Start())
	t.Cleanup(func() { _ = srvCfg.Close() })

	outOpts := option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  serverName,
		ALPN:        alpn,
		Certificate: []string{certPEM},
	}
	cliCfg, err := tls.NewClientWithOptions(tls.ClientOptions{
		Context:       context.Background(),
		Logger:        logger.NOP(),
		ServerAddress: serverName,
		Options:       outOpts,
	})
	require.NoError(t, err)
	return srvCfg, cliCfg, outOpts
}

func startXHTTPServer(t *testing.T, opts option.V2RayXHTTPOptions, srvTLS tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, M.Socksaddr) {
	t.Helper()
	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, handler)
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = srv.Close()
		_ = ln.Close()
	})
	go func() {
		_ = srv.Serve(ln)
	}()
	tcpAddr := ln.Addr().(*net.TCPAddr)
	return srv, M.SocksaddrFrom(M.AddrFromIP(tcpAddr.IP), uint16(tcpAddr.Port))
}

func assertHalfCloseEcho(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	wc, ok := conn.(interface{ CloseWrite() error })
	require.True(t, ok, "conn must support CloseWrite")

	_, err := conn.Write(payload)
	require.NoError(t, err)
	require.NoError(t, wc.CloseWrite())

	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	expected := append([]byte("echo:"), payload...)
	require.Equal(t, expected, got)
	require.NoError(t, conn.Close())
}

func TestXHTTPOptionsJSONAndValidation(t *testing.T) {
	t.Parallel()

	certPEM, _ := generateCertPair(t, "dl.example.com")
	raw := `{
		"type": "xhttp",
		"host": ["up.example.com"],
		"path": "/xhttp",
		"mode": "stream-up",
		"no_sse_header": true,
		"x_padding_bytes": "100-200",
		"sc_max_each_post_bytes": 65536,
		"sc_min_posts_interval_ms": "10-20",
		"sc_max_buffered_posts": 16,
		"sc_stream_up_server_secs": "1-2",
		"x_padding_placement": "query_in_header",
		"session_placement": "header",
		"seq_placement": "cookie",
		"uplink_data_placement": "body",
		"download_address": "127.0.0.1",
		"download_port": 8443,
		"download_dialer": {"connect_timeout": "3s"},
		"download_tls": {"enabled": true, "server_name": "dl.example.com", "certificate": [` + "`" + `` + "`" + `]},
		"xmux": {"max_concurrency": 4, "h_max_request_times": "2-3"}
	}`
	// Use proper JSON encoding for multi-line PEM certificate.
	certJSON, err := json.Marshal(certPEM)
	require.NoError(t, err)
	raw = strings.Replace(raw, "[``]", "["+string(certJSON)+"]", 1)

	var transportOpts option.V2RayTransportOptions
	require.NoError(t, json.UnmarshalContext(context.Background(), []byte(raw), &transportOpts))
	require.Equal(t, C.V2RayTransportTypeXHTTP, transportOpts.Type)
	require.Equal(t, "stream-up", transportOpts.XHTTPOptions.Mode)
	require.Equal(t, "query_in_header", transportOpts.XHTTPOptions.XPaddingPlacement)
	require.NotNil(t, transportOpts.XHTTPOptions.DownloadDialer)
	require.NotNil(t, transportOpts.XHTTPOptions.DownloadTLS)
	require.NotNil(t, transportOpts.XHTTPOptions.Xmux)

	badConfigs := []struct {
		name string
		opts option.V2RayXHTTPOptions
	}{
		{
			name: "stream-one with download split",
			opts: option.V2RayXHTTPOptions{
				Mode:            "stream-one",
				DownloadAddress: "127.0.0.1",
			},
		},
		{
			name: "bad mode",
			opts: option.V2RayXHTTPOptions{Mode: "invalid-mode"},
		},
		{
			name: "bad x_padding_placement",
			opts: option.V2RayXHTTPOptions{XPaddingPlacement: "body"},
		},
		{
			name: "bad session_placement",
			opts: option.V2RayXHTTPOptions{SessionPlacement: "body"},
		},
		{
			name: "bad seq_placement",
			opts: option.V2RayXHTTPOptions{SeqPlacement: "body"},
		},
		{
			name: "bad uplink_data_placement",
			opts: option.V2RayXHTTPOptions{UplinkDataPlacement: "path"},
		},
		{
			name: "negative uplink_chunk_size",
			opts: option.V2RayXHTTPOptions{UplinkChunkSize: -1},
		},
		{
			name: "inverted range",
			opts: option.V2RayXHTTPOptions{XPaddingBytes: option.XmuxRange{From: 50, To: 10}},
		},
		{
			name: "bad xmux",
			opts: option.V2RayXHTTPOptions{Xmux: &option.XmuxOptions{MaxConcurrency: option.XmuxRange{From: 10, To: 2}}},
		},
	}
	for _, tc := range badConfigs {
		_, err := NewServer(context.Background(), logger.NOP(), tc.opts, nil, streamingEchoHandler())
		require.Error(t, err, tc.name)
		_, err = NewClient(context.Background(), &testDialer{}, M.ParseSocksaddrHostPort("127.0.0.1", 443), tc.opts, nil)
		require.Error(t, err, tc.name)
	}
}

func TestXHTTPStreamOneTLSAndH2C(t *testing.T) {
	t.Parallel()

	for _, useTLS := range []bool{true, false} {
		name := "h2c"
		if useTLS {
			name = "tls_h2"
		}
		t.Run(name, func(t *testing.T) {
			var srvTLS tls.ServerConfig
			var cliTLS tls.Config
			if useTLS {
				srvTLS, cliTLS, _ = newTLSPair(t, "xhttp.example.com", nil)
			}
			opts := option.V2RayXHTTPOptions{
				Path:              "/streamone",
				Mode:              "stream-one",
				XPaddingPlacement: "query_in_header",
				XPaddingBytes:     option.XmuxRange{From: 64, To: 128},
			}
			_, addr := startXHTTPServer(t, opts, srvTLS, streamingEchoHandler())
			client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx)
			require.NoError(t, err)
			defer conn.Close()

			// Exercise multiple streaming turns over single stream-one connection.
			for _, msg := range [][]byte{
				[]byte("first-frame"),
				bytes.Repeat([]byte("AB"), 16*1024),
			} {
				_, err = conn.Write(msg)
				require.NoError(t, err)
				got := make([]byte, len(msg))
				_, err = io.ReadFull(conn, got)
				require.NoError(t, err)
				require.Equal(t, msg, got)
			}
		})
	}
}

func TestXHTTPStreamUpRotationHalfCloseAndSSEHeaders(t *testing.T) {
	t.Parallel()

	for _, noSSE := range []bool{false, true} {
		name := "sse_enabled"
		if noSSE {
			name = "no_sse_header"
		}
		t.Run(name, func(t *testing.T) {
			srvTLS, cliTLS, _ := newTLSPair(t, "streamup.example.com", nil)
			opts := option.V2RayXHTTPOptions{
				Path:                 "/split",
				Mode:                 "stream-up",
				NoSSEHeader:          noSSE,
				ScStreamUpServerSecs: option.XmuxRange{From: 1, To: 1},
				XPaddingBytes:        option.XmuxRange{From: 32, To: 64},
			}
			_, addr := startXHTTPServer(t, opts, srvTLS, streamingEchoHandler())

			d := &testDialer{}
			client, err := NewClient(context.Background(), d, addr, opts, cliTLS)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			// Verify response headers on downlink GET directly.
			req := client.cfg.buildRequest(client.dlURL, http.MethodGet, "streamup.example.com", client.headers, "probe-sse", nil, nil)
			resp, err := client.downlinkPool.roundTrip(req)
			require.NoError(t, err)
			require.Equal(t, "no", resp.Header.Get("X-Accel-Buffering"))
			if noSSE {
				require.NotEqual(t, "text/event-stream", resp.Header.Get("Content-Type"))
			} else {
				require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
			}
			_ = resp.Body.Close()
		})
	}

	// Verify mid-stream rotation (sc_stream_up_server_secs=1) and CloseWrite EOF propagation.
	srvTLS, cliTLS, _ := newTLSPair(t, "rotate.example.com", nil)
	opts := option.V2RayXHTTPOptions{
		Path:                 "/rotate",
		Mode:                 "stream-up",
		ScStreamUpServerSecs: option.XmuxRange{From: 1, To: 1},
	}
	_, addr := startXHTTPServer(t, opts, srvTLS, halfCloseEchoHandler())
	client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)

	part1 := []byte("before-rotation-")
	part2 := []byte("after-rotation!")
	_, err = conn.Write(part1)
	require.NoError(t, err)

	// Wait slightly over 1s so streamUpBodyReader triggers EOF rotation and continues on seq=1.
	time.Sleep(1150 * time.Millisecond)

	_, err = conn.Write(part2)
	require.NoError(t, err)
	require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())

	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, append([]byte("echo:"), append(part1, part2...)...), got)
	require.NoError(t, conn.Close())
}

func TestXHTTPPacketUpPlacementsAndPacing(t *testing.T) {
	t.Parallel()

	type combo struct {
		name        string
		sessionPlac string
		seqPlac     string
		padPlac     string
		dataPlac    string
		useTLS      bool
	}
	combos := []combo{
		{"defaults_h1", "path", "path", "header", "body", false},
		{"header_cookie_query", "header", "cookie", "query", "header", true},
		{"cookie_header_referer_cookie", "cookie", "header", "query_in_header", "cookie", false},
		{"query_query_cookie_query", "query", "query", "cookie", "query", false},
	}

	for _, tc := range combos {
		t.Run(tc.name, func(t *testing.T) {
			var srvTLS tls.ServerConfig
			var cliTLS tls.Config
			if tc.useTLS {
				srvTLS, cliTLS, _ = newTLSPair(t, "pkt.example.com", []string{"http/1.1"})
			}
			opts := option.V2RayXHTTPOptions{
				Path:                 "/pkt",
				Mode:                 "packet-up",
				SessionPlacement:     tc.sessionPlac,
				SeqPlacement:         tc.seqPlac,
				XPaddingPlacement:    tc.padPlac,
				UplinkDataPlacement:  tc.dataPlac,
				XPaddingBytes:        option.XmuxRange{From: 24, To: 48},
				ScMaxEachPostBytes:   option.XmuxRange{From: 150, To: 150},
				ScMinPostsIntervalMs: option.XmuxRange{From: 5, To: 10},
				UplinkChunkSize:      120,
			}
			_, addr := startXHTTPServer(t, opts, srvTLS, halfCloseEchoHandler())
			client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx)
			require.NoError(t, err)

			payload := bytes.Repeat([]byte("0123456789abcdef"), 30) // 480 bytes -> multiple POSTs
			assertHalfCloseEcho(t, conn, payload)
		})
	}
}

func TestXHTTPPacketUpOutOfOrderSeqRecovery(t *testing.T) {
	t.Parallel()

	srv, addr := startXHTTPServer(t, option.V2RayXHTTPOptions{
		Path:               "/ooo",
		Mode:               "packet-up",
		ScMaxBufferedPosts: option.XmuxRange{From: 8, To: 8},
	}, nil, halfCloseEchoHandler())
	_ = srv

	baseURL := "http://" + addr.String() + "/ooo"
	sessID := "ooo-session-01"
	hc := &http.Client{Timeout: 5 * time.Second}

	dlResp, err := hc.Get(baseURL + "/" + sessID)
	require.NoError(t, err)
	defer dlResp.Body.Close()

	sendSeq := func(seq string, body string, end bool) {
		req, reqErr := http.NewRequest(http.MethodPost, baseURL+"/"+sessID+"/"+seq, strings.NewReader(body))
		require.NoError(t, reqErr)
		if end {
			req.Header.Set("X-Stream-End", "1")
		}
		resp, respErr := hc.Do(req)
		require.NoError(t, respErr)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
	}

	// Deliver chunks 2, 1, 0 intentionally out of order.
	sendSeq("2", "-third", true)
	sendSeq("1", "-second", false)
	sendSeq("0", "first", false)

	got, err := io.ReadAll(dlResp.Body)
	require.NoError(t, err)
	require.Equal(t, []byte("echo:first-second-third"), got)
}

func TestXHTTPDownloadSeparationAndFetchHeaders(t *testing.T) {
	t.Parallel()

	upSrvTLS, upCliTLS, _ := newTLSPair(t, "up.example.com", nil)
	dlSrvTLS, _, dlOutTLS := newTLSPair(t, "dl.example.com", nil)

	var upMu, dlMu sync.Mutex
	var upMethods, dlMethods []string
	var capturedHeaders http.Header

	upSrv, err := NewServer(context.Background(), logger.NOP(), option.V2RayXHTTPOptions{
		Path: "/sep",
		Mode: "stream-up",
	}, upSrvTLS, halfCloseEchoHandler())
	require.NoError(t, err)
	dlSrv, err := NewServer(context.Background(), logger.NOP(), option.V2RayXHTTPOptions{
		Path: "/sep",
		Mode: "stream-up",
	}, dlSrvTLS, halfCloseEchoHandler())
	require.NoError(t, err)

	// Share one session table or use separate uplink/downlink HTTP handlers dispatching to the same Server instance.
	// Here upSrv owns the session table; dlListener terminates dlSrvTLS and delegates HTTP GET to upSrv.ServeHTTP.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	dlLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = upSrv.Close()
		_ = dlSrv.Close()
		_ = upLn.Close()
		_ = dlLn.Close()
	})

	upH2 := &http2.Server{}
	dlH2 := &http2.Server{}
	upHTTP := &http.Server{
		//nolint:staticcheck
		Handler: h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upMu.Lock()
			upMethods = append(upMethods, r.Method)
			if capturedHeaders == nil {
				capturedHeaders = r.Header.Clone()
			}
			upMu.Unlock()
			upSrv.ServeHTTP(w, r)
		}), upH2),
	}
	dlHTTP := &http.Server{
		//nolint:staticcheck
		Handler: h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			dlMu.Lock()
			dlMethods = append(dlMethods, r.Method)
			dlMu.Unlock()
			upSrv.ServeHTTP(w, r)
		}), dlH2),
	}
	require.NoError(t, http2.ConfigureServer(upHTTP, upH2))
	require.NoError(t, http2.ConfigureServer(dlHTTP, dlH2))

	upWrappedLn := &tlsAcceptListener{Listener: upLn, tlsConfig: upSrvTLS}
	dlWrappedLn := &tlsAcceptListener{Listener: dlLn, tlsConfig: dlSrvTLS}
	go func() { _ = upHTTP.Serve(upWrappedLn) }()
	go func() { _ = dlHTTP.Serve(dlWrappedLn) }()
	t.Cleanup(func() {
		_ = upHTTP.Close()
		_ = dlHTTP.Close()
	})

	upTCP := upLn.Addr().(*net.TCPAddr)
	dlTCP := dlLn.Addr().(*net.TCPAddr)
	upAddr := M.SocksaddrFrom(M.AddrFromIP(upTCP.IP), uint16(upTCP.Port))

	upDialer := &testDialer{}
	client, err := NewClient(context.Background(), upDialer, upAddr, option.V2RayXHTTPOptions{
		Path:            "/sep",
		Mode:            "stream-up",
		DownloadAddress: "127.0.0.1",
		DownloadPort:    uint16(dlTCP.Port),
		DownloadDialer:  &option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{ConnectTimeout: badoption.Duration(5 * time.Second)}},
		DownloadTLS:     &dlOutTLS,
	}, upCliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn, []byte("split-channel-payload"))

	upMu.Lock()
	gotUp := append([]string(nil), upMethods...)
	hdrs := capturedHeaders
	upMu.Unlock()
	dlMu.Lock()
	gotDL := append([]string(nil), dlMethods...)
	dlMu.Unlock()

	// Under -race scheduling, Write and CloseWrite in assertHalfCloseEcho may either
	// coalesce into a single POST with X-Stream-End: 1 or emit a second empty EOF POST.
	require.GreaterOrEqual(t, len(gotUp), 1)
	require.LessOrEqual(t, len(gotUp), 2)
	for _, m := range gotUp {
		require.Equal(t, http.MethodPost, m)
	}
	require.Equal(t, []string{http.MethodGet}, gotDL)
	require.Equal(t, "cors", hdrs.Get("Sec-Fetch-Mode"))
	require.Equal(t, "empty", hdrs.Get("Sec-Fetch-Dest"))
	require.Equal(t, "same-origin", hdrs.Get("Sec-Fetch-Site"))
	require.NotEmpty(t, hdrs.Get("User-Agent"))
}

type tlsAcceptListener struct {
	net.Listener
	tlsConfig tls.ServerConfig
}

func (l *tlsAcceptListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.tlsConfig.Server(conn)
}

func TestXHTTPXmuxHTTPPoolRotation(t *testing.T) {
	t.Parallel()

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	cert := ts.Certificate()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	cliTLS, err := tls.NewClientWithOptions(tls.ClientOptions{
		Context:       context.Background(),
		Logger:        logger.NOP(),
		ServerAddress: "example.com",
		Options: option.OutboundTLSOptions{
			Enabled:     true,
			Insecure:    true,
			ALPN:        []string{"h2"},
			Certificate: []string{string(certPEM)},
		},
	})
	require.NoError(t, err)

	d := &testDialer{}
	addr := M.ParseSocksaddr(ts.Listener.Addr().String())
	client, err := NewClient(context.Background(), d, addr, option.V2RayXHTTPOptions{
		Path: "/",
		Mode: "stream-up",
		Xmux: &option.XmuxOptions{
			MaxConcurrency:   option.XmuxRange{From: 2, To: 2},
			MaxConnections:   option.XmuxRange{From: 1, To: 1},
			HMaxRequestTimes: option.XmuxRange{From: 2, To: 2},
		},
	}, cliTLS)
	require.NoError(t, err)
	defer client.Close()

	for i := range 5 {
		req, reqErr := http.NewRequest(http.MethodPost, ts.URL+"/", http.NoBody)
		require.NoError(t, reqErr)
		req = req.WithContext(adapter.ContextWithKeepSession(context.Background()))
		resp, rtErr := client.uplinkPool.roundTrip(req)
		require.NoError(t, rtErr, "request %d", i)
		_, _ = io.Copy(io.Discard, resp.Body)
		require.NoError(t, resp.Body.Close())
	}

	// With HMaxRequestTimes=2 over 5 sequential round-trips: 2 + 2 + 1 => 3 underlying TCP/TLS dials.
	require.Equal(t, int32(3), d.dialCount.Load())
}
