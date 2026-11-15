package v2rayxhttp

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestXHTTPValidationNewBatchOptions(t *testing.T) {
	t.Parallel()

	raw := `{
		"mode": "packet-up",
		"sc_max_concurrent_posts": "2-6",
		"sc_downlink_server_secs": "45-90",
		"quic": {
			"max_concurrent_streams": 64,
			"disable_path_mtu_discovery": true
		}
	}`
	var opts option.V2RayXHTTPOptions
	require.NoError(t, json.Unmarshal([]byte(raw), &opts))
	require.Equal(t, option.XmuxRange{From: 2, To: 6}, opts.ScMaxConcurrentPosts)
	require.Equal(t, option.XmuxRange{From: 45, To: 90}, opts.ScDownlinkServerSecs)
	require.NotNil(t, opts.QUIC)
	require.Equal(t, 64, opts.QUIC.MaxConcurrentStreams)
	require.True(t, opts.QUIC.DisablePathMTUDiscovery)

	badRanges := []option.V2RayXHTTPOptions{
		{ScMaxConcurrentPosts: option.XmuxRange{From: 8, To: 2}},
		{ScDownlinkServerSecs: option.XmuxRange{From: 90, To: 30}},
	}
	for _, bad := range badRanges {
		_, err := NewServer(context.Background(), logger.NOP(), bad, nil, streamingEchoHandler())
		require.Error(t, err)
		_, err = NewClient(context.Background(), &testDialer{}, M.ParseSocksaddrHostPort("127.0.0.1", 443), bad, nil)
		require.Error(t, err)
	}
}

func TestXHTTPPacketUpConcurrencyAndNoTransformHeaders(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "concurrent.example.com", []string{"h2"})
	opts := option.V2RayXHTTPOptions{
		Path:                 "/xhttp",
		Mode:                 "packet-up",
		ScMaxEachPostBytes:   option.XmuxRange{From: 1024, To: 1024},
		ScMaxBufferedPosts:   option.XmuxRange{From: 16, To: 16},
		ScMaxConcurrentPosts: option.XmuxRange{From: 4, To: 4},
	}
	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, halfCloseEchoHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	var inFlight atomic.Int32
	var maxInFlight atomic.Int32
	var postCount atomic.Int32
	var badCacheCtrl atomic.Int32

	addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &headerInspectWriter{ResponseWriter: w}
		if r.Method == http.MethodPost {
			postCount.Add(1)
			cur := inFlight.Add(1)
			for {
				prev := maxInFlight.Load()
				if cur <= prev || maxInFlight.CompareAndSwap(prev, cur) {
					break
				}
			}
			time.Sleep(25 * time.Millisecond)
			defer inFlight.Add(-1)
		}
		srv.ServeHTTP(rec, r)
		if cc := rec.Header().Get("Cache-Control"); cc != "" && cc != "no-store, no-transform" {
			badCacheCtrl.Add(1)
		}
	}))
	client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)

	payload := bytes.Repeat([]byte("CONCURRENT_PACKET_UP_"), 780) // ~16 KB across ~16 POSTs
	assertHalfCloseEcho(t, conn, payload)

	require.Zero(t, badCacheCtrl.Load())
	require.GreaterOrEqual(t, int(postCount.Load()), 16)
	require.GreaterOrEqual(t, int(maxInFlight.Load()), 2, "expected concurrent packet-up POST execution")
}

func TestXHTTPPacketUpConcurrencyRespectsBufferedWindow(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "window.example.com", []string{"h2"})
	opts := option.V2RayXHTTPOptions{
		Path:                 "/win",
		Mode:                 "packet-up",
		ScMaxEachPostBytes:   option.XmuxRange{From: 512, To: 512},
		ScMaxBufferedPosts:   option.XmuxRange{From: 2, To: 2},
		ScMaxConcurrentPosts: option.XmuxRange{From: 4, To: 4},
	}
	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, halfCloseEchoHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	var firstSeqDelayed atomic.Bool
	addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && firstSeqDelayed.CompareAndSwap(false, true) {
			time.Sleep(40 * time.Millisecond)
		}
		srv.ServeHTTP(w, r)
	}))
	client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)

	payload := bytes.Repeat([]byte("SLIDING_WINDOW_GUARD_"), 400) // ~8.4 KB
	assertHalfCloseEcho(t, conn, payload)
}

func TestXHTTPDownlinkRotationAcrossMultipleGETs(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "rotate-dl.example.com", []string{"h2"})
	opts := option.V2RayXHTTPOptions{
		Path:                 "/rotate",
		Mode:                 "packet-up",
		ScDownlinkServerSecs: option.XmuxRange{From: 1, To: 1},
	}

	const totalChunks = 12
	chunkSize := 1024
	expected := bytes.Repeat([]byte("ROTATING_DOWNLINK_STREAM_"), (totalChunks*chunkSize)/25+1)[:totalChunks*chunkSize]

	handler := testServerHandler{
		fn: func(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
			go func() {
				defer func() {
					_ = conn.Close()
					if onClose != nil {
						onClose(nil)
					}
				}()
				_, _ = io.ReadAll(conn)
				for i := 0; i < totalChunks; i++ {
					part := expected[i*chunkSize : (i+1)*chunkSize]
					if _, err := conn.Write(part); err != nil {
						return
					}
					time.Sleep(200 * time.Millisecond)
				}
			}()
		},
	}

	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, handler)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	var mu sync.Mutex
	var getSeqs []string
	var getOffsets []uint64
	addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			off, _ := strconv.ParseUint(r.Header.Get(headerDownlinkOffset), 10, 64)
			mu.Lock()
			getSeqs = append(getSeqs, r.Header.Get(headerDownlinkSeq))
			getOffsets = append(getOffsets, off)
			mu.Unlock()
		}
		srv.ServeHTTP(w, r)
	}))
	client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("start"))
	require.NoError(t, err)
	require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())

	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, expected, got)

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(getSeqs), 2, "expected multiple rotating downlink GETs")
	require.Equal(t, "0", getSeqs[0])
	require.Equal(t, uint64(0), getOffsets[0])
	require.Equal(t, "1", getSeqs[1])
	require.Greater(t, getOffsets[1], uint64(0))
}

func TestXHTTPDownlinkCutRecoveryAndTrailerStripping(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "cut-recover.example.com", []string{"h2"})
	opts := option.V2RayXHTTPOptions{
		Path: "/recover",
		Mode: "packet-up",
	}

	payload := bytes.Repeat([]byte("MID_STREAM_CDN_CUT_RECOVERY_"), 600) // ~16.8 KB
	handler := testServerHandler{
		fn: func(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
			go func() {
				defer func() {
					_ = conn.Close()
					if onClose != nil {
						onClose(nil)
					}
				}()
				_, _ = io.ReadAll(conn)
				// Write first part, pause briefly, then write remainder and close cleanly.
				_, _ = conn.Write(payload[:4096])
				time.Sleep(30 * time.Millisecond)
				_, _ = conn.Write(payload[4096:])
			}()
		},
	}

	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, handler)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	var getAttempts atomic.Int32
	addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			srv.ServeHTTP(w, r)
			return
		}
		attempt := getAttempts.Add(1)
		sw := &trailerStripAndCutWriter{
			ResponseWriter: w,
			cutAfter:       128,
			shouldCut:      attempt == 1,
		}
		srv.ServeHTTP(sw, r)
		if sw.aborted {
			panic(http.ErrAbortHandler)
		}
	}))
	client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("go"))
	require.NoError(t, err)
	require.NoError(t, conn.(interface{ CloseWrite() error }).CloseWrite())

	got, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.GreaterOrEqual(t, int(getAttempts.Load()), 2)
}

func TestXHTTPLegacyNonResumableDownlinkCompat(t *testing.T) {
	t.Parallel()

	opts := option.V2RayXHTTPOptions{
		Path: "/legacy",
		Mode: "packet-up",
	}
	srv, addr := startXHTTPServer(t, opts, nil, halfCloseEchoHandler())
	base := "http://" + addr.String() + "/legacy/legacy-sess-1"

	getResp, err := http.Get(base)
	require.NoError(t, err)
	defer getResp.Body.Close()
	require.Equal(t, http.StatusOK, getResp.StatusCode)
	require.Equal(t, "no-store, no-transform", getResp.Header.Get("Cache-Control"))

	dupResp, err := http.Get(base)
	require.NoError(t, err)
	_ = dupResp.Body.Close()
	require.Equal(t, http.StatusConflict, dupResp.StatusCode)

	postReq, err := http.NewRequest(http.MethodPost, base+"/0", bytes.NewReader([]byte("legacy-ok")))
	require.NoError(t, err)
	postReq.Header.Set(headerStreamEnd, "1")
	postResp, err := http.DefaultClient.Do(postReq)
	require.NoError(t, err)
	_ = postResp.Body.Close()
	require.Equal(t, http.StatusOK, postResp.StatusCode)

	got, err := io.ReadAll(getResp.Body)
	require.NoError(t, err)
	require.Equal(t, []byte("echo:legacy-ok"), got)
	require.NotNil(t, srv)
}

type headerInspectWriter struct {
	http.ResponseWriter
}

func (w *headerInspectWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type trailerStripAndCutWriter struct {
	http.ResponseWriter
	wroteHeader bool
	shouldCut   bool
	cutAfter    int
	written     int
	aborted     bool
}

func (w *trailerStripAndCutWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *trailerStripAndCutWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		// Emulate an HTTP proxy stripping response Trailer announcements.
		w.ResponseWriter.Header().Del("Trailer")
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *trailerStripAndCutWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.aborted {
		return 0, io.ErrClosedPipe
	}
	if w.shouldCut && w.written+len(p) >= w.cutAfter {
		rem := w.cutAfter - w.written
		if rem > 0 {
			n, _ := w.ResponseWriter.Write(p[:rem])
			w.written += n
		}
		if f, ok := w.ResponseWriter.(http.Flusher); ok {
			f.Flush()
		}
		w.aborted = true
		return rem, io.ErrClosedPipe
	}
	n, err := w.ResponseWriter.Write(p)
	w.written += n
	return n, err
}

func (w *trailerStripAndCutWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func startTLSHTTP2Proxy(t *testing.T, srvTLS tls.ServerConfig, handler http.Handler) M.Socksaddr {
	t.Helper()
	tcpTLS := srvTLS.Clone().(tls.ServerConfig)
	tcpTLS.SetNextProtos([]string{"h2", "http/1.1"})
	stdCfg, err := tcpTLS.STDConfig()
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tlsLn := stdtls.NewListener(ln, stdCfg)

	proxySrv := &http.Server{Handler: handler}
	require.NoError(t, http2.ConfigureServer(proxySrv, &http2.Server{}))
	t.Cleanup(func() {
		_ = proxySrv.Close()
		_ = tlsLn.Close()
	})
	go func() {
		_ = proxySrv.Serve(tlsLn)
	}()
	tcpAddr := ln.Addr().(*net.TCPAddr)
	return M.SocksaddrFrom(M.AddrFromIP(tcpAddr.IP), uint16(tcpAddr.Port))
}

func TestXHTTPPacketUpTransientRetryAndPermanentFailFast(t *testing.T) {
	t.Parallel()

	t.Run("transient_status_and_idempotent_seq_dedup", func(t *testing.T) {
		t.Parallel()

		srvTLS, cliTLS, _ := newTLSPair(t, "retry-up.example.com", []string{"h2"})
		opts := option.V2RayXHTTPOptions{
			Path:                 "/xhttp",
			Mode:                 "packet-up",
			ScMaxEachPostBytes:   option.XmuxRange{From: 512, To: 512},
			ScMaxBufferedPosts:   option.XmuxRange{From: 16, To: 16},
			ScMaxConcurrentPosts: option.XmuxRange{From: 1, To: 1},
		}
		srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, halfCloseEchoHandler())
		require.NoError(t, err)
		t.Cleanup(func() { _ = srv.Close() })

		var seq0Attempts atomic.Int32
		var seq1Attempts atomic.Int32
		addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				switch {
				case len(r.URL.Path) >= 2 && r.URL.Path[len(r.URL.Path)-2:] == "/0":
					switch seq0Attempts.Add(1) {
					case 1:
						// Simulate gateway failure before reaching origin.
						w.WriteHeader(http.StatusServiceUnavailable)
						return
					case 2:
						// Deliver chunk 0 to origin, then mask the response as 502 Bad Gateway
						// so the client must retry with the same seq=0 and rely on dedup.
						rec := httptest.NewRecorder()
						srv.ServeHTTP(rec, r)
						require.Equal(t, http.StatusOK, rec.Code)
						w.WriteHeader(http.StatusBadGateway)
						return
					}
				case len(r.URL.Path) >= 2 && r.URL.Path[len(r.URL.Path)-2:] == "/1":
					if seq1Attempts.Add(1) == 1 {
						w.WriteHeader(http.StatusTooManyRequests)
						return
					}
				}
			}
			srv.ServeHTTP(w, r)
		}))

		cli, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cli.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := cli.DialContext(ctx)
		require.NoError(t, err)
		payload := bytes.Repeat([]byte("IDEMPOTENT_RETRY_"), 128)
		assertHalfCloseEcho(t, conn, payload)
		require.Equal(t, int32(3), seq0Attempts.Load())
		require.Equal(t, int32(2), seq1Attempts.Load())
	})

	t.Run("permanent_403_fail_fast", func(t *testing.T) {
		t.Parallel()

		srvTLS, cliTLS, _ := newTLSPair(t, "failfast-up.example.com", []string{"h2"})
		opts := option.V2RayXHTTPOptions{
			Path:                 "/xhttp",
			Mode:                 "packet-up",
			ScMaxConcurrentPosts: option.XmuxRange{From: 1, To: 1},
		}
		srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, halfCloseEchoHandler())
		require.NoError(t, err)
		t.Cleanup(func() { _ = srv.Close() })

		var postAttempts atomic.Int32
		addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				postAttempts.Add(1)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			srv.ServeHTTP(w, r)
		}))

		cli, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cli.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := cli.DialContext(ctx)
		require.NoError(t, err)
		defer conn.Close()

		_, err = conn.Write([]byte("trigger-403"))
		require.NoError(t, err)
		err = conn.(N.WriteCloser).CloseWrite()
		if err == nil {
			buf := make([]byte, 64)
			_, err = conn.Read(buf)
		}
		require.Error(t, err)
		require.Equal(t, int32(1), postAttempts.Load())
	})
}

func TestXHTTPDownlinkTransientStatusRetryAndPermanentFailFast(t *testing.T) {
	t.Parallel()

	t.Run("transient_502_504_recovery", func(t *testing.T) {
		t.Parallel()

		srvTLS, cliTLS, _ := newTLSPair(t, "retry-down.example.com", []string{"h2"})
		opts := option.V2RayXHTTPOptions{
			Path:                 "/xhttp",
			Mode:                 "packet-up",
			ScMaxConcurrentPosts: option.XmuxRange{From: 1, To: 1},
		}
		srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, halfCloseEchoHandler())
		require.NoError(t, err)
		t.Cleanup(func() { _ = srv.Close() })

		var getAttempts atomic.Int32
		addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				switch getAttempts.Add(1) {
				case 1:
					w.WriteHeader(http.StatusBadGateway)
					return
				case 2:
					w.WriteHeader(http.StatusGatewayTimeout)
					return
				}
			}
			srv.ServeHTTP(w, r)
		}))

		cli, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cli.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := cli.DialContext(ctx)
		require.NoError(t, err)
		assertHalfCloseEcho(t, conn, []byte("hello-after-502-504"))
		require.Equal(t, int32(3), getAttempts.Load())
	})

	t.Run("permanent_404_fail_fast", func(t *testing.T) {
		t.Parallel()

		srvTLS, cliTLS, _ := newTLSPair(t, "failfast-down.example.com", []string{"h2"})
		opts := option.V2RayXHTTPOptions{
			Path:                 "/xhttp",
			Mode:                 "packet-up",
			ScMaxConcurrentPosts: option.XmuxRange{From: 1, To: 1},
		}
		srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, halfCloseEchoHandler())
		require.NoError(t, err)
		t.Cleanup(func() { _ = srv.Close() })

		var getAttempts atomic.Int32
		addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				getAttempts.Add(1)
				w.WriteHeader(http.StatusNotFound)
				return
			}
			srv.ServeHTTP(w, r)
		}))

		cli, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
		require.NoError(t, err)
		t.Cleanup(func() { _ = cli.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := cli.DialContext(ctx)
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 64)
			_, err = conn.Read(buf)
		}
		require.Error(t, err)
		require.Equal(t, int32(1), getAttempts.Load())
	})
}

type delayedCoalesceDialer struct {
	delay         time.Duration
	tcpDials      atomic.Int32
	firstCanceled atomic.Bool
}

func (d *delayedCoalesceDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkTCP {
		d.tcpDials.Add(1)
	}
	if d.delay > 0 {
		timer := time.NewTimer(d.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			d.firstCanceled.Store(true)
			return nil, ctx.Err()
		}
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, destination.String())
}

func (d *delayedCoalesceDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func TestXHTTPXmuxColdStartDialCoalescing(t *testing.T) {
	t.Parallel()

	t.Run("h2_concurrent_cold_start_coalesces_to_single_dial", func(t *testing.T) {
		t.Parallel()

		srvTLS, cliTLS, _ := newTLSPair(t, "coalesce-h2.example.com", []string{"h2"})
		addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
		dialer := &delayedCoalesceDialer{delay: 50 * time.Millisecond}
		pool := newXmuxHTTPPool(dialer, addr, cliTLS, true, 0, 0, mux.XmuxOptions{}, nil)
		t.Cleanup(pool.closeAll)

		const workers = 6
		start := make(chan struct{})
		errs := make(chan error, workers)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://coalesce-h2.example.com/probe", nil)
				if err != nil {
					errs <- err
					return
				}
				resp, err := pool.roundTrip(req)
				if err != nil {
					errs <- err
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				errs <- nil
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			require.NoError(t, err)
		}
		require.Equal(t, int32(1), dialer.tcpDials.Load())
	})

	t.Run("leader_cancel_does_not_poison_waiter", func(t *testing.T) {
		t.Parallel()

		srvTLS, cliTLS, _ := newTLSPair(t, "coalesce-cancel.example.com", []string{"h2"})
		addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
		dialer := &delayedCoalesceDialer{delay: 80 * time.Millisecond}
		pool := newXmuxHTTPPool(dialer, addr, cliTLS, true, 0, 0, mux.XmuxOptions{}, nil)
		t.Cleanup(pool.closeAll)

		ctxLeader, cancelLeader := context.WithCancel(context.Background())
		reqLeader, err := http.NewRequestWithContext(ctxLeader, http.MethodGet, "https://coalesce-cancel.example.com/1", nil)
		require.NoError(t, err)
		reqWaiter, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://coalesce-cancel.example.com/2", nil)
		require.NoError(t, err)

		var leaderErr, waiterErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, leaderErr = pool.roundTrip(reqLeader)
		}()
		time.Sleep(15 * time.Millisecond)
		go func() {
			defer wg.Done()
			resp, err := pool.roundTrip(reqWaiter)
			waiterErr = err
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
		time.Sleep(15 * time.Millisecond)
		cancelLeader()
		wg.Wait()

		require.Error(t, leaderErr)
		require.True(t, dialer.firstCanceled.Load())
		require.NoError(t, waiterErr)
	})
}

func TestXHTTPAutoModeFallbackToPacketUpOnHalfDuplexBuffering(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "auto-fallback.example.com", []string{"h2"})
	srvOpts := option.V2RayXHTTPOptions{
		Path: "/auto",
	}
	srv, err := NewServer(context.Background(), logger.NOP(), srvOpts, srvTLS, streamingEchoHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	var streamOneAttempts atomic.Int32
	var packetUpRequests atomic.Int32
	addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate half-duplex commercial CDN buffering stream-one POST body until EOF.
		if r.Method == http.MethodPost && r.URL.Path == "/auto" {
			streamOneAttempts.Add(1)
			_, _ = io.ReadAll(r.Body)
			return
		}
		packetUpRequests.Add(1)
		srv.ServeHTTP(w, r)
	}))

	client, err := NewClient(context.Background(), &testDialer{}, addr, option.V2RayXHTTPOptions{
		Path: "/auto",
		Mode: "auto",
	}, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	client.streamOneAutoTimeout = 100 * time.Millisecond

	// 1) First dial runs stream-one and hits half-duplex buffering timeout -> triggers auto-fallback.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel1()
	conn1, err := client.DialContext(ctx1)
	require.NoError(t, err)
	_, err = conn1.Write([]byte("ping-stream-one"))
	require.NoError(t, err)
	tmp := make([]byte, 16)
	_, err = conn1.Read(tmp)
	require.Error(t, err)
	_ = conn1.Close()
	require.GreaterOrEqual(t, int(streamOneAttempts.Load()), 1)
	require.True(t, client.autoFallbackPacketUp.Load())

	// 2) Subsequent dial automatically uses packet-up over full-duplex H2/CDN without stalling.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	conn2, err := client.DialContext(ctx2)
	require.NoError(t, err)
	defer conn2.Close()
	payload := []byte("recovered-via-auto-packet-up")
	_, err = conn2.Write(payload)
	require.NoError(t, err)
	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn2, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	require.GreaterOrEqual(t, int(packetUpRequests.Load()), 2)
}

func TestXHTTPPacketUp413AdaptiveChunkHalving(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "limit413.example.com", []string{"h2"})
	opts := option.V2RayXHTTPOptions{
		Path:                 "/limit413",
		Mode:                 "packet-up",
		ScMaxEachPostBytes:   option.XmuxRange{From: 32768, To: 32768},
		ScMaxConcurrentPosts: option.XmuxRange{From: 1, To: 1},
	}
	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, halfCloseEchoHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	var post413Count atomic.Int32
	addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.ContentLength > 8192 {
			post413Count.Add(1)
			http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		srv.ServeHTTP(w, r)
	}))

	client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	payload := bytes.Repeat([]byte("A413_LIMIT_"), 2200) // ~24.2KB

	// Attempt 1 probes 24.2KB -> 413 (cap 12.1KB) -> 12.1KB -> 413 (cap 6.05KB) -> 4x 6.05KB 200 OK
	// and completes cleanly inside the very first connection.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()
	conn1, err := client.DialContext(ctx1)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn1, payload)
	require.Equal(t, int32(2), post413Count.Load())
	require.LessOrEqual(t, int(client.adaptiveMaxChunkBytes.Load()), 8192)

	// Attempt 2 reuses the learned chunk cap with zero additional 413 rejections.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	conn2, err := client.DialContext(ctx2)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn2, payload)
	require.Equal(t, int32(2), post413Count.Load())
}

func TestXHTTPResumableDownlinkDefaultRotationWithoutExplicitConfig(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "default-rot.example.com", []string{"h2"})
	opts := option.V2RayXHTTPOptions{
		Path: "/defrot",
		Mode: "packet-up",
		// Omit ScDownlinkServerSecs intentionally to verify built-in CDN idle safeguard default.
	}
	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, streamingEchoHandler())
	require.NoError(t, err)
	srv.defaultDownlinkRotate = 80 * time.Millisecond
	t.Cleanup(func() { _ = srv.Close() })

	var getCount atomic.Int32
	addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			getCount.Add(1)
		}
		srv.ServeHTTP(w, r)
	}))

	client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()

	for round := 0; round < 3; round++ {
		msg := []byte("default-rotate-round-" + strconv.Itoa(round) + "\n")
		_, err = conn.Write(msg)
		require.NoError(t, err)
		buf := make([]byte, len(msg))
		_, err = io.ReadFull(conn, buf)
		require.NoError(t, err)
		require.Equal(t, msg, buf)
		time.Sleep(110 * time.Millisecond)
	}
	require.GreaterOrEqual(t, int(getCount.Load()), 2)
}

func runNonBodyLimitCase(t *testing.T, placement string, limit int, statusCode int, exceedLimit func(*http.Request) bool) {
	t.Helper()

	srvTLS, cliTLS, _ := newTLSPair(t, placement+"-limit.example.com", []string{"h2"})
	opts := option.V2RayXHTTPOptions{
		Path:                "/nonbody",
		Mode:                "packet-up",
		UplinkDataPlacement: placement,
		UplinkChunkSize:     limit,
		XPaddingBytes:       option.XmuxRange{From: 0, To: 0},
	}
	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, halfCloseEchoHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	var rejected atomic.Int32
	addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && exceedLimit(r) {
			rejected.Add(1)
			http.Error(w, http.StatusText(statusCode), statusCode)
			return
		}
		srv.ServeHTTP(w, r)
	}))

	client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	payload := bytes.Repeat([]byte("NB414_431_"), 300) // 3000B

	// First connection probes non-body limit in place, shrinks below 1KB down to 512B floor, and recovers.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()
	conn1, err := client.DialContext(ctx1)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn1, payload)

	beforeAttempt2 := rejected.Load()
	require.GreaterOrEqual(t, int(beforeAttempt2), 2)
	learnedCap := int(client.adaptiveMaxChunkBytes.Load())
	require.GreaterOrEqual(t, learnedCap, minAdaptiveNonBodyChunkBytes)
	require.LessOrEqual(t, learnedCap, 1024)

	// Second connection reuses learned non-body chunk cap with zero new rejections.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	conn2, err := client.DialContext(ctx2)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn2, payload)
	require.Equal(t, beforeAttempt2, rejected.Load())
}

func TestXHTTPNonBody414And431AdaptiveChunkHalving(t *testing.T) {
	t.Parallel()

	t.Run("query_414", func(t *testing.T) {
		t.Parallel()
		runNonBodyLimitCase(t, placementQuery, 4096, http.StatusRequestURITooLong, func(r *http.Request) bool {
			return len(r.URL.RawQuery) > 1000
		})
	})

	t.Run("header_431", func(t *testing.T) {
		t.Parallel()
		runNonBodyLimitCase(t, placementHeader, 4096, http.StatusRequestHeaderFieldsTooLarge, func(r *http.Request) bool {
			total := 0
			for k, vals := range r.Header {
				for _, v := range vals {
					total += len(k) + len(v)
				}
			}
			return total > 1300
		})
	})
}

func startDownloadSplitServers(
	t *testing.T,
	path string,
	handler adapter.V2RayServerTransportHandler,
	upProxyFn func(srv *Server, w http.ResponseWriter, r *http.Request),
) (upAddr M.Socksaddr, dlPort uint16, upCliTLS tls.Config, dlOutTLS option.OutboundTLSOptions, dlGetHits *atomic.Int32) {
	t.Helper()

	upSrvTLS, upCliTLS, _ := newTLSPair(t, "split-up.example.com", []string{"h2"})
	dlSrvTLS, _, dlOutTLS := newTLSPair(t, "split-dl.example.com", []string{"h2"})

	srvOpts := option.V2RayXHTTPOptions{Path: path, Mode: "packet-up"}
	srv, err := NewServer(context.Background(), logger.NOP(), srvOpts, upSrvTLS, handler)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	dlHits := &atomic.Int32{}
	dlAddr := startTLSHTTP2Proxy(t, dlSrvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			dlHits.Add(1)
		}
		srv.ServeHTTP(w, r)
	}))
	upAddr = startTLSHTTP2Proxy(t, upSrvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upProxyFn(srv, w, r)
	}))
	return upAddr, dlAddr.Port, upCliTLS, dlOutTLS, dlHits
}

func TestXHTTPDownloadSplitAutoModeFallbackAndDefaultStreamUpRotation(t *testing.T) {
	t.Parallel()

	t.Run("rejection_504_fallback", func(t *testing.T) {
		t.Parallel()
		var rejectFirst atomic.Bool
		rejectFirst.Store(true)
		var packetPosts atomic.Int32

		upAddr, dlPort, upCliTLS, dlOutTLS, dlHits := startDownloadSplitServers(t, "/split-auto-504", halfCloseEchoHandler(), func(srv *Server, w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.ContentLength < 0 && rejectFirst.Swap(false) {
				http.Error(w, "Gateway Timeout", http.StatusGatewayTimeout)
				return
			}
			if r.Method == http.MethodPost && r.ContentLength >= 0 {
				packetPosts.Add(1)
			}
			srv.ServeHTTP(w, r)
		})

		client, err := NewClient(context.Background(), &testDialer{}, upAddr, option.V2RayXHTTPOptions{
			Path:            "/split-auto-504",
			Mode:            "auto",
			DownloadAddress: "127.0.0.1",
			DownloadPort:    dlPort,
			DownloadTLS:     &dlOutTLS,
		}, upCliTLS)
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		// Conn 1 hits CDN 504 on streaming POST and flips autoFallbackPacketUp.
		ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
		conn1, err := client.DialContext(ctx1)
		require.NoError(t, err)
		_, _ = conn1.Write([]byte("trigger-504-fallback"))
		_ = conn1.(N.WriteCloser).CloseWrite()
		_, _ = io.ReadAll(conn1)
		_ = conn1.Close()
		cancel1()

		require.Eventually(t, func() bool {
			return client.autoFallbackPacketUp.Load()
		}, 2*time.Second, 10*time.Millisecond)

		// Conn 2 automatically runs packet-up uplink while preserving download_settings split downlink.
		dlHitsBeforeConn2 := dlHits.Load()
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		conn2, err := client.DialContext(ctx2)
		require.NoError(t, err)
		payload := []byte("split-auto-504-recovered")
		assertHalfCloseEcho(t, conn2, payload)
		require.GreaterOrEqual(t, int(packetPosts.Load()), 1)
		require.Greater(t, dlHits.Load(), dlHitsBeforeConn2)
	})

	t.Run("silent_buffering_stall_fallback", func(t *testing.T) {
		t.Parallel()
		var holdFirst atomic.Bool
		holdFirst.Store(true)
		var packetPosts atomic.Int32

		upAddr, dlPort, upCliTLS, dlOutTLS, dlHits := startDownloadSplitServers(t, "/split-auto-stall", halfCloseEchoHandler(), func(srv *Server, w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.ContentLength < 0 && holdFirst.Swap(false) {
				// Simulate a commercial CDN silently buffering the streaming POST until client closes.
				<-r.Context().Done()
				return
			}
			if r.Method == http.MethodPost && r.ContentLength >= 0 {
				packetPosts.Add(1)
			}
			srv.ServeHTTP(w, r)
		})

		client, err := NewClient(context.Background(), &testDialer{}, upAddr, option.V2RayXHTTPOptions{
			Path:            "/split-auto-stall",
			Mode:            "auto",
			DownloadAddress: "127.0.0.1",
			DownloadPort:    dlPort,
			DownloadTLS:     &dlOutTLS,
		}, upCliTLS)
		require.NoError(t, err)
		client.streamOneAutoTimeout = 80 * time.Millisecond
		t.Cleanup(func() { _ = client.Close() })

		ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
		conn1, err := client.DialContext(ctx1)
		require.NoError(t, err)
		_, err = conn1.Write([]byte("silently-buffered-uplink"))
		require.NoError(t, err)
		time.Sleep(110 * time.Millisecond)
		_ = conn1.Close()
		cancel1()

		require.True(t, client.autoFallbackPacketUp.Load())

		dlHitsBeforeConn2 := dlHits.Load()
		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		conn2, err := client.DialContext(ctx2)
		require.NoError(t, err)
		assertHalfCloseEcho(t, conn2, []byte("split-auto-stall-recovered"))
		require.GreaterOrEqual(t, int(packetPosts.Load()), 1)
		require.Greater(t, dlHits.Load(), dlHitsBeforeConn2)
	})

	t.Run("default_stream_up_rotation_without_config", func(t *testing.T) {
		t.Parallel()
		srvTLS, cliTLS, _ := newTLSPair(t, "streamup-rot.example.com", []string{"h2"})
		opts := option.V2RayXHTTPOptions{
			Path: "/streamup-rot",
			Mode: "stream-up",
			// Omit ScStreamUpServerSecs intentionally to verify built-in 50s default safeguard.
		}
		srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, streamingEchoHandler())
		require.NoError(t, err)
		t.Cleanup(func() { _ = srv.Close() })

		var postCount atomic.Int32
		addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				postCount.Add(1)
			}
			srv.ServeHTTP(w, r)
		}))

		client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
		require.NoError(t, err)
		client.streamUpAutoRotate = 80 * time.Millisecond
		t.Cleanup(func() { _ = client.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx)
		require.NoError(t, err)
		defer conn.Close()

		for round := 0; round < 3; round++ {
			msg := []byte("streamup-rot-round-" + strconv.Itoa(round) + "\n")
			_, err = conn.Write(msg)
			require.NoError(t, err)
			buf := make([]byte, len(msg))
			_, err = io.ReadFull(conn, buf)
			require.NoError(t, err)
			require.Equal(t, msg, buf)
			time.Sleep(110 * time.Millisecond)
		}
		require.GreaterOrEqual(t, int(postCount.Load()), 2)
	})
}

func TestXHTTPStreamOnePostHeaderBufferingAndReversibleAutoFallback(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "streamone-auto.example.com", []string{"h2"})
	opts := option.V2RayXHTTPOptions{
		Path: "/auto-streamone",
		Mode: "auto",
	}
	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, streamingEchoHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	var bufferStreamOne atomic.Bool
	bufferStreamOne.Store(true)
	var streamOnePosts atomic.Int32
	var packetUpPosts atomic.Int32

	addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if r.URL.Path == opts.Path {
				streamOnePosts.Add(1)
				if bufferStreamOne.Load() {
					// Send 200 OK headers right away, then buffer request body without echoing.
					w.WriteHeader(http.StatusOK)
					if f, ok := w.(http.Flusher); ok {
						f.Flush()
					}
					_, _ = io.ReadAll(r.Body)
					return
				}
			} else {
				packetUpPosts.Add(1)
			}
		}
		srv.ServeHTTP(w, r)
	}))

	client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
	require.NoError(t, err)
	client.streamOneAutoTimeout = 80 * time.Millisecond
	client.autoFallbackCooldown = 140 * time.Millisecond
	t.Cleanup(func() { _ = client.Close() })

	// Phase 1: stream-one receives 200 headers immediately, then upstream upload stalls.
	// Auto watchdog aborts stalled stream-one and flips auto mode to packet-up.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel1()
	conn1, err := client.DialContext(ctx1)
	require.NoError(t, err)
	_, err = conn1.Write([]byte("probe-post-header-buffer"))
	require.NoError(t, err)
	buf := make([]byte, 32)
	_, err = conn1.Read(buf)
	require.Error(t, err)
	_ = conn1.Close()
	require.True(t, client.autoFallbackPacketUp.Load())
	require.Equal(t, int32(1), streamOnePosts.Load())

	// Phase 2: during cooldown, auto mode stays on packet-up and succeeds even if stream-one is still buffered.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	conn2, err := client.DialContext(ctx2)
	require.NoError(t, err)
	msg2 := []byte("fallback-packet-up-ok\n")
	_, err = conn2.Write(msg2)
	require.NoError(t, err)
	got2 := make([]byte, len(msg2))
	_, err = io.ReadFull(conn2, got2)
	require.NoError(t, err)
	require.Equal(t, msg2, got2)
	_ = conn2.Close()
	require.GreaterOrEqual(t, int(packetUpPosts.Load()), 1)

	// Phase 3: restore full-duplex proxy and let cooldown elapse -> client probes stream-one and resets fallback.
	bufferStreamOne.Store(false)
	time.Sleep(180 * time.Millisecond)

	ctx3, cancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel3()
	conn3, err := client.DialContext(ctx3)
	require.NoError(t, err)
	msg3 := []byte("recovered-stream-one\n")
	_, err = conn3.Write(msg3)
	require.NoError(t, err)
	got3 := make([]byte, len(msg3))
	_, err = io.ReadFull(conn3, got3)
	require.NoError(t, err)
	require.Equal(t, msg3, got3)
	_ = conn3.Close()

	require.False(t, client.autoFallbackPacketUp.Load())
	require.Equal(t, int32(2), streamOnePosts.Load())

	// Subsequent connection continues using stream-one directly without extra packet-up fallback.
	ctx4, cancel4 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel4()
	conn4, err := client.DialContext(ctx4)
	require.NoError(t, err)
	msg4 := []byte("steady-stream-one\n")
	_, err = conn4.Write(msg4)
	require.NoError(t, err)
	got4 := make([]byte, len(msg4))
	_, err = io.ReadFull(conn4, got4)
	require.NoError(t, err)
	require.Equal(t, msg4, got4)
	_ = conn4.Close()
	require.Equal(t, int32(3), streamOnePosts.Load())
}

func TestXHTTPPacketUpSmallHandshakeThenLarge413And429RetryAfterPacing(t *testing.T) {
	t.Parallel()

	t.Run("SmallHandshakePreservesLarge413Probe", func(t *testing.T) {
		t.Parallel()
		srvTLS, cliTLS, _ := newTLSPair(t, "pkt413.example.com", []string{"h2"})
		opts := option.V2RayXHTTPOptions{
			Path:                 "/pkt-413-cold",
			Mode:                 "packet-up",
			ScMaxConcurrentPosts: option.XmuxRange{From: 4, To: 4},
		}
		srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, streamingEchoHandler())
		require.NoError(t, err)
		t.Cleanup(func() { _ = srv.Close() })

		const maxAllowedBody = 8192
		var saw413 atomic.Bool
		addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				body, readErr := io.ReadAll(r.Body)
				if readErr != nil {
					http.Error(w, readErr.Error(), http.StatusBadRequest)
					return
				}
				if len(body) > maxAllowedBody {
					saw413.Store(true)
					http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
			srv.ServeHTTP(w, r)
		}))

		client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx)
		require.NoError(t, err)
		defer conn.Close()

		// 256B small handshake (<= 4KB minAdaptiveChunkBytes floor) must succeed without advancing confirmed chunk size.
		handshake := bytes.Repeat([]byte("H"), 256)
		_, err = conn.Write(handshake)
		require.NoError(t, err)
		hsBuf := make([]byte, len(handshake))
		_, err = io.ReadFull(conn, hsBuf)
		require.NoError(t, err)
		require.Equal(t, handshake, hsBuf)
		require.Zero(t, client.confirmedMaxChunkBytes.Load())

		// 6KB medium write (> 4KB floor and <= 8KB proxy cap) proves 6KB without disabling in-place probing for later larger uploads.
		medium := bytes.Repeat([]byte("MEDIUM_OK_CHUNK_"), 384) // 6144 bytes
		_, err = conn.Write(medium)
		require.NoError(t, err)
		medBuf := make([]byte, len(medium))
		_, err = io.ReadFull(conn, medBuf)
		require.NoError(t, err)
		require.Equal(t, medium, medBuf)
		require.Eventually(t, func() bool {
			return client.confirmedMaxChunkBytes.Load() == int64(len(medium))
		}, 2*time.Second, 5*time.Millisecond)

		// Subsequent 32KB write (> confirmed 6KB and > 8KB proxy limit) triggers serialized 413 halving without dropping conn.
		large := bytes.Repeat([]byte("LARGE_413_PROBE_"), 2048) // 32768 bytes
		_, err = conn.Write(large)
		require.NoError(t, err)
		largeBuf := make([]byte, len(large))
		_, err = io.ReadFull(conn, largeBuf)
		require.NoError(t, err)
		require.Equal(t, large, largeBuf)

		require.True(t, saw413.Load())
		require.LessOrEqual(t, int(client.adaptiveMaxChunkBytes.Load()), maxAllowedBody)
		require.LessOrEqual(t, int(client.confirmedMaxChunkBytes.Load()), maxAllowedBody)
	})

	t.Run("HTTP429RetryAfterAndAdaptivePacing", func(t *testing.T) {
		t.Parallel()
		srvTLS, cliTLS, _ := newTLSPair(t, "pkt429.example.com", []string{"h2"})
		opts := option.V2RayXHTTPOptions{
			Path:                 "/pkt-429",
			Mode:                 "packet-up",
			ScMaxConcurrentPosts: option.XmuxRange{From: 2, To: 2},
		}
		srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, halfCloseEchoHandler())
		require.NoError(t, err)
		t.Cleanup(func() { _ = srv.Close() })

		var postCount atomic.Int32
		addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && postCount.Add(1) == 1 {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			srv.ServeHTTP(w, r)
		}))

		client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx)
		require.NoError(t, err)

		start := time.Now()
		assertHalfCloseEcho(t, conn, []byte("after-429-retry-after"))
		elapsed := time.Since(start)

		require.GreaterOrEqual(t, int(postCount.Load()), 2)
		require.GreaterOrEqual(t, elapsed, 800*time.Millisecond)
		require.Greater(t, client.adaptivePostIntervalNs.Load(), int64(0))

		now := time.Unix(1_700_000_000, 0).UTC()
		d, ok := parseRetryAfter("2", now)
		require.True(t, ok)
		require.Equal(t, 2*time.Second, d)
		d, ok = parseRetryAfter("0", now)
		require.True(t, ok)
		require.Equal(t, minAdaptivePostInterval, d)
		d, ok = parseRetryAfter(now.Add(3*time.Second).Format(http.TimeFormat), now)
		require.True(t, ok)
		require.Equal(t, 3*time.Second, d)
		d, ok = parseRetryAfter("not-a-valid-header", now)
		require.False(t, ok)
		require.Equal(t, time.Duration(0), d)
	})
}

func TestXHTTPServerChunkedUplinkStaleSeqAndContextCancel(t *testing.T) {
	t.Parallel()

	srv, err := NewServer(context.Background(), logger.NOP(), option.V2RayXHTTPOptions{
		Path: "/chunked-uplink",
	}, nil, halfCloseEchoHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	const sessionID = "stale-seq-session"
	dlCtx, dlCancel := context.WithCancel(context.Background())
	defer dlCancel()
	dlReq, err := http.NewRequestWithContext(dlCtx, http.MethodGet, "http://example.com/chunked-uplink/"+sessionID, nil)
	require.NoError(t, err)
	dlReq.Header.Set(headerDownlinkSeq, "0")
	dlReq.Header.Set(headerDownlinkOffset, "0")
	dlRec := httptest.NewRecorder()
	dlDone := make(chan struct{})
	go func() {
		defer close(dlDone)
		srv.ServeHTTP(dlRec, dlReq)
	}()

	// Initial ContentLength == -1 upload at seq=0 advances nextSeq to 1.
	req0, err := http.NewRequest(http.MethodPost, "http://example.com/chunked-uplink/"+sessionID+"/0", bytes.NewReader([]byte("chunk-0")))
	require.NoError(t, err)
	req0.ContentLength = -1
	rec0 := httptest.NewRecorder()
	srv.ServeHTTP(rec0, req0)
	require.Equal(t, http.StatusOK, rec0.Code)

	// Retried/duplicate chunked seq=0 (ContentLength == -1) must complete immediately without deadlocking.
	retryReq0, err := http.NewRequest(http.MethodPost, "http://example.com/chunked-uplink/"+sessionID+"/0", bytes.NewReader([]byte("chunk-0")))
	require.NoError(t, err)
	retryReq0.ContentLength = -1
	retryRec0 := httptest.NewRecorder()
	retryDone := make(chan struct{})
	go func() {
		defer close(retryDone)
		srv.ServeHTTP(retryRec0, retryReq0)
	}()
	select {
	case <-retryDone:
	case <-time.After(2 * time.Second):
		t.Fatal("stale chunked seq=0 deadlocked streamUplink")
	}
	require.Equal(t, http.StatusOK, retryRec0.Code)

	// Out-of-order chunked seq=2 waits on nextSeq, and cancels cleanly when request context is canceled.
	waitCtx, waitCancel := context.WithCancel(context.Background())
	req2, err := http.NewRequestWithContext(waitCtx, http.MethodPost, "http://example.com/chunked-uplink/"+sessionID+"/2", bytes.NewReader([]byte("chunk-2")))
	require.NoError(t, err)
	req2.ContentLength = -1
	rec2 := httptest.NewRecorder()
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		srv.ServeHTTP(rec2, req2)
	}()
	time.Sleep(30 * time.Millisecond)
	waitCancel()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled out-of-order streamUplink did not unblock")
	}
	require.Equal(t, http.StatusBadRequest, rec2.Code)

	dlCancel()
	<-dlDone
}

type noQUICTLSClient struct {
	tls.Config
}

func (c noQUICTLSClient) Clone() tls.Config {
	return noQUICTLSClient{c.Config.Clone()}
}

func (noQUICTLSClient) SupportsQUIC() bool {
	return false
}

type noQUICTLSServer struct {
	tls.ServerConfig
}

func (s noQUICTLSServer) Clone() tls.Config {
	return noQUICTLSServer{s.ServerConfig.Clone().(tls.ServerConfig)}
}

func (noQUICTLSServer) SupportsQUIC() bool {
	return false
}

func TestXHTTPServerDownlinkRotateSurvivesOrphanReap(t *testing.T) {
	t.Parallel()

	srv, err := NewServer(context.Background(), logger.NOP(), option.V2RayXHTTPOptions{
		Path: "/rotate-reap",
	}, nil, halfCloseEchoHandler())
	require.NoError(t, err)
	srv.defaultDownlinkRotate = 40 * time.Millisecond
	t.Cleanup(func() { _ = srv.Close() })

	// Seed session with idle resumed GET downlink that ages past serverOrphanTimeout before rotation.
	const rotatedID = "rotated-idle-session"
	rotReq, err := http.NewRequest(http.MethodGet, "http://example.com/rotate-reap/"+rotatedID, nil)
	require.NoError(t, err)
	rotReq.Header.Set(headerDownlinkSeq, "0")
	rotReq.Header.Set(headerDownlinkOffset, "0")
	rotRec := httptest.NewRecorder()
	rotDone := make(chan struct{})
	go func() {
		defer close(rotDone)
		srv.ServeHTTP(rotRec, rotReq)
	}()

	var rotatedSess *serverSession
	require.Eventually(t, func() bool {
		srv.sessMu.Lock()
		rotatedSess = srv.sessions[rotatedID]
		srv.sessMu.Unlock()
		return rotatedSess != nil && rotatedSess.isDownlinkAttached()
	}, 2*time.Second, 5*time.Millisecond)

	rotatedSess.lastActive.Store(time.Now().Add(-serverOrphanTimeout - 5*time.Second).UnixNano())
	select {
	case <-rotDone:
	case <-time.After(2 * time.Second):
		t.Fatal("downlink rotation did not detach in time")
	}

	// Clean server rotation refreshes lastActive, so orphan reaper must preserve session across reconnect RTT.
	srv.reapOnce(time.Now())
	srv.sessMu.Lock()
	kept := srv.sessions[rotatedID]
	srv.sessMu.Unlock()
	require.Same(t, rotatedSess, kept)
	require.NoError(t, rotatedSess.ctx.Err())

	// By contrast, an abrupt client disconnect does not extend orphan grace once stale.
	const abortedID = "aborted-idle-session"
	abortCtx, abortCancel := context.WithCancel(context.Background())
	abortReq, err := http.NewRequestWithContext(abortCtx, http.MethodGet, "http://example.com/rotate-reap/"+abortedID, nil)
	require.NoError(t, err)
	abortReq.Header.Set(headerDownlinkSeq, "0")
	abortReq.Header.Set(headerDownlinkOffset, "0")
	abortRec := httptest.NewRecorder()
	abortDone := make(chan struct{})
	go func() {
		defer close(abortDone)
		srv.ServeHTTP(abortRec, abortReq)
	}()

	var abortedSess *serverSession
	require.Eventually(t, func() bool {
		srv.sessMu.Lock()
		abortedSess = srv.sessions[abortedID]
		srv.sessMu.Unlock()
		return abortedSess != nil && abortedSess.isDownlinkAttached()
	}, 2*time.Second, 5*time.Millisecond)

	abortedSess.lastActive.Store(time.Now().Add(-serverOrphanTimeout - 5*time.Second).UnixNano())
	abortCancel()
	select {
	case <-abortDone:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled downlink did not exit in time")
	}

	srv.reapOnce(time.Now())
	require.Error(t, abortedSess.ctx.Err())
	srv.reapOnce(time.Now().Add(resumablePostCloseLinger + time.Second))
	srv.sessMu.Lock()
	_, stillPresent := srv.sessions[abortedID]
	srv.sessMu.Unlock()
	require.False(t, stillPresent)
}

func TestXHTTPAutoFallbackTriggersAfterCallerDialContextCanceled(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "auto-ctx.example.com", []string{"h2"})
	opts := option.V2RayXHTTPOptions{
		Path:          "/auto-ctx",
		XPaddingBytes: option.XmuxRange{From: 0, To: 0},
	}
	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, halfCloseEchoHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	// Simulate commercial CDN buffering stream-one POST bodies indefinitely while packet-up passes.
	addr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (r.URL.Path == "/auto-ctx" || r.URL.Path == "/auto-ctx/") {
			<-r.Context().Done()
			return
		}
		srv.ServeHTTP(w, r)
	}))

	client, err := NewClient(context.Background(), &testDialer{}, addr, opts, cliTLS)
	require.NoError(t, err)
	client.streamOneAutoTimeout = 80 * time.Millisecond
	t.Cleanup(func() { _ = client.Close() })

	// Caller cancels dial context right after DialContext returns (standard defer cancel pattern).
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn1, err := client.DialContext(dialCtx)
	require.NoError(t, err)
	dialCancel()

	_, _ = conn1.Write([]byte("buffered-stream-one-probe"))
	buf := make([]byte, 32)
	_, readErr := conn1.Read(buf)
	require.Error(t, readErr)
	_ = conn1.Close()

	require.Eventually(t, func() bool {
		return client.autoFallbackPacketUp.Load()
	}, 2*time.Second, 5*time.Millisecond)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	conn2, err := client.DialContext(ctx2)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn2, []byte("recovered-via-packet-up"))
}

func TestXHTTPNonQUICTLSDisablesHTTP3AndRejectsH3OnlyConfig(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "nonquic.example.com", nil)

	// Pure H3-only configuration with non-QUIC TLS must fail fast on both client and server.
	h3OnlyCliTLS := cliTLS.Clone()
	h3OnlyCliTLS.SetNextProtos([]string{h3NextProto})
	_, err := NewClient(context.Background(), &testDialer{}, M.ParseSocksaddrHostPort("127.0.0.1", 443), option.V2RayXHTTPOptions{
		Path: "/noquic",
	}, noQUICTLSClient{h3OnlyCliTLS})
	require.Error(t, err)

	h3OnlySrvTLS := srvTLS.Clone().(tls.ServerConfig)
	h3OnlySrvTLS.SetNextProtos([]string{h3NextProto})
	_, err = NewServer(context.Background(), logger.NOP(), option.V2RayXHTTPOptions{
		Path: "/noquic",
	}, noQUICTLSServer{h3OnlySrvTLS}, halfCloseEchoHandler())
	require.Error(t, err)

	// Hybrid H3+H2 or QUIC options with non-QUIC TLS stay TCP-only and disable Alt-Svc upgrades.
	hybridSrvTLS := srvTLS.Clone().(tls.ServerConfig)
	hybridSrvTLS.SetNextProtos([]string{h3NextProto, http2.NextProtoTLS})
	srv, err := NewServer(context.Background(), logger.NOP(), option.V2RayXHTTPOptions{
		Path: "/noquic",
		QUIC: &option.QUICOptions{},
	}, noQUICTLSServer{hybridSrvTLS}, halfCloseEchoHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	require.Equal(t, []string{N.NetworkTCP}, srv.Network())

	hybridCliTLS := cliTLS.Clone()
	client, err := NewClient(context.Background(), &testDialer{}, M.ParseSocksaddrHostPort("127.0.0.1", 443), option.V2RayXHTTPOptions{
		Path: "/noquic",
		QUIC: &option.QUICOptions{},
	}, noQUICTLSClient{hybridCliTLS})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.False(t, client.uplinkPool.enableH3)
	require.False(t, client.uplinkPool.allowAltSvcH3)
	require.Equal(t, []string{http2.NextProtoTLS, "http/1.1"}, hybridCliTLS.NextProtos())
}

type syncSignalReader struct {
	r       io.Reader
	started chan struct{}
	once    sync.Once
}

func (s *syncSignalReader) Read(p []byte) (int, error) {
	s.once.Do(func() { close(s.started) })
	return s.r.Read(p)
}

func TestXHTTPServerStreamUplinkDrainsPendingOutOfOrderChunks(t *testing.T) {
	t.Parallel()

	srv, err := NewServer(context.Background(), logger.NOP(), option.V2RayXHTTPOptions{
		Path: "/mixed-uplink",
		Mode: "packet-up",
	}, nil, halfCloseEchoHandler())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	const sessionID = "mixed-sess"
	dlReq, err := http.NewRequest(http.MethodGet, ts.URL+"/mixed-uplink/"+sessionID, nil)
	require.NoError(t, err)
	dlReq.Header.Set(headerDownlinkSeq, "0")
	dlReq.Header.Set(headerDownlinkOffset, "0")
	dlResp, err := ts.Client().Do(dlReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, dlResp.StatusCode)
	t.Cleanup(func() { _ = dlResp.Body.Close() })

	type dlResult struct {
		body []byte
		err  error
	}
	dlCh := make(chan dlResult, 1)
	go func() {
		body, readErr := io.ReadAll(dlResp.Body)
		dlCh <- dlResult{body: body, err: readErr}
	}()

	// 1) Start seq=0 as a chunked (ContentLength == -1) streaming uplink via io.Pipe.
	pr0, pw0 := io.Pipe()
	sr0 := &syncSignalReader{r: pr0, started: make(chan struct{})}
	up0Req, err := http.NewRequest(http.MethodPost, ts.URL+"/mixed-uplink/"+sessionID+"/0", sr0)
	require.NoError(t, err)
	up0Req.ContentLength = -1
	up0ErrCh := make(chan error, 1)
	go func() {
		resp, postErr := ts.Client().Do(up0Req)
		if postErr != nil {
			up0ErrCh <- postErr
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			up0ErrCh <- errors.New(resp.Status)
			return
		}
		up0ErrCh <- nil
	}()

	_, err = pw0.Write([]byte("chunk0-"))
	require.NoError(t, err)
	select {
	case <-sr0.started:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for chunked seq=0 read")
	}
	require.Eventually(t, func() bool {
		srv.sessMu.Lock()
		sess := srv.sessions[sessionID]
		srv.sessMu.Unlock()
		if sess == nil {
			return false
		}
		sess.seqMu.Lock()
		draining := sess.uplinkDraining
		sess.seqMu.Unlock()
		return draining
	}, 2*time.Second, 5*time.Millisecond)

	// 2) While seq=0 is streaming, deliver seq=1 with explicit Content-Length (pushChunk) and X-Stream-End.
	up1Req, err := http.NewRequest(http.MethodPost, ts.URL+"/mixed-uplink/"+sessionID+"/1", bytes.NewReader([]byte("chunk1-end")))
	require.NoError(t, err)
	up1Req.Header.Set("X-Stream-End", "1")
	up1Resp, err := ts.Client().Do(up1Req)
	require.NoError(t, err)
	_, _ = io.Copy(io.Discard, up1Resp.Body)
	_ = up1Resp.Body.Close()
	require.Equal(t, http.StatusOK, up1Resp.StatusCode)

	// 3) Finish seq=0; streamUplink must immediately drain pending seq=1 and close uplinkWriter cleanly.
	require.NoError(t, pw0.Close())
	select {
	case postErr := <-up0ErrCh:
		require.NoError(t, postErr)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for seq=0 response")
	}

	select {
	case res := <-dlCh:
		require.NoError(t, res.err)
		require.Equal(t, []byte("echo:chunk0-chunk1-end"), res.body)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for downlink EOF after mixed streamUplink/pushChunk")
	}
}
