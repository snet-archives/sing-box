//go:build with_quic

package v2rayxhttp

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-mux"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type h3TestDialer struct {
	udpDials atomic.Int32
	tcpDials atomic.Int32
	blockUDP bool
}

func (d *h3TestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		d.udpDials.Add(1)
		if d.blockUDP {
			return nil, errors.New("simulated blocked udp")
		}
	} else {
		d.tcpDials.Add(1)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, destination.String())
}

func (d *h3TestDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func startXHTTPUDPServer(t *testing.T, opts option.V2RayXHTTPOptions, srvTLS tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, M.Socksaddr) {
	t.Helper()
	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, handler)
	require.NoError(t, err)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = srv.Close()
		_ = pc.Close()
	})
	go func() {
		_ = srv.ServePacket(pc)
	}()
	udpAddr := pc.LocalAddr().(*net.UDPAddr)
	return srv, M.SocksaddrFrom(M.AddrFromIP(udpAddr.IP), uint16(udpAddr.Port))
}

func startXHTTPDualServer(t *testing.T, opts option.V2RayXHTTPOptions, srvTLS tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, M.Socksaddr) {
	return startXHTTPDualServerWithHTTPWrapper(t, opts, srvTLS, handler, nil)
}

func startXHTTPDualServerWithHTTPWrapper(t *testing.T, opts option.V2RayXHTTPOptions, srvTLS tls.ServerConfig, handler adapter.V2RayServerTransportHandler, wrap func(*Server, http.Handler) http.Handler) (*Server, M.Socksaddr) {
	t.Helper()
	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, handler)
	require.NoError(t, err)
	if wrap != nil {
		srv.httpServer.Handler = wrap(srv, srv.httpServer.Handler)
	}

	var (
		tcpLn net.Listener
		udpPC net.PacketConn
		port  int
	)
	for i := 0; i < 8; i++ {
		tcpLn, err = net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		port = tcpLn.Addr().(*net.TCPAddr).Port
		udpPC, err = net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", tcpLn.Addr().(*net.TCPAddr).String()[len("127.0.0.1:"):]))
		if err == nil {
			break
		}
		_ = tcpLn.Close()
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = srv.Close()
		_ = tcpLn.Close()
		_ = udpPC.Close()
	})
	go func() { _ = srv.Serve(tcpLn) }()
	go func() { _ = srv.ServePacket(udpPC) }()
	return srv, M.SocksaddrFrom(M.AddrFromIP(net.ParseIP("127.0.0.1")), uint16(port))
}

func TestXHTTPHTTP3PureModes(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"stream-one", "stream-up", "packet-up"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			srvTLS, cliTLS, _ := newTLSPair(t, "h3.example.com", []string{"h3"})
			opts := option.V2RayXHTTPOptions{
				Path:                 "/h3-" + mode,
				Mode:                 mode,
				ScMaxEachPostBytes:   option.XmuxRange{From: 2048, To: 2048},
				ScMaxConcurrentPosts: option.XmuxRange{From: 4, To: 4},
			}
			handler := halfCloseEchoHandler()
			if mode == "stream-one" {
				handler = streamingEchoHandler()
			}
			srv, addr := startXHTTPUDPServer(t, opts, srvTLS, handler)
			require.Equal(t, []string{N.NetworkUDP}, srv.Network())

			dialer := &h3TestDialer{}
			client, err := NewClient(context.Background(), dialer, addr, opts, cliTLS)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx)
			require.NoError(t, err)
			defer conn.Close()

			payload := bytes.Repeat([]byte("HTTP3_QUIC_XHTTP_"), 1500) // ~25.5 KB
			if mode == "stream-one" {
				_, err = conn.Write(payload)
				require.NoError(t, err)
				got := make([]byte, len(payload))
				_, err = io.ReadFull(conn, got)
				require.NoError(t, err)
				require.Equal(t, payload, got)
			} else {
				assertHalfCloseEcho(t, conn, payload)
			}

			require.GreaterOrEqual(t, int(dialer.udpDials.Load()), 1)
			require.Zero(t, dialer.tcpDials.Load())
		})
	}
}

func TestXHTTPHTTP3FallbackToH2WhenUDPBlocked(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "h3-fallback.example.com", []string{"h3", "h2"})
	opts := option.V2RayXHTTPOptions{
		Path: "/fallback",
		Mode: "packet-up",
	}
	srv, addr := startXHTTPServer(t, opts, srvTLS, halfCloseEchoHandler())
	require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP}, srv.Network())

	dialer := &h3TestDialer{blockUDP: true}
	client, err := NewClient(context.Background(), dialer, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	var udpDialsAfterFirst int32
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := client.DialContext(ctx)
		require.NoError(t, err)
		assertHalfCloseEcho(t, conn, bytes.Repeat([]byte("H2_FALLBACK_"), 200))
		cancel()
		if i == 0 {
			udpDialsAfterFirst = dialer.udpDials.Load()
			require.GreaterOrEqual(t, int(udpDialsAfterFirst), 1)
			require.LessOrEqual(t, int(udpDialsAfterFirst), 2)
		}
	}

	// Second session must skip UDP while H3 fallback cooldown is active.
	require.Equal(t, udpDialsAfterFirst, dialer.udpDials.Load())
	require.GreaterOrEqual(t, int(dialer.tcpDials.Load()), 1)
}

func TestXHTTPHTTP3PureNoFallbackFailsWhenUDPBlocked(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "h3-strict.example.com", []string{"h3"})
	opts := option.V2RayXHTTPOptions{
		Path: "/strict",
		Mode: "packet-up",
	}
	_, addr := startXHTTPUDPServer(t, opts, srvTLS, halfCloseEchoHandler())

	dialer := &h3TestDialer{blockUDP: true}
	client, err := NewClient(context.Background(), dialer, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	if err == nil {
		defer conn.Close()
		_, err = conn.Write([]byte("must-fail"))
		if err == nil {
			buf := make([]byte, 32)
			_, err = conn.Read(buf)
		}
	}
	require.Error(t, err)
	require.Zero(t, dialer.tcpDials.Load())
}

func TestXHTTPHTTP3SplitChannelAndAltSvc(t *testing.T) {
	t.Parallel()

	upSrvTLS, upCliTLS, _ := newTLSPair(t, "up.example.com", []string{"h3", "h2"})
	dlSrvTLS, _, dlOutTLS := newTLSPair(t, "dl.example.com", []string{"h3"})

	upOpts := option.V2RayXHTTPOptions{
		Path: "/split-h3",
		Mode: "stream-up",
	}
	upSrv, upAddr := startXHTTPDualServer(t, upOpts, upSrvTLS, halfCloseEchoHandler())
	require.Equal(t, []string{N.NetworkTCP, N.NetworkUDP}, upSrv.Network())

	// Dedicated HTTP/3 downlink server sharing session table with upSrv via ServeHTTP.
	dlOpts := option.V2RayXHTTPOptions{Path: "/split-h3"}
	dlHandler := testServerHandler{fn: func(context.Context, net.Conn, adapter.InboundContext, N.CloseHandlerFunc) {}}
	dlSrv, err := NewServer(context.Background(), logger.NOP(), dlOpts, dlSrvTLS, dlHandler)
	require.NoError(t, err)
	dlSrv.httpServer.Handler = upSrv
	dlPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = dlSrv.Close()
		_ = dlPC.Close()
	})
	go func() {
		_ = dlSrv.ServePacket(dlPC)
	}()
	dlPort := dlPC.LocalAddr().(*net.UDPAddr).Port

	// Wait briefly until dual server recorded H3 port for Alt-Svc advertisement.
	require.Eventually(t, func() bool {
		return upSrv.h3Port.Load() > 0
	}, 2*time.Second, 10*time.Millisecond)

	cliOpts := option.V2RayXHTTPOptions{
		Path:            "/split-h3",
		Mode:            "stream-up",
		DownloadAddress: "127.0.0.1",
		DownloadPort:    uint16(dlPort),
		DownloadTLS:     &dlOutTLS,
	}
	// Verify TCP H2 GET carries Alt-Svc advertising UDP HTTP/3 port.
	probeDialer := &h3TestDialer{blockUDP: true}
	probeCli, err := NewClient(context.Background(), probeDialer, upAddr, upOpts, upCliTLS)
	require.NoError(t, err)
	probeReq, err := http.NewRequest(http.MethodPost, "https://"+upAddr.String()+"/split-h3", http.NoBody)
	require.NoError(t, err)
	probeResp, err := probeCli.uplinkPool.roundTrip(probeReq)
	require.NoError(t, err)
	altSvc := probeResp.Header.Get("Alt-Svc")
	_ = probeResp.Body.Close()
	_ = probeCli.Close()
	require.Contains(t, altSvc, "h3=\":")

	// Verify actual split data plane: TCP H2 uplink -> H3 UDP downlink.
	splitDialer := &h3TestDialer{}
	splitCli, err := NewClient(context.Background(), splitDialer, upAddr, cliOpts, upCliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = splitCli.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := splitCli.DialContext(ctx)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn, bytes.Repeat([]byte("SPLIT_H2_UP_H3_DOWN_"), 500))
	require.GreaterOrEqual(t, int(splitDialer.udpDials.Load()), 1)
}

func TestXHTTPQUICOptionsApplied(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "quic-opt.example.com", []string{"h3"})
	opts := option.V2RayXHTTPOptions{
		Path: "/qopt",
		Mode: "packet-up",
		QUIC: &option.QUICOptions{
			HTTP2Options: option.HTTP2Options{
				MaxConcurrentStreams: 32,
			},
			InitialPacketSize:       1350,
			DisablePathMTUDiscovery: true,
		},
	}
	_, addr := startXHTTPUDPServer(t, opts, srvTLS, halfCloseEchoHandler())
	client, err := NewClient(context.Background(), &h3TestDialer{}, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn, bytes.Repeat([]byte("QUIC_OPTS_"), 1024))
}

func TestXHTTPChromeParrotUTLSAndH3Settings(t *testing.T) {
	t.Parallel()

	// Verify DisableChromeParrot JSON option and quic.Config wiring.
	var parsedOpts option.V2RayXHTTPOptions
	require.NoError(t, json.Unmarshal([]byte(`{"quic":{"disable_chrome_parrot":true}}`), &parsedOpts))
	require.NotNil(t, parsedOpts.QUIC)
	require.True(t, parsedOpts.QUIC.DisableChromeParrot)

	defaultClientQUIC := buildXHTTPQUICConfig(nil, 0, 0, false, true)
	require.True(t, defaultClientQUIC.ChromeParrot)
	require.True(t, defaultClientQUIC.EnableDatagrams)
	disabledClientQUIC := buildXHTTPQUICConfig(parsedOpts.QUIC, 0, 0, false, true)
	require.False(t, disabledClientQUIC.ChromeParrot)
	serverQUIC := buildXHTTPQUICConfig(nil, 0, 0, true, false)
	require.False(t, serverQUIC.ChromeParrot)

	// Start an H3 server inspecting client HTTP/3 SETTINGS frame values.
	srvTLS, _, cliOpts := newTLSPair(t, "chrome-h3.example.com", []string{"h3", "h2"})
	h3TLS := srvTLS.Clone().(tls.ServerConfig)
	h3TLS.SetNextProtos([]string{"h3"})
	require.NoError(t, qtls.ConfigureHTTP3(h3TLS))

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	qtls.SetDesiredBufferSizes(pc)
	earlyLn, err := qtls.ListenEarly(pc, h3TLS, buildXHTTPQUICConfig(nil, 0, 0, true, false))
	require.NoError(t, err)

	settingsCh := make(chan *http3.Settings, 1)
	var settingsOnce sync.Once
	h3Srv := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if st, ok := w.(http3.Settingser); ok {
				select {
				case <-st.ReceivedSettings():
					settingsOnce.Do(func() {
						settingsCh <- st.Settings()
					})
				case <-r.Context().Done():
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("settings-ok"))
		}),
	}
	t.Cleanup(func() {
		_ = h3Srv.Close()
		_ = earlyLn.Close()
		_ = pc.Close()
	})
	go func() { _ = h3Srv.ServeListener(earlyLn) }()

	udpAddr := pc.LocalAddr().(*net.UDPAddr)
	target := M.SocksaddrFrom(M.AddrFromIP(udpAddr.IP), uint16(udpAddr.Port))

	// Configure client with uTLS Chrome enabled so STDConfigForQUIC bridges uTLS -> QUIC.
	cliOpts.UTLS = &option.OutboundUTLSOptions{
		Enabled:     true,
		Fingerprint: "chrome",
	}
	cliTLS, err := tls.NewClient(context.Background(), logger.NOP(), "chrome-h3.example.com", cliOpts)
	require.NoError(t, err)

	dialer := &h3TestDialer{}
	pool := newXmuxHTTPPool(dialer, target, cliTLS, true, 0, 0, mux.XmuxOptions{}, nil)
	t.Cleanup(pool.closeAll)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://chrome-h3.example.com/probe", nil)
	require.NoError(t, err)
	resp, err := pool.roundTrip(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, []byte("settings-ok"), body)
	require.GreaterOrEqual(t, int(dialer.udpDials.Load()), 1)
	require.Zero(t, dialer.tcpDials.Load())

	select {
	case got := <-settingsCh:
		require.NotNil(t, got)
		require.True(t, got.EnableDatagrams)
		require.Len(t, got.Other, 1)
		for id := range got.Other {
			require.GreaterOrEqual(t, id, uint64(0x21))
			require.Zero(t, (id-0x21)%0x1f)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP/3 settings frame")
	}
}

func TestXHTTPXMUXColdStartCoalescingH3(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "coalesce-h3.example.com", []string{"h3", "h2"})
	opts := option.V2RayXHTTPOptions{
		Path: "/ch3",
		Mode: "stream-up",
	}
	_, addr := startXHTTPDualServer(t, opts, srvTLS, halfCloseEchoHandler())

	delayed := &delayedCoalesceDialer{delay: 40 * time.Millisecond}
	client, err := NewClient(context.Background(), delayed, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// stream-up concurrently triggers GET (downlink) and POST (uplink) on a cold pool;
	// coalescing must share a single UDP/QUIC handshake.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn, bytes.Repeat([]byte("H3_COALESCE_"), 512))

	pool := client.uplinkPool
	pool.mu.Lock()
	defer pool.mu.Unlock()
	require.Equal(t, 1, len(pool.conns))
	require.True(t, pool.conns[0].isH3)
}

type qosDroppingDialer struct {
	udpDials atomic.Int32
	tcpDials atomic.Int32
	dropUDP  atomic.Bool
}

type qosDropConn struct {
	net.Conn
	drop *atomic.Bool
}

func (c *qosDropConn) Read(p []byte) (int, error) {
	if c.drop.Load() {
		return 0, errors.New("simulated udp qos blackhole")
	}
	return c.Conn.Read(p)
}

func (c *qosDropConn) Write(p []byte) (int, error) {
	if c.drop.Load() {
		return 0, errors.New("simulated udp qos blackhole")
	}
	return c.Conn.Write(p)
}

func (d *qosDroppingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, network, destination.String())
	if err != nil {
		return nil, err
	}
	if N.NetworkName(network) == N.NetworkUDP {
		d.udpDials.Add(1)
		return &qosDropConn{Conn: conn, drop: &d.dropUDP}, nil
	}
	d.tcpDials.Add(1)
	return conn, nil
}

func (d *qosDroppingDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func TestXHTTPRuntimeUDPQOSDegradesToH2(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "qos-fallback.example.com", []string{"h3", "h2"})
	opts := option.V2RayXHTTPOptions{
		Path: "/qos",
		Mode: "packet-up",
	}
	_, addr := startXHTTPDualServer(t, opts, srvTLS, halfCloseEchoHandler())

	dialer := &qosDroppingDialer{}
	client, err := NewClient(context.Background(), dialer, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// 1) Initial connection succeeds over HTTP/3.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn1, err := client.DialContext(ctx)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn1, []byte("initial-h3-ok"))
	require.GreaterOrEqual(t, int(dialer.udpDials.Load()), 1)
	require.Zero(t, dialer.tcpDials.Load())

	// 2) Flip UDP blackhole while H3 socket/session is active: subsequent session must
	// automatically fail over to TCP HTTP/2 without user intervention.
	dialer.dropUDP.Store(true)
	conn2, err := client.DialContext(ctx)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn2, bytes.Repeat([]byte("H2_AFTER_QOS_"), 128))
	require.GreaterOrEqual(t, int(dialer.tcpDials.Load()), 1)

	tryH3, allowFallback := client.uplinkPool.shouldAttemptH3(time.Now())
	require.False(t, tryH3)
	require.True(t, allowFallback)
}

func TestXHTTPRuntimeFailureStateMachine(t *testing.T) {
	t.Parallel()

	_, cliTLS, _ := newTLSPair(t, "sm.example.com", []string{"h3", "h2"})
	pool := newXmuxHTTPPool(&h3TestDialer{}, M.ParseSocksaddrHostPort("127.0.0.1", 443), cliTLS, true, 0, 0, mux.XmuxOptions{}, nil)
	t.Cleanup(pool.closeAll)

	base := time.Unix(1_700_000_000, 0)
	// First failure alone stays within threshold.
	pool.recordH3RuntimeFailure(base, nil)
	tryH3, _ := pool.shouldAttemptH3(base)
	require.True(t, tryH3)
	require.True(t, pool.h3HasFailures.Load())

	// A healthy success clears transient failure state.
	pool.recordH3RuntimeSuccess()
	require.False(t, pool.h3HasFailures.Load())

	// Isolated glitch outside h3DegradeFailureWindow does not trip cooldown either.
	pool.recordH3RuntimeFailure(base, nil)
	later := base.Add(h3DegradeFailureWindow + time.Second)
	pool.recordH3RuntimeFailure(later, nil)
	tryH3, _ = pool.shouldAttemptH3(later)
	require.True(t, tryH3)

	// Consecutive runtime failure within window trips cooldown to TCP H2 fallback.
	later2 := later.Add(time.Second)
	pool.recordH3RuntimeFailure(later2, nil)
	tryH3, allowFallback := pool.shouldAttemptH3(later2)
	require.False(t, tryH3)
	require.True(t, allowFallback)
}

type silentUDPBlackholeDialer struct {
	udpDials atomic.Int32
	tcpDials atomic.Int32
	release  chan struct{}
}

func (d *silentUDPBlackholeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		d.udpDials.Add(1)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.release:
			return nil, errors.New("released blackhole")
		}
	}
	d.tcpDials.Add(1)
	var nd net.Dialer
	return nd.DialContext(ctx, network, destination.String())
}

func (d *silentUDPBlackholeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func TestXHTTPHappyEyeballsUDPSilentBlackholeRacing(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "happy-eyeballs.example.com", []string{"h3", "h2"})
	opts := option.V2RayXHTTPOptions{
		Path: "/he",
		Mode: "packet-up",
	}
	_, addr := startXHTTPDualServer(t, opts, srvTLS, halfCloseEchoHandler())

	dialer := &silentUDPBlackholeDialer{release: make(chan struct{})}
	t.Cleanup(func() { close(dialer.release) })

	client, err := NewClient(context.Background(), dialer, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	client.uplinkPool.h3LeadDelay = 60 * time.Millisecond

	// Twice racing against silent UDP blackhole must failover via TCP H2 well under 1s each
	// (nowhere near 3s h3FallbackDialTimeout) and trip H3 runtime degradation cooldown.
	for i := 0; i < 2; i++ {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := client.DialContext(ctx)
		require.NoError(t, err)
		assertHalfCloseEcho(t, conn, []byte("happy-eyeballs-tcp-win"))
		cancel()
		require.Less(t, time.Since(start), 1500*time.Millisecond)
		if i == 0 {
			// Force re-dial on next iteration to test cooldown progression cleanly.
			client.uplinkPool.closeIdleConnections()
		}
	}
	require.GreaterOrEqual(t, int(dialer.tcpDials.Load()), 1)

	tryH3, allowFallback := client.uplinkPool.shouldAttemptH3(time.Now())
	require.False(t, tryH3)
	require.True(t, allowFallback)
}

type postHandshakeBlackholeConn struct {
	net.Conn
	blackhole *atomic.Bool
}

func (c *postHandshakeBlackholeConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if err != nil {
			return 0, err
		}
		if !c.blackhole.Load() {
			return n, nil
		}
	}
}

func (c *postHandshakeBlackholeConn) Write(p []byte) (int, error) {
	if c.blackhole.Load() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

type postHandshakeBlackholeDialer struct {
	udpDials  atomic.Int32
	tcpDials  atomic.Int32
	blackhole atomic.Bool
}

func (d *postHandshakeBlackholeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var nd net.Dialer
	conn, err := nd.DialContext(ctx, network, destination.String())
	if err != nil {
		return nil, err
	}
	if N.NetworkName(network) == N.NetworkUDP {
		d.udpDials.Add(1)
		return &postHandshakeBlackholeConn{Conn: conn, blackhole: &d.blackhole}, nil
	}
	d.tcpDials.Add(1)
	return conn, nil
}

func (d *postHandshakeBlackholeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func TestXHTTPPostHandshakeUDPBlackholeWatchdogFallback(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "watchdog.example.com", []string{"h3", "h2"})
	opts := option.V2RayXHTTPOptions{
		Path: "/watchdog",
		Mode: "packet-up",
	}
	_, addr := startXHTTPDualServer(t, opts, srvTLS, halfCloseEchoHandler())

	dialer := &postHandshakeBlackholeDialer{}
	client, err := NewClient(context.Background(), dialer, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	client.uplinkPool.h3HeaderWatchdog = 120 * time.Millisecond

	// 1) Initial session completes handshake and echoes over healthy UDP HTTP/3.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn1, err := client.DialContext(ctx)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn1, []byte("initial-h3-healthy"))
	require.GreaterOrEqual(t, int(dialer.udpDials.Load()), 1)
	require.Zero(t, dialer.tcpDials.Load())

	// 2) Silently drop UDP packets post-handshake (no OS socket error): watchdog must
	// abort header wait at ~120ms, degrade H3, and replay idempotently over TCP H2.
	dialer.blackhole.Store(true)
	start := time.Now()
	conn2, err := client.DialContext(ctx)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn2, []byte("recovered-after-silent-blackhole"))
	require.Less(t, time.Since(start), 2*time.Second)
	require.GreaterOrEqual(t, int(dialer.tcpDials.Load()), 1)
}

func TestXHTTPPostHandshakeWatchdogDoesNotInterruptIdleStreamingBody(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "watchdog-stream.example.com", []string{"h3", "h2"})
	opts := option.V2RayXHTTPOptions{
		Path: "/watchdog-stream",
		Mode: "packet-up",
	}
	_, addr := startXHTTPDualServer(t, opts, srvTLS, streamingEchoHandler())

	dialer := &h3TestDialer{}
	client, err := NewClient(context.Background(), dialer, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	client.uplinkPool.h3HeaderWatchdog = 80 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	defer conn.Close()

	// Sleep well past h3HeaderWatchdog after GET headers arrive; downlink streaming body must stay alive on H3.
	time.Sleep(220 * time.Millisecond)
	_, err = conn.Write([]byte("after-idle-body-ok"))
	require.NoError(t, err)
	buf := make([]byte, len("after-idle-body-ok"))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, "after-idle-body-ok", string(buf))
	require.Zero(t, dialer.tcpDials.Load())
}

type toggleUDPDialer struct {
	udpDials atomic.Int32
	tcpDials atomic.Int32
	blockUDP atomic.Bool
}

func (d *toggleUDPDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if N.NetworkName(network) == N.NetworkUDP {
		d.udpDials.Add(1)
		if d.blockUDP.Load() {
			return nil, errors.New("simulated blocked udp")
		}
	} else {
		d.tcpDials.Add(1)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, destination.String())
}

func (d *toggleUDPDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

type h3MockDNSRouter struct {
	adapter.DNSRouter
	calls   atomic.Int32
	handler func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error)
}

func (m *h3MockDNSRouter) Exchange(ctx context.Context, message *mDNS.Msg, _ adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	m.calls.Add(1)
	return m.handler(ctx, message)
}

func TestXHTTPHTTP3RecoversFromCooldownOverActiveH2(t *testing.T) {
	t.Parallel()

	srvTLS, cliTLS, _ := newTLSPair(t, "recover-h3.example.com", []string{"h3", "h2"})
	opts := option.V2RayXHTTPOptions{
		Path: "/recover-h3",
		Mode: "packet-up",
	}
	_, addr := startXHTTPDualServer(t, opts, srvTLS, halfCloseEchoHandler())

	dialer := &toggleUDPDialer{}
	dialer.blockUDP.Store(true)

	client, err := NewClient(context.Background(), dialer, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	// 1) With UDP blocked, dial falls back to TCP H2 and enters H3 cooldown while caching an idle H2 slot.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn1, err := client.DialContext(ctx)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn1, []byte("fallback-over-tcp-h2"))
	tcpBeforeRecovery := dialer.tcpDials.Load()
	require.GreaterOrEqual(t, int(tcpBeforeRecovery), 1)

	client.uplinkPool.mu.Lock()
	require.False(t, client.uplinkPool.h3RetryAfter.IsZero())
	client.uplinkPool.h3RetryAfter = time.Now().Add(60 * time.Millisecond)
	client.uplinkPool.mu.Unlock()

	// 2) Restore UDP and wait for H3 cooldown to expire; pool must probe H3 even though H2 slot is reusable.
	dialer.blockUDP.Store(false)
	time.Sleep(80 * time.Millisecond)

	udpBeforeRecovery := dialer.udpDials.Load()
	conn2, err := client.DialContext(ctx)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn2, []byte("recovered-back-to-h3"))

	require.Greater(t, dialer.udpDials.Load(), udpBeforeRecovery)
	require.Equal(t, tcpBeforeRecovery, dialer.tcpDials.Load())
	require.Eventually(t, func() bool {
		client.uplinkPool.mu.Lock()
		defer client.uplinkPool.mu.Unlock()
		hasH3 := false
		hasNonH3 := false
		for _, conn := range client.uplinkPool.conns {
			if conn.isH3 {
				hasH3 = true
			} else {
				hasNonH3 = true
			}
		}
		return hasH3 && !hasNonH3
	}, 2*time.Second, 10*time.Millisecond)
}

func makeECHHTTPSResponse(qname string, ttl uint32, echList []byte) *mDNS.Msg {
	return &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			Response: true,
			Rcode:    mDNS.RcodeSuccess,
		},
		Answer: []mDNS.RR{
			&mDNS.HTTPS{
				SVCB: mDNS.SVCB{
					Hdr: mDNS.RR_Header{
						Name:   mDNS.Fqdn(qname),
						Rrtype: mDNS.TypeHTTPS,
						Class:  mDNS.ClassINET,
						Ttl:    ttl,
					},
					Priority: 1,
					Target:   ".",
					Value: []mDNS.SVCBKeyValue{
						&mDNS.SVCBECHConfig{ECH: echList},
					},
				},
			},
		},
	}
}

func TestXHTTPHTTP3ECHKeyRotationRefreshRetry(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := generateCertPair(t, "inner-ech.example.com")
	echConfig1PEM, _, err := tls.ECHKeygenDefault("outer-ech.example.com")
	require.NoError(t, err)
	echConfig2PEM, echKey2PEM, err := tls.ECHKeygenDefault("outer-ech.example.com")
	require.NoError(t, err)

	block1, _ := pem.Decode([]byte(echConfig1PEM))
	require.NotNil(t, block1)
	block2, _ := pem.Decode([]byte(echConfig2PEM))
	require.NotNil(t, block2)

	srvTLS, err := tls.NewServerWithOptions(tls.ServerOptions{
		Context: context.Background(),
		Logger:  logger.NOP(),
		Options: option.InboundTLSOptions{
			Enabled:     true,
			ServerName:  "inner-ech.example.com",
			ALPN:        []string{"h3", "h2"},
			Certificate: []string{certPEM},
			Key:         []string{keyPEM},
			ECH: &option.InboundECHOptions{
				Enabled: true,
				Key:     []string{echKey2PEM},
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, srvTLS.Start())
	t.Cleanup(func() { _ = srvTLS.Close() })

	dnsMock := &h3MockDNSRouter{}
	dnsMock.handler = func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
		// 1st DNS lookup serves stale ECH key v1 with long TTL; refresh after rejection fetches live v2.
		if dnsMock.calls.Load() == 1 {
			return makeECHHTTPSResponse("outer-ech.example.com", 300, block1.Bytes), nil
		}
		return makeECHHTTPSResponse("outer-ech.example.com", 300, block2.Bytes), nil
	}

	cliCtx := service.ContextWith[adapter.DNSRouter](context.Background(), dnsMock)
	cliTLS, err := tls.NewClientWithOptions(tls.ClientOptions{
		Context:       cliCtx,
		Logger:        logger.NOP(),
		ServerAddress: "inner-ech.example.com",
		Options: option.OutboundTLSOptions{
			Enabled:     true,
			ServerName:  "inner-ech.example.com",
			ALPN:        []string{"h3", "h2"},
			Certificate: []string{certPEM},
			ECH: &option.OutboundECHOptions{
				Enabled:         true,
				QueryServerName: "outer-ech.example.com",
			},
		},
	})
	require.NoError(t, err)

	opts := option.V2RayXHTTPOptions{
		Path: "/ech-h3-rotate",
		Mode: "packet-up",
	}
	_, addr := startXHTTPDualServer(t, opts, srvTLS, halfCloseEchoHandler())

	dialer := &h3TestDialer{}
	client, err := NewClient(context.Background(), dialer, addr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn, []byte("ech-h3-rotated-success"))

	require.GreaterOrEqual(t, int(dnsMock.calls.Load()), 2)
	require.GreaterOrEqual(t, int(dialer.udpDials.Load()), 2)
	require.Zero(t, dialer.tcpDials.Load())
}

func TestXHTTPAltSvcDiscoveryUpgradesEmptyALPNToHTTP3OnAlternatePort(t *testing.T) {
	t.Parallel()

	srvTLS, _, cliTLSOpts := newTLSPair(t, "altsvc.example.com", []string{"h3", "h2"})
	cliTLSOpts.ALPN = nil
	cliTLS, err := tls.NewClientWithOptions(tls.ClientOptions{
		Context:       context.Background(),
		Logger:        logger.NOP(),
		ServerAddress: "altsvc.example.com",
		Options:       cliTLSOpts,
	})
	require.NoError(t, err)

	opts := option.V2RayXHTTPOptions{
		Path: "/altsvc",
		Mode: "packet-up",
	}
	srv, err := NewServer(context.Background(), logger.NOP(), opts, srvTLS, halfCloseEchoHandler())
	require.NoError(t, err)

	udpPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = srv.Close()
		_ = udpPC.Close()
	})
	go func() { _ = srv.ServePacket(udpPC) }()
	h3Port := udpPC.LocalAddr().(*net.UDPAddr).Port

	altSvcHeader := `h3=":` + strconv.Itoa(h3Port) + `"; ma=60`
	tcpAddr := startTLSHTTP2Proxy(t, srvTLS, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", altSvcHeader)
		srv.ServeHTTP(w, r)
	}))

	dialer := &h3TestDialer{}
	client, err := NewClient(context.Background(), dialer, tcpAddr, opts, cliTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	require.True(t, client.uplinkPool.allowAltSvcH3)
	require.True(t, client.downlinkPool.allowAltSvcH3)

	// Connection 1 runs over TCP HTTP/2 and receives Alt-Svc advertising the UDP H3 port.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel1()
	conn1, err := client.DialContext(ctx1)
	require.NoError(t, err)
	assertHalfCloseEcho(t, conn1, []byte("initial-tcp-h2-receives-altsvc"))
	require.GreaterOrEqual(t, int(dialer.tcpDials.Load()), 1)

	// Subsequent connections discover and upgrade over UDP HTTP/3 on h3Port.
	for i := 0; i < 2; i++ {
		ctxN, cancelN := context.WithTimeout(context.Background(), 10*time.Second)
		connN, dialErr := client.DialContext(ctxN)
		require.NoError(t, dialErr)
		assertHalfCloseEcho(t, connN, []byte("upgraded-udp-h3-"+strconv.Itoa(i)))
		cancelN()
	}
	require.GreaterOrEqual(t, int(dialer.udpDials.Load()), 1)

	// Verify Alt-Svc parser rejects cross-origin host hijack and respects clear.
	baseTarget := M.ParseSocksaddrHostPort("127.0.0.1", 443)
	target, ttl, clearAlt, ok := parseAltSvcH3([]string{`h3="evil.example.com:8443"; ma=120`}, baseTarget, "altsvc.example.com")
	require.False(t, ok)
	require.False(t, clearAlt)
	require.Zero(t, ttl)
	require.Equal(t, M.Socksaddr{}, target)

	target, ttl, clearAlt, ok = parseAltSvcH3([]string{`h3=":8443"; ma=90`}, baseTarget, "altsvc.example.com")
	require.True(t, ok)
	require.False(t, clearAlt)
	require.Equal(t, 90*time.Second, ttl)
	require.Equal(t, uint16(8443), target.Port)

	_, _, clearAlt, ok = parseAltSvcH3([]string{`clear`}, baseTarget, "altsvc.example.com")
	require.False(t, ok)
	require.True(t, clearAlt)

	t0 := time.Now()
	client.uplinkPool.recordAltSvc([]string{`clear`}, t0)
	client.uplinkPool.mu.Lock()
	clearedTarget := client.uplinkPool.altSvcTarget
	client.uplinkPool.mu.Unlock()
	require.Equal(t, M.Socksaddr{}, clearedTarget)

	// Renewing expired Alt-Svc on the same port resets altSvcProbed; active lease preserves it.
	client.uplinkPool.recordAltSvc([]string{altSvcHeader}, t0)
	client.uplinkPool.mu.Lock()
	client.uplinkPool.altSvcProbed = true
	client.uplinkPool.mu.Unlock()
	client.uplinkPool.recordAltSvc([]string{altSvcHeader}, t0.Add(10*time.Second))
	client.uplinkPool.mu.Lock()
	stillProbed := client.uplinkPool.altSvcProbed
	client.uplinkPool.mu.Unlock()
	require.True(t, stillProbed)

	client.uplinkPool.recordAltSvc([]string{altSvcHeader}, t0.Add(70*time.Second))
	client.uplinkPool.mu.Lock()
	rearmed := !client.uplinkPool.altSvcProbed
	client.uplinkPool.mu.Unlock()
	require.True(t, rearmed)
}

func TestXHTTPHTTP3ExponentialBackoffAndDefaultKeepAlive(t *testing.T) {
	t.Parallel()

	cfgDefault := buildXHTTPQUICConfig(nil, 0, 0, false, true)
	require.Equal(t, h3DefaultKeepAlivePeriod, cfgDefault.KeepAlivePeriod)

	srvTLS, cliTLS, _ := newTLSPair(t, "backoff.example.com", []string{"h3", "h2"})
	opts := option.V2RayXHTTPOptions{Path: "/backoff", Mode: "packet-up"}
	client, err := NewClient(context.Background(), &h3TestDialer{}, M.ParseSocksaddrHostPort("127.0.0.1", 443), opts, cliTLS)
	_ = srvTLS
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	pool := client.uplinkPool
	t0 := time.Unix(1_700_000_000, 0)
	expected := []time.Duration{
		30 * time.Second,
		60 * time.Second,
		120 * time.Second,
		240 * time.Second,
		300 * time.Second,
		300 * time.Second,
	}
	for _, want := range expected {
		pool.markH3Failed(t0)
		pool.mu.Lock()
		got := pool.h3RetryAfter.Sub(t0)
		pool.mu.Unlock()
		require.Equal(t, want, got)
	}

	pool.clearH3Failure()
	pool.markH3Failed(t0)
	pool.mu.Lock()
	gotAfterReset := pool.h3RetryAfter.Sub(t0)
	pool.mu.Unlock()
	require.Equal(t, 30*time.Second, gotAfterReset)
}

func TestXHTTPHTTP3StreamingUploadExemptFromHeaderWatchdog(t *testing.T) {
	t.Parallel()

	t.Run("StreamUpLongLivedSurvivesWatchdog", func(t *testing.T) {
		t.Parallel()

		srvTLS, cliTLS, _ := newTLSPair(t, "xhttp.example.com", []string{"h3", "h2"})
		opts := option.V2RayXHTTPOptions{
			Path: "/streamup-h3-watchdog",
			Mode: "stream-up",
		}
		_, addr := startXHTTPDualServerWithHTTPWrapper(t, opts, srvTLS, streamingEchoHandler(), nil)

		dialer := &h3TestDialer{}
		client, err := NewClient(context.Background(), dialer, addr, opts, cliTLS)
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		client.uplinkPool.h3HeaderWatchdog = 80 * time.Millisecond
		if client.downlinkPool != nil && client.downlinkPool != client.uplinkPool {
			client.downlinkPool.h3HeaderWatchdog = 80 * time.Millisecond
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := client.DialContext(ctx)
		require.NoError(t, err)
		defer conn.Close()

		require.Equal(t, int32(0), dialer.tcpDials.Load())

		msg1 := []byte("before-watchdog\n")
		_, err = conn.Write(msg1)
		require.NoError(t, err)
		buf1 := make([]byte, len(msg1))
		_, err = io.ReadFull(conn, buf1)
		require.NoError(t, err)
		require.Equal(t, msg1, buf1)
		require.GreaterOrEqual(t, dialer.udpDials.Load(), int32(1))
		require.Equal(t, int32(0), dialer.tcpDials.Load())

		// Hold the non-replayable stream-up POST open 3x longer than the H3 header watchdog.
		time.Sleep(240 * time.Millisecond)

		msg2 := []byte("after-watchdog\n")
		_, err = conn.Write(msg2)
		require.NoError(t, err)
		buf2 := make([]byte, len(msg2))
		_, err = io.ReadFull(conn, buf2)
		require.NoError(t, err)
		require.Equal(t, msg2, buf2)

		if wc, ok := conn.(interface{ CloseWrite() error }); ok {
			require.NoError(t, wc.CloseWrite())
			rest, readErr := io.ReadAll(conn)
			require.NoError(t, readErr)
			require.Empty(t, rest)
		}

		require.Equal(t, int32(0), dialer.tcpDials.Load())
		require.False(t, client.uplinkPool.h3HasFailures.Load())
		client.uplinkPool.mu.Lock()
		retryAfter := client.uplinkPool.h3RetryAfter
		client.uplinkPool.mu.Unlock()
		require.True(t, retryAfter.IsZero())
	})

	t.Run("AutoBufferedStreamOneDoesNotDegradeH3", func(t *testing.T) {
		t.Parallel()

		srvTLS, cliTLS, _ := newTLSPair(t, "xhttp.example.com", []string{"h3", "h2"})
		opts := option.V2RayXHTTPOptions{
			Path: "/auto-h3-buf",
		}
		var streamOnePosts atomic.Int32
		_, addr := startXHTTPDualServerWithHTTPWrapper(t, opts, srvTLS, streamingEchoHandler(), func(_ *Server, next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Simulate a commercial CDN buffering the stream-one POST body until EOF without sending headers.
				if r.Method == http.MethodPost && r.URL.Path == "/auto-h3-buf" {
					streamOnePosts.Add(1)
					_, _ = io.ReadAll(r.Body)
					return
				}
				next.ServeHTTP(w, r)
			})
		})

		dialer := &h3TestDialer{}
		client, err := NewClient(context.Background(), dialer, addr, opts, cliTLS)
		require.NoError(t, err)
		t.Cleanup(func() { _ = client.Close() })

		client.uplinkPool.h3HeaderWatchdog = 60 * time.Millisecond
		if client.downlinkPool != nil && client.downlinkPool != client.uplinkPool {
			client.downlinkPool.h3HeaderWatchdog = 60 * time.Millisecond
		}
		client.streamOneAutoTimeout = 150 * time.Millisecond

		ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel1()
		conn1, err := client.DialContext(ctx1)
		require.NoError(t, err)
		_, err = conn1.Write([]byte("buffered-stream-one"))
		require.NoError(t, err)
		tmp := make([]byte, 16)
		_, err = conn1.Read(tmp)
		require.Error(t, err)
		_ = conn1.Close()

		require.True(t, client.autoFallbackPacketUp.Load())
		require.Equal(t, int32(0), dialer.tcpDials.Load())
		require.False(t, client.uplinkPool.h3HasFailures.Load())
		client.uplinkPool.mu.Lock()
		retryAfter := client.uplinkPool.h3RetryAfter
		client.uplinkPool.mu.Unlock()
		require.True(t, retryAfter.IsZero())

		ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel2()
		conn2, err := client.DialContext(ctx2)
		require.NoError(t, err)
		defer conn2.Close()

		payload := []byte("recovered-via-h3-packet-up")
		_, err = conn2.Write(payload)
		require.NoError(t, err)
		got := make([]byte, len(payload))
		_, err = io.ReadFull(conn2, got)
		require.NoError(t, err)
		require.Equal(t, payload, got)

		require.Equal(t, int32(0), dialer.tcpDials.Load())
		require.GreaterOrEqual(t, dialer.udpDials.Load(), int32(1))
		require.Equal(t, int32(1), streamOnePosts.Load())
	})
}
