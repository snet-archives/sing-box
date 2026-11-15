package vlessenc

import (
	std_bufio "bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/stretchr/testify/require"
)

func assertExASCIIHeader(t *testing.T, pkt []byte) {
	t.Helper()
	require.NotEmpty(t, pkt)
	require.True(t, bytes.HasPrefix(pkt, []byte("GET ")), "Ex5: first TCP packet must begin with HTTP GET method, got %q", pkt[:min(len(pkt), 32)])
	printable := 0
	consec := 0
	maxConsec := 0
	for _, b := range pkt {
		if (b >= 0x20 && b <= 0x7e) || b == '\r' || b == '\n' || b == '\t' {
			printable++
		}
		if b >= 0x20 && b <= 0x7e {
			consec++
			if consec > maxConsec {
				maxConsec = consec
			}
		} else {
			consec = 0
		}
	}
	require.Equal(t, len(pkt), printable, "Ex2: first TCP flight before 101 must be 100%% printable ASCII/HTTP bytes")
	require.GreaterOrEqual(t, maxConsec, 20, "Ex3: first TCP flight must have >= 20 consecutive printable ASCII bytes")
}

func TestXorHTTPSchemaGeneration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	decSchema, err := schema.Generate(ctx, reflect.TypeFor[option.VLESSDecryptionOptions]())
	require.NoError(t, err)
	decStr := string(decSchema)
	require.Contains(t, decStr, `"http"`)
	require.Contains(t, decStr, `"http_host"`)
	require.Contains(t, decStr, `"http_path"`)

	encSchema, err := schema.Generate(ctx, reflect.TypeFor[option.VLESSEncryptionOptions]())
	require.NoError(t, err)
	encStr := string(encSchema)
	require.Contains(t, encStr, `"http"`)
	require.Contains(t, encStr, `"http_host"`)
	require.Contains(t, encStr, `"http_path"`)
	require.Contains(t, encStr, `"http_headers"`)

	masqSchema, err := schema.Generate(ctx, reflect.TypeFor[*option.Hysteria2Masquerade]())
	require.NoError(t, err)
	require.Contains(t, string(masqSchema), `"string"`)
	field, ok := reflect.TypeFor[option.VLESSInboundOptions]().FieldByName("Masquerade")
	require.True(t, ok)
	require.Equal(t, "masquerade,omitempty", field.Tag.Get("json"))
}

// firstFlightConn records initial pre-response write flights and server response bytes for inspection.
type firstFlightConn struct {
	net.Conn
	mu          sync.Mutex
	firstFlight []byte
	firstResp   []byte
	gotResponse bool
}

func (c *firstFlightConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.gotResponse {
		c.firstFlight = append(c.firstFlight, p...)
	}
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *firstFlightConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		c.gotResponse = true
		if len(c.firstResp) < 4096 {
			c.firstResp = append(c.firstResp, p[:n]...)
		}
		c.mu.Unlock()
	}
	return n, err
}

func TestXorHTTPUpgradeHandshakeAndExBypass(t *testing.T) {
	t.Parallel()

	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	var srvClock, cliClock atomic.Int64
	baseTime := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC).UnixNano()
	srvClock.Store(baseTime)
	cliClock.Store(baseTime)

	srv, err := NewServer(option.VLESSDecryptionOptions{
		Enabled:       true,
		PrivateKey:    kp.PrivateKey,
		MLKEM768Seed:  kp.MLKEM768Seed,
		TicketSecret:  kp.TicketSecret,
		XorMode:       XorHTTP,
		XorPSK:        kp.XorPSK,
		HTTPHost:      "cdn.example.com",
		HTTPPath:      "ws-vless",
		SessionMaxAge: badoption.Duration(5 * time.Minute),
	})
	require.NoError(t, err)
	srv.now = func() time.Time { return time.Unix(0, srvClock.Load()) }

	cli, err := NewClient(option.VLESSEncryptionOptions{
		Enabled:          true,
		PublicKey:        kp.PublicKey,
		MLKEM768EncapKey: kp.MLKEM768EncapKey,
		Mode:             ModeZeroRTT,
		XorMode:          XorHTTP,
		XorPSK:           kp.XorPSK,
		HTTPHost:         "cdn.example.com",
		HTTPPath:         "/ws-vless",
		HTTPHeaders: badoption.HTTPHeader{
			"X-Custom-Edge": badoption.Listable[string]{"edge-1"},
		},
	})
	require.NoError(t, err)
	cli.now = func() time.Time { return time.Unix(0, cliClock.Load()) }

	runEcho := func(payload []byte) []byte {
		rawCli, rawSrv := tcpPair(t)
		flightCli := &firstFlightConn{Conn: rawCli}
		spyCli := &spyConn{Conn: flightCli}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		errCh := make(chan error, 1)
		go func() {
			sConn, sErr := srv.ServerHandshake(ctx, rawSrv)
			if sErr != nil {
				_ = rawSrv.Close()
				errCh <- sErr
				return
			}
			defer sConn.Close()
			_, copyErr := io.Copy(sConn, sConn)
			errCh <- copyErr
		}()

		cConn, err := cli.ClientHandshake(ctx, spyCli)
		require.NoError(t, err)

		// First TCP flight before 101 must be pure HTTP Upgrade ASCII (passes Ex2/Ex3/Ex5, no trailing binary).
		flightCli.mu.Lock()
		firstFlight := append([]byte(nil), flightCli.firstFlight...)
		flightCli.mu.Unlock()
		assertExASCIIHeader(t, firstFlight)
		require.True(t, bytes.HasSuffix(firstFlight, []byte("\r\n\r\n")), "client must wait for 101 before sending binary KEM/ticket")

		req, err := http.ReadRequest(std_bufio.NewReader(bytes.NewReader(firstFlight)))
		require.NoError(t, err)
		require.Equal(t, "cdn.example.com", req.Host)
		require.Equal(t, "/ws-vless", req.URL.Path)
		require.Equal(t, "websocket", strings.ToLower(req.Header.Get("Upgrade")))
		require.Equal(t, "upgrade", strings.ToLower(req.Header.Get("Connection")))
		require.Equal(t, "13", req.Header.Get("Sec-WebSocket-Version"))
		require.Equal(t, "edge-1", req.Header.Get("X-Custom-Edge"))
		// TLS-only headers must be stripped over plain HTTP ws:// unless explicitly configured.
		require.Empty(t, req.Header.Get("Sec-CH-UA"))
		require.Empty(t, req.Header.Get("Sec-Fetch-Site"))

		_, err = cConn.Write(payload)
		require.NoError(t, err)

		got := make([]byte, 0, len(payload))
		tmp := make([]byte, 777)
		for len(got) < len(payload) {
			n, rErr := cConn.Read(tmp)
			require.NoError(t, rErr)
			got = append(got, tmp[:n]...)
		}
		require.Equal(t, payload, got)
		require.NoError(t, cConn.Close())
		require.NoError(t, <-errCh)

		// Server response must start with HTTP/1.1 101 Switching Protocols + Sec-WebSocket-Accept.
		flightCli.mu.Lock()
		firstResp := append([]byte(nil), flightCli.firstResp...)
		flightCli.mu.Unlock()
		resp, err := http.ReadResponse(std_bufio.NewReader(bytes.NewReader(firstResp)), req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
		require.Equal(t, computeWebSocketAccept(req.Header.Get("Sec-WebSocket-Key")), resp.Header.Get("Sec-WebSocket-Accept"))

		return spyCli.writes
	}

	// 1-RTT initial connection (multi-frame > 16KB AEAD records)
	wire1 := runEcho(bytes.Repeat([]byte("HTTP-PQ-HYBRID-"), 4000))
	// Advance clock slightly into next 1s to trigger distinct time/salt and exercise 0-RTT ticket fast-open!
	cliClock.Add(int64(2 * time.Second))
	srvClock.Add(int64(2 * time.Second))
	wire2 := runEcho([]byte("fast-0rtt-after-101"))
	// 0-RTT Wire is markedly shorter because ticket replaces 1088-byte ML-KEM ciphertext.
	require.Greater(t, len(wire1), len(wire2)+500)
}

func TestXorHTTPFallbackAndReplayRejection(t *testing.T) {
	t.Parallel()

	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	baseTime := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	var srvClock, cliClock atomic.Int64
	srvClock.Store(baseTime.UnixNano())
	cliClock.Store(baseTime.UnixNano())

	srv, err := NewServer(option.VLESSDecryptionOptions{
		Enabled:      true,
		PrivateKey:   kp.PrivateKey,
		MLKEM768Seed: kp.MLKEM768Seed,
		TicketSecret: kp.TicketSecret,
		XorMode:      XorHTTP,
		XorPSK:       kp.XorPSK,
		HTTPHost:     "cdn.example.com",
		HTTPPath:     "/ws-vless",
	})
	require.NoError(t, err)
	srv.now = func() time.Time { return time.Unix(0, srvClock.Load()) }

	assertFallbackExactBytes := func(t *testing.T, rawProbe []byte) {
		t.Helper()
		rawCli, rawSrv := tcpPair(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		type srvResult struct {
			err error
		}
		resCh := make(chan srvResult, 1)
		go func() {
			sConn, sErr := srv.ServerHandshake(ctx, rawSrv)
			if sConn != nil {
				_ = sConn.Close()
			}
			var fbErr *HandshakeFallbackError
			if errors.As(sErr, &fbErr) {
				// Read back buffered + remaining bytes from fallback conn and respond over HTTP.
				br := std_bufio.NewReader(fbErr.Conn)
				req, reqErr := http.ReadRequest(br)
				if reqErr == nil {
					_ = req.Body.Close()
					_, _ = io.WriteString(fbErr.Conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
				}
				_ = fbErr.Conn.Close()
			} else {
				_ = rawSrv.Close()
			}
			resCh <- srvResult{err: sErr}
		}()

		_, wErr := rawCli.Write(rawProbe)
		require.NoError(t, wErr)
		respBytes, rErr := io.ReadAll(rawCli)
		require.NoError(t, rErr)
		_ = rawCli.Close()

		res := <-resCh
		var fbErr *HandshakeFallbackError
		require.ErrorAs(t, res.err, &fbErr)
		require.Contains(t, string(respBytes), "HTTP/1.1 200 OK")
		require.NotContains(t, string(respBytes), "101 Switching Protocols")
	}

	t.Run("browser_get_probe", func(t *testing.T) {
		assertFallbackExactBytes(t, []byte("GET / HTTP/1.1\r\nHost: cdn.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"))
	})

	t.Run("wrong_path_or_host", func(t *testing.T) {
		wsKey, kErr := buildWebSocketAuthKey(srv.httpAuthKey, http.MethodGet, "/wrong-path", baseTime)
		require.NoError(t, kErr)
		assertFallbackExactBytes(t, []byte("GET /wrong-path HTTP/1.1\r\nHost: cdn.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+wsKey+"\r\n\r\n"))

		wsKeyRightPath, kErr := buildWebSocketAuthKey(srv.httpAuthKey, http.MethodGet, "/ws-vless", baseTime)
		require.NoError(t, kErr)
		assertFallbackExactBytes(t, []byte("GET /ws-vless HTTP/1.1\r\nHost: evil.example.net\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+wsKeyRightPath+"\r\n\r\n"))
	})

	t.Run("wrong_psk_and_skew", func(t *testing.T) {
		badCli, cErr := NewClient(option.VLESSEncryptionOptions{
			Enabled:          true,
			PublicKey:        kp.PublicKey,
			MLKEM768EncapKey: kp.MLKEM768EncapKey,
			Mode:             ModeNative,
			XorMode:          XorHTTP,
			XorPSK:           "", // missing PSK
			HTTPHost:         "cdn.example.com",
			HTTPPath:         "/ws-vless",
		})
		require.NoError(t, cErr)
		badCli.now = func() time.Time { return time.Unix(0, cliClock.Load()) }

		wsKey, kErr := buildWebSocketAuthKey(badCli.httpAuthKey, http.MethodGet, "/ws-vless", baseTime)
		require.NoError(t, kErr)
		assertFallbackExactBytes(t, []byte("GET /ws-vless HTTP/1.1\r\nHost: cdn.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+wsKey+"\r\n\r\n"))

		// Outside 120s skew window
		skewKey, kErr := buildWebSocketAuthKey(srv.httpAuthKey, http.MethodGet, "/ws-vless", baseTime.Add(4*time.Minute))
		require.NoError(t, kErr)
		assertFallbackExactBytes(t, []byte("GET /ws-vless HTTP/1.1\r\nHost: cdn.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+skewKey+"\r\n\r\n"))

		// Within 120s skew window succeeds
		okSkewKey, kErr := buildWebSocketAuthKey(srv.httpAuthKey, http.MethodGet, "/ws-vless", baseTime.Add(90*time.Second))
		require.NoError(t, kErr)
		rawCli, rawSrv := tcpPair(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		errCh := make(chan error, 1)
		go func() {
			_, sErr := srv.serverHTTPUpgrade(ctx, rawSrv)
			_ = rawSrv.Close()
			errCh <- sErr
		}()
		_, wErr := rawCli.Write([]byte("GET /ws-vless HTTP/1.1\r\nHost: cdn.example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + okSkewKey + "\r\n\r\n"))
		require.NoError(t, wErr)
		resp, rErr := http.ReadResponse(std_bufio.NewReader(rawCli), nil)
		require.NoError(t, rErr)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
		_ = rawCli.Close()
		require.NoError(t, <-errCh)
	})

	t.Run("exact_replay_rejected_with_fallback", func(t *testing.T) {
		goodCli, cErr := NewClient(option.VLESSEncryptionOptions{
			Enabled:          true,
			PublicKey:        kp.PublicKey,
			MLKEM768EncapKey: kp.MLKEM768EncapKey,
			Mode:             ModeNative,
			XorMode:          XorHTTP,
			XorPSK:           kp.XorPSK,
			HTTPHost:         "cdn.example.com",
			HTTPPath:         "/ws-vless",
		})
		require.NoError(t, cErr)
		goodCli.now = func() time.Time { return time.Unix(0, cliClock.Load()) }

		rawCli, rawSrv := tcpPair(t)
		flight := &firstFlightConn{Conn: rawCli}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		errCh := make(chan error, 1)
		go func() {
			sConn, sErr := srv.ServerHandshake(ctx, rawSrv)
			if sConn != nil {
				_ = sConn.Close()
			} else {
				_ = rawSrv.Close()
			}
			errCh <- sErr
		}()
		cConn, hErr := goodCli.ClientHandshake(ctx, flight)
		require.NoError(t, hErr)
		_ = cConn.Close()
		_ = <-errCh

		flight.mu.Lock()
		capturedUpgrade := append([]byte(nil), flight.firstFlight...)
		flight.mu.Unlock()
		require.NotEmpty(t, capturedUpgrade)

		// Replaying the exact captured HTTP Upgrade request must NOT get 101; it must fall back.
		assertFallbackExactBytes(t, capturedUpgrade)
	})
}
