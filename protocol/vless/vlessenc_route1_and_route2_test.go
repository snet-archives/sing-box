package vless

import (
	std_bufio "bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/vlessenc"
	C "github.com/sagernet/sing-box/constant"
	sblog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowtls"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

func mustVLESSKeypairAndUUID(t *testing.T) (string, vlessenc.KeyPair) {
	t.Helper()
	uid, err := uuid.NewV4()
	require.NoError(t, err)
	kp, err := vlessenc.GenerateKeyPair()
	require.NoError(t, err)
	return uid.String(), kp
}

func makeVLESSEncConfigs(kp vlessenc.KeyPair, xorMode, httpHost, httpPath string) (*option.VLESSDecryptionOptions, *option.VLESSEncryptionOptions) {
	dec := &option.VLESSDecryptionOptions{
		Enabled:       true,
		PrivateKey:    kp.PrivateKey,
		MLKEM768Seed:  kp.MLKEM768Seed,
		TicketSecret:  kp.TicketSecret,
		XorMode:       xorMode,
		XorPSK:        kp.XorPSK,
		HTTPHost:      httpHost,
		HTTPPath:      httpPath,
		SessionMaxAge: badoption.Duration(5 * time.Minute),
	}
	enc := &option.VLESSEncryptionOptions{
		Enabled:          true,
		PublicKey:        kp.PublicKey,
		MLKEM768EncapKey: kp.MLKEM768EncapKey,
		Mode:             vlessenc.ModeZeroRTT,
		XorMode:          xorMode,
		XorPSK:           kp.XorPSK,
		HTTPHost:         httpHost,
		HTTPPath:         httpPath,
	}
	return dec, enc
}

// startTCPWireTap forwards accepted TCP connections to targetAddr while recording
// each connection's initial client->server flight prior to the server's first byte.
func startTCPWireTap(t *testing.T, targetAddr string) (uint16, func() [][]byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var (
		mu      sync.Mutex
		flights [][]byte
		wg      sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			cliConn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				srvConn, dialErr := net.DialTimeout("tcp", targetAddr, 5*time.Second)
				if dialErr != nil {
					return
				}
				defer srvConn.Close()

				var (
					flightMu        sync.Mutex
					firstFlight     []byte
					serverResponded atomic.Bool
					recordOnce      sync.Once
				)
				recordFlight := func() {
					recordOnce.Do(func() {
						flightMu.Lock()
						captured := append([]byte(nil), firstFlight...)
						flightMu.Unlock()
						if len(captured) > 0 {
							mu.Lock()
							flights = append(flights, captured)
							mu.Unlock()
						}
					})
				}

				done := make(chan struct{}, 2)
				go func() {
					buf := make([]byte, 4096)
					for {
						n, rErr := c.Read(buf)
						if n > 0 {
							if !serverResponded.Load() {
								flightMu.Lock()
								if !serverResponded.Load() && len(firstFlight) < 8192 {
									firstFlight = append(firstFlight, buf[:n]...)
								}
								flightMu.Unlock()
							}
							if _, wErr := srvConn.Write(buf[:n]); wErr != nil {
								break
							}
						}
						if rErr != nil {
							break
						}
					}
					if tc, ok := srvConn.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
					done <- struct{}{}
				}()
				go func() {
					buf := make([]byte, 4096)
					for {
						n, rErr := srvConn.Read(buf)
						if n > 0 {
							if serverResponded.CompareAndSwap(false, true) {
								recordFlight()
							}
							if _, wErr := c.Write(buf[:n]); wErr != nil {
								break
							}
						}
						if rErr != nil {
							break
						}
					}
					if tc, ok := c.(*net.TCPConn); ok {
						_ = tc.CloseWrite()
					}
					done <- struct{}{}
				}()
				<-done
				<-done
				recordFlight()
			}(cliConn)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	return port, func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]byte, len(flights))
		copy(out, flights)
		return out
	}
}

func assertVLESSOutboundEcho(t *testing.T, out adapter.Outbound, payloads ...[]byte) {
	t.Helper()
	dst := M.ParseSocksaddrHostPort("echo.local", 9000)
	for i, payload := range payloads {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := out.(N.Dialer).DialContext(ctx, N.NetworkTCP, dst)
		require.NoError(t, err, "round %d dial", i)

		_, err = conn.Write(payload)
		require.NoError(t, err, "round %d write", i)

		got := make([]byte, len(payload))
		_, err = io.ReadFull(conn, got)
		require.NoError(t, err, "round %d read", i)
		require.Equal(t, payload, got, "round %d payload mismatch", i)
		require.NoError(t, conn.Close())
		cancel()
	}
}

func assertWireStartsASCIIHTTP(t *testing.T, flight []byte, expectedMethod string) {
	t.Helper()
	require.NotEmpty(t, flight)
	require.True(t, bytes.HasPrefix(flight, []byte(expectedMethod+" ")), "expected %s prefix, got %q", expectedMethod, flight[:min(len(flight), 32)])
	headerEnd := bytes.Index(flight, []byte("\r\n\r\n"))
	require.Greater(t, headerEnd, 20, "missing complete HTTP header terminator in first flight")
	consec := 0
	maxConsec := 0
	for _, b := range flight[:headerEnd] {
		isPrintable := (b >= 0x20 && b <= 0x7e) || b == '\r' || b == '\n' || b == '\t'
		require.True(t, isPrintable, "non-ASCII byte 0x%02x in HTTP header", b)
		if b >= 0x20 && b <= 0x7e {
			consec++
			if consec > maxConsec {
				maxConsec = consec
			}
		} else {
			consec = 0
		}
	}
	require.GreaterOrEqual(t, maxConsec, 20)
}

func reserveLocalTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	require.NoError(t, ln.Close())
	return port
}

func startLocalTLSTarget(t *testing.T, serverName string) (uint16, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dnsNames := []string{serverName}
	for i := 0; i < 96; i++ {
		dnsNames = append(dnsNames, "cdn-"+string(rune('a'+i%26))+"-node.example.com")
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert := stdtls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func(raw net.Conn) {
				defer wg.Done()
				defer raw.Close()
				tlsConn := stdtls.Server(raw, &stdtls.Config{
					Certificates:     []stdtls.Certificate{cert},
					MinVersion:       stdtls.VersionTLS13,
					MaxVersion:       stdtls.VersionTLS13,
					CurvePreferences: []stdtls.CurveID{stdtls.X25519MLKEM768, stdtls.X25519},
					NextProtos:       []string{"h2", "http/1.1"},
				})
				if hErr := tlsConn.Handshake(); hErr != nil {
					return
				}
				_, _ = io.Copy(tlsConn, tlsConn)
			}(c)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return uint16(ln.Addr().(*net.TCPAddr).Port), certPEM
}

func certPEMPairFromStrings(t *testing.T) (string, string, []byte) {
	t.Helper()
	certPEM, keyPEM := generateTestCertPEM(t)
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(parsedCert.PublicKey)
	require.NoError(t, err)
	pin := sha256.Sum256(spki)
	return certPEM, keyPEM, pin[:]
}

type stubOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *stubOutboundManager) Start(stage adapter.StartStage, scope *adapter.Scope) error { return nil }
func (m *stubOutboundManager) Close() error                                               { return nil }
func (m *stubOutboundManager) Outbounds() []adapter.Outbound                              { return nil }
func (m *stubOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := m.outbounds[tag]
	return o, ok
}
func (m *stubOutboundManager) Default() adapter.Outbound { return nil }
func (m *stubOutboundManager) Create(context.Context, adapter.Router, sblog.ContextLogger, string, string, any) error {
	return nil
}

type shadowTLSDetourRouter struct {
	adapter.Router
	target adapter.Inbound
}

func (r shadowTLSDetourRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if injectable, ok := r.target.(adapter.TCPInjectableInbound); ok {
		injectable.NewConnection(ctx, conn, metadata, onClose)
		return
	}
	N.CloseOnHandshakeFailure(conn, onClose, errors.New("detour target not TCPInjectableInbound"))
}

func TestVLESSMasqueradeValidationFailFast(t *testing.T) {
	t.Parallel()
	uid, kp := mustVLESSKeypairAndUUID(t)
	ctx := context.Background()
	masq := &option.Hysteria2Masquerade{
		Type: C.Hysterai2MasqueradeTypeString,
		StringOptions: option.Hysteria2MasqueradeString{
			StatusCode: http.StatusOK,
			Content:    "ok",
		},
	}

	_, err := NewInbound(ctx, vlessEncEchoRouter{}, logger.NOP(), "vless-in", option.VLESSInboundOptions{
		Users:      []option.VLESSUser{{UUID: uid}},
		Masquerade: masq,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), `xor_mode "http"`)

	decRandom, _ := makeVLESSEncConfigs(kp, vlessenc.XorRandom, "", "")
	_, err = NewInbound(ctx, vlessEncEchoRouter{}, logger.NOP(), "vless-in", option.VLESSInboundOptions{
		Users:      []option.VLESSUser{{UUID: uid}},
		Decryption: decRandom,
		Masquerade: masq,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), `xor_mode "http"`)

	decHTTP, _ := makeVLESSEncConfigs(kp, vlessenc.XorHTTP, "", "")
	_, err = NewInbound(ctx, vlessEncEchoRouter{}, logger.NOP(), "vless-in", option.VLESSInboundOptions{
		Users:      []option.VLESSUser{{UUID: uid}},
		Decryption: decHTTP,
		Transport:  &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket},
		Masquerade: masq,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "masquerade is incompatible with custom transport")

	in, err := NewInbound(ctx, vlessEncEchoRouter{}, logger.NOP(), "vless-in", option.VLESSInboundOptions{
		Users:      []option.VLESSUser{{UUID: uid}},
		Decryption: decHTTP,
		Masquerade: masq,
	})
	require.NoError(t, err)
	require.NotNil(t, in)
}

func TestVLESSRoute2XorHTTPAndMasquerade(t *testing.T) {
	t.Parallel()
	uid, kp := mustVLESSKeypairAndUUID(t)
	decOpts, encOpts := makeVLESSEncConfigs(kp, vlessenc.XorHTTP, "", "/api/stream")
	// Leave HTTPHost empty on client so Outbound fills it automatically from ServerOptions.

	const masqBody = "<!doctype html><html><title>Edge CDN</title><body>Service Online</body></html>"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := adapter.NewScope(ctx, logger.NOP())
	defer scope.Close()

	in, err := NewInbound(ctx, vlessEncEchoRouter{}, logger.NOP(), "vless-route2", option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: 0,
		},
		Users:      []option.VLESSUser{{UUID: uid}},
		Decryption: decOpts,
		Masquerade: &option.Hysteria2Masquerade{
			Type: C.Hysterai2MasqueradeTypeString,
			StringOptions: option.Hysteria2MasqueradeString{
				StatusCode: http.StatusOK,
				Headers: badoption.HTTPHeader{
					"Content-Type": badoption.Listable[string]{"text/html; charset=utf-8"},
					"Server":       badoption.Listable[string]{"nginx/1.26.0"},
				},
				Content: masqBody,
			},
		},
	})
	require.NoError(t, err)
	require.NoError(t, in.Start(adapter.StartStateStart, scope))

	inAddr := in.(*Inbound).listener.TCPListener().Addr().String()
	tapPort, getFlights := startTCPWireTap(t, inAddr)

	out, err := NewOutbound(ctx, nil, logger.NOP(), "vless-route2-out", option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: tapPort,
		},
		UUID:       uid,
		Encryption: encOpts,
	})
	require.NoError(t, err)
	require.NoError(t, out.(*Outbound).Start(adapter.StartStateInitialize, scope))

	// 1. 1-RTT + 0-RTT genuine traffic passes through Route 2 (no TLS, no outer transport).
	assertVLESSOutboundEcho(t, out,
		bytes.Repeat([]byte("ROUTE2-1RTT-"), 200),
		bytes.Repeat([]byte("ROUTE2-0RTT-"), 200),
	)

	flights := getFlights()
	require.Len(t, flights, 2)
	for _, f := range flights {
		assertWireStartsASCIIHTTP(t, f, http.MethodGet)
		require.True(t, bytes.HasSuffix(f, []byte("\r\n\r\n")), "TCP Packet #1 must contain only HTTP Upgrade ASCII before 101")
	}

	// 2. Active HTTP scanner receives real HTML masquerade response directly from vless.Inbound.
	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Get("http://" + inAddr + "/index.html")
	require.NoError(t, err)
	bodyBytes, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "nginx/1.26.0", resp.Header.Get("Server"))
	require.Equal(t, masqBody, string(bodyBytes))

	// 3. Replaying an authentic captured HTTP Upgrade header on TCP triggers anti-replay fallback (HTTP 200 HTML, NOT 101!).
	replayConn, err := net.DialTimeout("tcp", inAddr, 5*time.Second)
	require.NoError(t, err)
	defer replayConn.Close()
	_, err = replayConn.Write(flights[0])
	require.NoError(t, err)
	replayResp, err := http.ReadResponse(std_bufio.NewReader(replayConn), nil)
	require.NoError(t, err)
	replayBody, err := io.ReadAll(replayResp.Body)
	_ = replayResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, replayResp.StatusCode)
	require.Equal(t, masqBody, string(replayBody))
}

func TestVLESSRoute1PlaintextHTTPUpgradeAndXHTTP(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		transport option.V2RayTransportOptions
		methods   []string
	}{
		{
			name: "httpupgrade_no_tls",
			transport: option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeHTTPUpgrade,
				HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
					Host: "up.example.com",
					Path: "/up-vless",
				},
			},
			methods: []string{http.MethodGet},
		},
		{
			name: "xhttp_packet_up_no_tls",
			transport: option.V2RayTransportOptions{
				Type: C.V2RayTransportTypeXHTTP,
				XHTTPOptions: option.V2RayXHTTPOptions{
					Host: badoption.Listable[string]{"xhttp.example.com"},
					Path: "/split-vless",
					Mode: "packet-up",
				},
			},
			// packet-up issues concurrent GET (downlink) and POST (uplink) requests,
			// so either method may open the first TCP flight under -race scheduling.
			methods: []string{http.MethodGet, http.MethodPost},
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			uid, kp := mustVLESSKeypairAndUUID(t)
			decOpts, encOpts := makeVLESSEncConfigs(kp, vlessenc.XorRandom, "", "")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			scope := adapter.NewScope(ctx, logger.NOP())
			defer scope.Close()

			in, err := NewInbound(ctx, vlessEncEchoRouter{}, logger.NOP(), "vless-in-"+tc.name, option.VLESSInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
					ListenPort: 0,
				},
				Users:      []option.VLESSUser{{UUID: uid}},
				Decryption: decOpts,
				Transport:  &tc.transport,
			})
			require.NoError(t, err)
			require.NoError(t, in.Start(adapter.StartStateStart, scope))

			inAddr := in.(*Inbound).listener.TCPListener().Addr().String()
			tapPort, getFlights := startTCPWireTap(t, inAddr)

			out, err := NewOutbound(ctx, nil, logger.NOP(), "vless-out-"+tc.name, option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: tapPort,
				},
				UUID:       uid,
				Encryption: encOpts,
				Transport:  &tc.transport,
			})
			require.NoError(t, err)
			require.NoError(t, out.(*Outbound).Start(adapter.StartStateInitialize, scope))

			assertVLESSOutboundEcho(t, out,
				bytes.Repeat([]byte("ROUTE1-HTTP-1RTT-"), 150),
				bytes.Repeat([]byte("ROUTE1-HTTP-0RTT-"), 150),
			)

			flights := getFlights()
			require.NotEmpty(t, flights)
			matchedMethod := ""
			for _, m := range tc.methods {
				if bytes.HasPrefix(flights[0], []byte(m+" ")) {
					matchedMethod = m
					break
				}
			}
			require.NotEmpty(t, matchedMethod, "expected one of %v prefix, got %q", tc.methods, flights[0][:min(len(flights[0]), 32)])
			assertWireStartsASCIIHTTP(t, flights[0], matchedMethod)
		})
	}
}

func TestVLESSRoute1SelfSignedTLSAndPinning(t *testing.T) {
	t.Parallel()

	t.Run("auto_generated_self_signed_insecure", func(t *testing.T) {
		t.Parallel()
		uid, kp := mustVLESSKeypairAndUUID(t)
		decOpts, encOpts := makeVLESSEncConfigs(kp, vlessenc.XorRandom, "", "")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		scope := adapter.NewScope(ctx, logger.NOP())
		defer scope.Close()

		in, err := NewInbound(ctx, vlessEncEchoRouter{}, logger.NOP(), "vless-auto-tls", option.VLESSInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
				ListenPort: 0,
			},
			Users:      []option.VLESSUser{{UUID: uid}},
			Decryption: decOpts,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &option.InboundTLSOptions{
					Enabled:  true,
					Insecure: true,
				},
			},
		})
		require.NoError(t, err)
		require.NoError(t, in.Start(adapter.StartStateStart, scope))

		inAddr := in.(*Inbound).listener.TCPListener().Addr().(*net.TCPAddr)
		out, err := NewOutbound(ctx, nil, logger.NOP(), "vless-auto-tls-out", option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "127.0.0.1",
				ServerPort: uint16(inAddr.Port),
			},
			UUID:       uid,
			Encryption: encOpts,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: "auto-self.example.com",
					Insecure:   true,
				},
			},
		})
		require.NoError(t, err)
		require.NoError(t, out.(*Outbound).Start(adapter.StartStateInitialize, scope))

		assertVLESSOutboundEcho(t, out, []byte("auto-self-signed-1rtt"), []byte("auto-self-signed-0rtt"))
	})

	t.Run("pinned_self_signed_spki_sha256", func(t *testing.T) {
		t.Parallel()
		uid, kp := mustVLESSKeypairAndUUID(t)
		decOpts, encOpts := makeVLESSEncConfigs(kp, vlessenc.XorRandom, "", "")
		certPEM, keyPEM, pin := certPEMPairFromStrings(t)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		scope := adapter.NewScope(ctx, logger.NOP())
		defer scope.Close()

		in, err := NewInbound(ctx, vlessEncEchoRouter{}, logger.NOP(), "vless-pinned-tls", option.VLESSInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
				ListenPort: 0,
			},
			Users:      []option.VLESSUser{{UUID: uid}},
			Decryption: decOpts,
			InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
				TLS: &option.InboundTLSOptions{
					Enabled:     true,
					ServerName:  "localhost",
					Certificate: badoption.Listable[string]{certPEM},
					Key:         badoption.Listable[string]{keyPEM},
				},
			},
		})
		require.NoError(t, err)
		require.NoError(t, in.Start(adapter.StartStateStart, scope))
		inAddr := in.(*Inbound).listener.TCPListener().Addr().(*net.TCPAddr)

		goodOut, err := NewOutbound(ctx, nil, logger.NOP(), "vless-pinned-ok", option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "127.0.0.1",
				ServerPort: uint16(inAddr.Port),
			},
			UUID:       uid,
			Encryption: encOpts,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:                    true,
					ServerName:                 "localhost",
					CertificatePublicKeySHA256: badoption.Listable[[]byte]{pin},
				},
			},
		})
		require.NoError(t, err)
		require.NoError(t, goodOut.(*Outbound).Start(adapter.StartStateInitialize, scope))
		assertVLESSOutboundEcho(t, goodOut, []byte("pinned-spki-1rtt"), []byte("pinned-spki-0rtt"))

		wrongPin := make([]byte, 32)
		badOut, err := NewOutbound(ctx, nil, logger.NOP(), "vless-pinned-bad", option.VLESSOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     "127.0.0.1",
				ServerPort: uint16(inAddr.Port),
			},
			UUID:       uid,
			Encryption: encOpts,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:                    true,
					ServerName:                 "localhost",
					CertificatePublicKeySHA256: badoption.Listable[[]byte]{wrongPin},
				},
			},
		})
		require.NoError(t, err)
		dCtx, dCancel := context.WithTimeout(ctx, 5*time.Second)
		defer dCancel()
		badConn, err := badOut.(N.Dialer).DialContext(dCtx, N.NetworkTCP, M.ParseSocksaddrHostPort("echo.local", 9000))
		if err == nil {
			_ = badConn.Close()
		}
		require.Error(t, err)
	})
}

func runShadowTLSv3VLESSEncTest(t *testing.T, utlsEnabled bool) {
	t.Helper()
	targetPort, certPEM := startLocalTLSTarget(t, "edge.example.com")
	uid, kp := mustVLESSKeypairAndUUID(t)
	decOpts, encOpts := makeVLESSEncConfigs(kp, vlessenc.XorRandom, "", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scope := adapter.NewScope(ctx, logger.NOP())
	defer scope.Close()

	vlessIn, err := NewInbound(ctx, vlessEncEchoRouter{}, logger.NOP(), "vless-in", option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
			ListenPort: 0,
		},
		Users:      []option.VLESSUser{{UUID: uid}},
		Decryption: decOpts,
	})
	require.NoError(t, err)

	stlsPort := reserveLocalTCPPort(t)
	stlsIn, err := shadowtls.NewInbound(
		ctx,
		shadowTLSDetourRouter{target: vlessIn},
		logger.NOP(),
		"stls-in",
		option.ShadowTLSInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1"))),
				ListenPort: stlsPort,
				Detour:     "vless-in",
			},
			Version: 3,
			Users: []option.ShadowTLSUser{
				{Name: "u1", Password: "stls-v3-secret-password"},
			},
			Handshake: option.ShadowTLSHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: targetPort,
				},
			},
		},
	)
	require.NoError(t, err)
	require.NoError(t, stlsIn.Start(adapter.StartStateStart, scope))

	stlsAddr := M.ParseSocksaddrHostPort("127.0.0.1", stlsPort).String()
	tapPort, getFlights := startTCPWireTap(t, stlsAddr)

	var utlsOpts *option.OutboundUTLSOptions
	if utlsEnabled {
		utlsOpts = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		}
	}
	stlsOut, err := shadowtls.NewOutbound(ctx, nil, logger.NOP(), "stls-out", option.ShadowTLSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: tapPort,
		},
		Version:  3,
		Password: "stls-v3-secret-password",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:     true,
				ServerName:  "edge.example.com",
				Certificate: badoption.Listable[string]{certPEM},
				UTLS:        utlsOpts,
			},
		},
	})
	require.NoError(t, err)

	outCtx := service.ContextWith[adapter.OutboundManager](ctx, &stubOutboundManager{
		outbounds: map[string]adapter.Outbound{
			"stls-out": stlsOut,
		},
	})
	vlessOut, err := NewOutbound(outCtx, nil, logger.NOP(), "vless-stls-out", option.VLESSOutboundOptions{
		DialerOptions: option.DialerOptions{
			Detour: "stls-out",
		},
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: 1,
		},
		UUID:       uid,
		Encryption: encOpts,
	})
	require.NoError(t, err)
	require.NoError(t, vlessOut.(*Outbound).Start(adapter.StartStateInitialize, scope))

	assertVLESSOutboundEcho(t, vlessOut, []byte("shadowtls-v3-1rtt"), []byte("shadowtls-v3-0rtt"))

	flights := getFlights()
	require.Len(t, flights, 2)
	for _, f := range flights {
		require.Greater(t, len(f), 5)
		// Real TLS ClientHello record header: 0x16 0x03 0x01
		require.Equal(t, []byte{0x16, 0x03, 0x01}, f[:3])
	}
}

func TestVLESSRoute1ShadowTLSv3WithVLESSEnc(t *testing.T) {
	t.Parallel()
	runShadowTLSv3VLESSEncTest(t, false)
}
