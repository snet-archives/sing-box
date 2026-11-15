package vlessenc

import (
	"bytes"
	"context"
	"io"
	"math"
	"net"
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

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	var srvConn net.Conn
	var srvErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		srvConn, srvErr = ln.Accept()
	}()

	cliConn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	<-done
	require.NoError(t, srvErr)
	t.Cleanup(func() {
		_ = cliConn.Close()
		_ = srvConn.Close()
	})
	return cliConn, srvConn
}

type spyConn struct {
	net.Conn
	mu     sync.Mutex
	reads  int
	writes []byte
}

func (c *spyConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	c.reads++
	c.mu.Unlock()
	return c.Conn.Read(p)
}

func (c *spyConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.mu.Lock()
		c.writes = append(c.writes, p[:n]...)
		c.mu.Unlock()
	}
	return n, err
}

func (c *spyConn) ReadCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

func (c *spyConn) WrittenBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.writes...)
}

func TestKeyPairValidationAndSchema(t *testing.T) {
	t.Parallel()

	kp, err := GenerateKeyPair()
	require.NoError(t, err)
	require.NotEmpty(t, kp.PrivateKey)
	require.NotEmpty(t, kp.PublicKey)
	require.NotEmpty(t, kp.MLKEM768Seed)
	require.NotEmpty(t, kp.MLKEM768EncapKey)
	require.NotEmpty(t, kp.TicketSecret)
	require.NotEmpty(t, kp.XorPSK)

	_, err = NewServer(option.VLESSDecryptionOptions{
		Enabled:      true,
		PrivateKey:   kp.PrivateKey,
		MLKEM768Seed: kp.MLKEM768Seed,
		TicketSecret: kp.TicketSecret,
		XorMode:      XorRandom,
		XorPSK:       kp.XorPSK,
	})
	require.NoError(t, err)

	_, err = NewClient(option.VLESSEncryptionOptions{
		Enabled:          true,
		PublicKey:        kp.PublicKey,
		MLKEM768EncapKey: kp.MLKEM768EncapKey,
		Mode:             ModeZeroRTT,
		XorMode:          XorRandom,
		XorPSK:           kp.XorPSK,
	})
	require.NoError(t, err)

	// Fail-fast checks
	_, err = NewServer(option.VLESSDecryptionOptions{Enabled: true, PrivateKey: "bad", MLKEM768Seed: kp.MLKEM768Seed})
	require.Error(t, err)
	_, err = NewServer(option.VLESSDecryptionOptions{Enabled: true, PrivateKey: kp.PrivateKey, MLKEM768Seed: kp.PublicKey})
	require.Error(t, err)
	_, err = NewServer(option.VLESSDecryptionOptions{Enabled: true, PrivateKey: kp.PrivateKey, MLKEM768Seed: kp.MLKEM768Seed, XorMode: "bad"})
	require.Error(t, err)
	_, err = NewServer(option.VLESSDecryptionOptions{Enabled: true, PrivateKey: kp.PrivateKey, MLKEM768Seed: kp.MLKEM768Seed, SessionMaxAge: badoption.Duration(-time.Second)})
	require.Error(t, err)

	_, err = NewClient(option.VLESSEncryptionOptions{Enabled: true, PublicKey: "bad", MLKEM768EncapKey: kp.MLKEM768EncapKey})
	require.Error(t, err)
	_, err = NewClient(option.VLESSEncryptionOptions{Enabled: true, PublicKey: kp.PublicKey, MLKEM768EncapKey: kp.PublicKey})
	require.Error(t, err)
	_, err = NewClient(option.VLESSEncryptionOptions{Enabled: true, PublicKey: kp.PublicKey, MLKEM768EncapKey: kp.MLKEM768EncapKey, Mode: "bad"})
	require.Error(t, err)

	inSchema, err := schema.Generate(context.Background(), reflect.TypeFor[option.VLESSDecryptionOptions]())
	require.NoError(t, err)
	for _, k := range []string{"private_key", "mlkem768_seed", "xor_mode", "session_max_age"} {
		require.True(t, strings.Contains(string(inSchema), k), "decryption schema missing %q", k)
	}
	outSchema, err := schema.Generate(context.Background(), reflect.TypeFor[option.VLESSEncryptionOptions]())
	require.NoError(t, err)
	for _, k := range []string{"public_key", "mlkem768_encap_key", "zero_rtt", "xor_psk"} {
		require.True(t, strings.Contains(string(outSchema), k), "encryption schema missing %q", k)
	}
}

func TestHandshake1RTTAllModesAndMultiFrame(t *testing.T) {
	t.Parallel()

	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	for _, xorMode := range []string{XorNone, XorMask, XorRandom} {
		t.Run("xor_"+xorMode, func(t *testing.T) {
			srv, err := NewServer(option.VLESSDecryptionOptions{
				Enabled:      true,
				PrivateKey:   kp.PrivateKey,
				MLKEM768Seed: kp.MLKEM768Seed,
				TicketSecret: kp.TicketSecret,
				XorMode:      xorMode,
				XorPSK:       kp.XorPSK,
			})
			require.NoError(t, err)
			cli, err := NewClient(option.VLESSEncryptionOptions{
				Enabled:          true,
				PublicKey:        kp.PublicKey,
				MLKEM768EncapKey: kp.MLKEM768EncapKey,
				Mode:             ModeNative,
				XorMode:          xorMode,
				XorPSK:           kp.XorPSK,
			})
			require.NoError(t, err)

			rawCli, rawSrv := tcpPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			errCh := make(chan error, 1)
			go func() {
				sConn, sErr := srv.ServerHandshake(ctx, rawSrv)
				if sErr != nil {
					errCh <- sErr
					return
				}
				defer sConn.Close()
				_, copyErr := io.Copy(sConn, sConn)
				errCh <- copyErr
			}()

			cConn, err := cli.ClientHandshake(ctx, rawCli)
			require.NoError(t, err)

			// Exercise multi-chunk > 16KB AEAD records + small fragmented Read buffers.
			payload := bytes.Repeat([]byte("PQ-HYBRID-FRAME-"), 4000) // 64,000 bytes
			_, err = cConn.Write(payload)
			require.NoError(t, err)

			received := make([]byte, 0, len(payload))
			tmp := make([]byte, 777)
			for len(received) < len(payload) {
				n, rErr := cConn.Read(tmp)
				require.NoError(t, rErr)
				received = append(received, tmp[:n]...)
			}
			require.Equal(t, payload, received)
			require.NoError(t, cConn.Close())
			require.NoError(t, <-errCh)
		})
	}
}

func TestHandshakeZeroRTTAndTicketExpiry(t *testing.T) {
	t.Parallel()

	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	var srvClock, cliClock atomic.Int64
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	srvClock.Store(baseTime)
	cliClock.Store(baseTime)

	srv, err := NewServer(option.VLESSDecryptionOptions{
		Enabled:       true,
		PrivateKey:    kp.PrivateKey,
		MLKEM768Seed:  kp.MLKEM768Seed,
		TicketSecret:  kp.TicketSecret,
		XorMode:       XorRandom,
		XorPSK:        kp.XorPSK,
		SessionMaxAge: badoption.Duration(200 * time.Millisecond),
	})
	require.NoError(t, err)
	srv.now = func() time.Time { return time.Unix(0, srvClock.Load()) }

	cli, err := NewClient(option.VLESSEncryptionOptions{
		Enabled:          true,
		PublicKey:        kp.PublicKey,
		MLKEM768EncapKey: kp.MLKEM768EncapKey,
		Mode:             ModeZeroRTT,
		XorMode:          XorRandom,
		XorPSK:           kp.XorPSK,
	})
	require.NoError(t, err)
	cli.now = func() time.Time { return time.Unix(0, cliClock.Load()) }

	runRoundTrip := func(msg string) (wireCli *spyConn, err error) {
		rawCli, rawSrv := tcpPair(t)
		wireCli = &spyConn{Conn: rawCli}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		srvDone := make(chan error, 1)
		go func() {
			sConn, sErr := srv.ServerHandshake(ctx, rawSrv)
			if sErr != nil {
				_ = rawSrv.Close()
				srvDone <- sErr
				return
			}
			defer sConn.Close()
			buf := make([]byte, 256)
			n, rErr := sConn.Read(buf)
			if rErr != nil {
				srvDone <- rErr
				return
			}
			_, wErr := sConn.Write(append([]byte("ack:"), buf[:n]...))
			srvDone <- wErr
		}()

		cConn, cErr := cli.ClientHandshake(ctx, wireCli)
		if cErr != nil {
			_ = wireCli.Close()
			<-srvDone
			return wireCli, cErr
		}
		_, wErr := cConn.Write([]byte(msg))
		if wErr != nil {
			_ = cConn.Close()
			<-srvDone
			return wireCli, wErr
		}
		resp := make([]byte, len("ack:")+len(msg))
		_, rErr := io.ReadFull(cConn, resp)
		_ = cConn.Close()
		sErr := <-srvDone
		if rErr != nil {
			return wireCli, rErr
		}
		if sErr != nil {
			return wireCli, sErr
		}
		require.Equal(t, "ack:"+msg, string(resp))
		return wireCli, nil
	}

	// Conn 1: 1-RTT initial handshake reads ServerHello and caches 0-RTT ticket.
	wire1, err := runRoundTrip("hello-1rtt")
	require.NoError(t, err)
	require.Greater(t, wire1.ReadCount(), 0)

	// Conn 2: True 0-RTT! ServerHello must NOT be read before ClientHandshake + Write complete.
	rawCli2, rawSrv2 := tcpPair(t)
	wire2 := &spyConn{Conn: rawCli2}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	srvErrCh := make(chan error, 1)
	go func() {
		sConn, sErr := srv.ServerHandshake(ctx2, rawSrv2)
		if sErr != nil {
			srvErrCh <- sErr
			return
		}
		defer sConn.Close()
		buf := make([]byte, 64)
		n, rErr := sConn.Read(buf)
		if rErr != nil {
			srvErrCh <- rErr
			return
		}
		_, wErr := sConn.Write(append([]byte("ack:"), buf[:n]...))
		srvErrCh <- wErr
	}()

	cConn2, err := cli.ClientHandshake(ctx2, wire2)
	require.NoError(t, err)
	require.Equal(t, 0, wire2.ReadCount(), "0-RTT handshake must return before reading ServerHello")
	_, err = cConn2.Write([]byte("hello-0rtt"))
	require.NoError(t, err)
	require.Equal(t, 0, wire2.ReadCount(), "0-RTT first data write must occur before reading ServerHello")

	got2 := make([]byte, len("ack:hello-0rtt"))
	_, err = io.ReadFull(cConn2, got2)
	require.NoError(t, err)
	require.Equal(t, "ack:hello-0rtt", string(got2))
	require.NoError(t, cConn2.Close())
	require.NoError(t, <-srvErrCh)

	// Advance server clock past SessionMaxAge (200ms) while client still thinks ticket is valid:
	// Conn 3 attempts 0-RTT with expired ticket -> server rejects -> client invalidates cache.
	srvClock.Add(int64(300 * time.Millisecond))
	_, err = runRoundTrip("stale-0rtt")
	require.Error(t, err)

	// Align clocks: Conn 4 automatically recovers via fresh 1-RTT handshake after cache invalidation.
	cliClock.Store(srvClock.Load())
	wire4, err := runRoundTrip("recovered-1rtt")
	require.NoError(t, err)
	require.Greater(t, wire4.ReadCount(), 0)

	// Advance both clocks past SessionMaxAge: client proactively sees local expiry and falls back directly to 1-RTT.
	bothAdvance := int64(300 * time.Millisecond)
	srvClock.Add(bothAdvance)
	cliClock.Add(bothAdvance)
	wire5, err := runRoundTrip("proactive-1rtt")
	require.NoError(t, err)
	require.Greater(t, wire5.ReadCount(), 0)
}

func TestZeroRTTReplayRejection(t *testing.T) {
	t.Parallel()

	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	srv, err := NewServer(option.VLESSDecryptionOptions{
		Enabled:      true,
		PrivateKey:   kp.PrivateKey,
		MLKEM768Seed: kp.MLKEM768Seed,
		TicketSecret: kp.TicketSecret,
		XorMode:      XorMask,
		XorPSK:       kp.XorPSK,
	})
	require.NoError(t, err)

	cli, err := NewClient(option.VLESSEncryptionOptions{
		Enabled:          true,
		PublicKey:        kp.PublicKey,
		MLKEM768EncapKey: kp.MLKEM768EncapKey,
		Mode:             ModeZeroRTT,
		XorMode:          XorMask,
		XorPSK:           kp.XorPSK,
	})
	require.NoError(t, err)

	// Seed 0-RTT ticket with 1-RTT connection.
	{
		rc, rs := tcpPair(t)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		done := make(chan error, 1)
		go func() {
			sc, sErr := srv.ServerHandshake(ctx, rs)
			if sErr == nil {
				_ = sc.Close()
			}
			done <- sErr
		}()
		cc, err := cli.ClientHandshake(ctx, rc)
		cancel()
		require.NoError(t, err)
		_ = cc.Close()
		require.NoError(t, <-done)
	}

	// Capture exact bytes of a valid 0-RTT ClientHello + data flight.
	rc, rs := tcpPair(t)
	wireCapture := &spyConn{Conn: rc}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done1 := make(chan error, 1)
	go func() {
		sc, sErr := srv.ServerHandshake(ctx, rs)
		if sErr != nil {
			done1 <- sErr
			return
		}
		defer sc.Close()
		buf := make([]byte, 32)
		_, rErr := io.ReadFull(sc, buf[:4])
		done1 <- rErr
	}()

	cc, err := cli.ClientHandshake(ctx, wireCapture)
	require.NoError(t, err)
	_, err = cc.Write([]byte("ping"))
	require.NoError(t, err)
	require.NoError(t, <-done1)
	_ = cc.Close()

	captured := wireCapture.WrittenBytes()
	require.NotEmpty(t, captured)

	// Replay captured ClientHello bytes to the same server: must be rejected as replay!
	replayCli, replaySrv := tcpPair(t)
	go func() {
		_, _ = replayCli.Write(captured)
		_ = replayCli.Close()
	}()
	_, err = srv.ServerHandshake(ctx, replaySrv)
	require.ErrorIs(t, err, ErrReplayRejected)
}

func TestWrongKeysAndTamperRejection(t *testing.T) {
	t.Parallel()

	kp1, err := GenerateKeyPair()
	require.NoError(t, err)
	kp2, err := GenerateKeyPair()
	require.NoError(t, err)

	srv, err := NewServer(option.VLESSDecryptionOptions{
		Enabled:      true,
		PrivateKey:   kp1.PrivateKey,
		MLKEM768Seed: kp1.MLKEM768Seed,
		XorMode:      XorMask,
		XorPSK:       kp1.XorPSK,
	})
	require.NoError(t, err)

	wrongCases := []struct {
		name string
		opt  option.VLESSEncryptionOptions
	}{
		{
			name: "wrong X25519 key",
			opt: option.VLESSEncryptionOptions{
				Enabled: true, PublicKey: kp2.PublicKey, MLKEM768EncapKey: kp1.MLKEM768EncapKey, XorMode: XorMask, XorPSK: kp1.XorPSK,
			},
		},
		{
			name: "wrong MLKEM key",
			opt: option.VLESSEncryptionOptions{
				Enabled: true, PublicKey: kp1.PublicKey, MLKEM768EncapKey: kp2.MLKEM768EncapKey, XorMode: XorMask, XorPSK: kp1.XorPSK,
			},
		},
		{
			name: "wrong XorPSK",
			opt: option.VLESSEncryptionOptions{
				Enabled: true, PublicKey: kp1.PublicKey, MLKEM768EncapKey: kp1.MLKEM768EncapKey, XorMode: XorMask, XorPSK: kp2.XorPSK,
			},
		},
		{
			name: "wrong XorMode",
			opt: option.VLESSEncryptionOptions{
				Enabled: true, PublicKey: kp1.PublicKey, MLKEM768EncapKey: kp1.MLKEM768EncapKey, XorMode: XorNone,
			},
		},
	}

	for _, tc := range wrongCases {
		t.Run(tc.name, func(t *testing.T) {
			cli, err := NewClient(tc.opt)
			require.NoError(t, err)
			rc, rs := tcpPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			go func() {
				sc, sErr := srv.ServerHandshake(ctx, rs)
				if sErr == nil {
					_, _ = sc.Write([]byte("should-never-authenticate"))
					_ = sc.Close()
				} else {
					_ = rs.Close()
				}
			}()
			cc, err := cli.ClientHandshake(ctx, rc)
			if err == nil {
				buf := make([]byte, 32)
				_, err = cc.Read(buf)
				_ = cc.Close()
			}
			require.Error(t, err)
		})
	}
}

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var entropy float64
	total := float64(len(data))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func TestXorRandomEntropyAndLengthDiversity(t *testing.T) {
	t.Parallel()

	kp, err := GenerateKeyPair()
	require.NoError(t, err)

	srv, err := NewServer(option.VLESSDecryptionOptions{
		Enabled:      true,
		PrivateKey:   kp.PrivateKey,
		MLKEM768Seed: kp.MLKEM768Seed,
		XorMode:      XorRandom,
		XorPSK:       kp.XorPSK,
	})
	require.NoError(t, err)

	cli, err := NewClient(option.VLESSEncryptionOptions{
		Enabled:          true,
		PublicKey:        kp.PublicKey,
		MLKEM768EncapKey: kp.MLKEM768EncapKey,
		Mode:             ModeNative,
		XorMode:          XorRandom,
		XorPSK:           kp.XorPSK,
	})
	require.NoError(t, err)

	lengths := make(map[int]struct{})
	var allClientHellos []byte
	for range 12 {
		rc, rs := tcpPair(t)
		spy := &spyConn{Conn: rc}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		done := make(chan struct{})
		go func() {
			defer close(done)
			sc, sErr := srv.ServerHandshake(ctx, rs)
			if sErr == nil {
				_ = sc.Close()
			}
		}()
		cc, cErr := cli.ClientHandshake(ctx, spy)
		cancel()
		require.NoError(t, cErr)
		_ = cc.Close()
		<-done

		wire := spy.WrittenBytes()
		lengths[len(wire)] = struct{}{}
		allClientHellos = append(allClientHellos, wire...)
	}

	// Variable random padding ensures distinct ClientHello lengths across connections.
	require.GreaterOrEqual(t, len(lengths), 4, "expected varied ClientHello packet sizes in xor_mode=random")
	// Masked + padded KEM handshakes must exceed 7.7 bits/byte Shannon entropy.
	entropy := shannonEntropy(allClientHellos)
	require.Greater(t, entropy, 7.7)
}
