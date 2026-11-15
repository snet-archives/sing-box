package dialermask_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/dialermask"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestMaskOptionsJSONAndSchemaValidation(t *testing.T) {
	t.Parallel()

	rawJSON := `[
		{"type":"fragment","packet":true,"record":true,"length":"5-15","interval":"1ms-3ms"},
		{"type":"noise","count":3,"min_size":32,"max_size":64,"interval":"2ms"},
		{"type":"salamander","password":"secret-password"},
		{"type":"udphop","ports":["20001-20003","20005"],"interval":"5s","interval_max":"10s"}
	]`

	var masks []option.MaskOptions
	if err := json.Unmarshal([]byte(rawJSON), &masks); err != nil {
		t.Fatalf("unmarshal masks: %v", err)
	}
	if len(masks) != 4 {
		t.Fatalf("expected 4 masks, got %d", len(masks))
	}

	reEncoded, err := json.Marshal(masks)
	if err != nil {
		t.Fatalf("marshal masks: %v", err)
	}
	var roundTrip []option.MaskOptions
	if err := json.Unmarshal(reEncoded, &roundTrip); err != nil {
		t.Fatalf("re-unmarshal masks: %v", err)
	}

	pipeline, err := dialermask.ParseMaskOptions(roundTrip)
	if err != nil {
		t.Fatalf("ParseMaskOptions valid config failed: %v", err)
	}
	if !pipeline.HasTCPMasks() || !pipeline.HasUDPMasks() || !pipeline.HasUDPHop() {
		t.Fatalf("unexpected pipeline capabilities: tcp=%v udp=%v hop=%v",
			pipeline.HasTCPMasks(), pipeline.HasUDPMasks(), pipeline.HasUDPHop())
	}
	if wantPorts := []uint16{20001, 20002, 20003, 20005}; !slices.Equal(pipeline.UDPHopPorts(), wantPorts) {
		t.Fatalf("hop ports = %v, want %v", pipeline.UDPHopPorts(), wantPorts)
	}

	if _, err := schema.Generate(context.Background(), reflect.TypeFor[option.MaskOptions]()); err != nil {
		t.Fatalf("DescribeSchema MaskOptions failed: %v", err)
	}

	falseVal := false
	invalidCases := []struct {
		name  string
		masks []option.MaskOptions
	}{
		{
			name: "fragment neither packet nor record",
			masks: []option.MaskOptions{{
				Type:            option.MaskTypeFragment,
				FragmentOptions: option.MaskFragmentOptions{Packet: &falseVal, Record: false},
			}},
		},
		{
			name: "fragment bad length range",
			masks: []option.MaskOptions{{
				Type:            option.MaskTypeFragment,
				FragmentOptions: option.MaskFragmentOptions{Length: "10-5"},
			}},
		},
		{
			name: "noise negative min size",
			masks: []option.MaskOptions{{
				Type:         option.MaskTypeNoise,
				NoiseOptions: option.MaskNoiseOptions{MinSize: -1},
			}},
		},
		{
			name: "salamander empty password",
			masks: []option.MaskOptions{{
				Type: option.MaskTypeSalamander,
			}},
		},
		{
			name: "udphop interval exceeds interval_max",
			masks: []option.MaskOptions{{
				Type: option.MaskTypeUDPHop,
				UDPHopOptions: option.MaskUDPHopOptions{
					Ports:       badoption.Listable[string]{"10000"},
					Interval:    badoption.Duration(10 * time.Second),
					IntervalMax: badoption.Duration(5 * time.Second),
				},
			}},
		},
		{
			name: "duplicate udphop",
			masks: []option.MaskOptions{
				{
					Type:          option.MaskTypeUDPHop,
					UDPHopOptions: option.MaskUDPHopOptions{Ports: badoption.Listable[string]{"10000"}},
				},
				{
					Type:          option.MaskTypeUDPHop,
					UDPHopOptions: option.MaskUDPHopOptions{Ports: badoption.Listable[string]{"10001"}},
				},
			},
		},
		{
			name: "unknown mask type",
			masks: []option.MaskOptions{{
				Type: "nonexistent",
			}},
		},
	}

	for _, tc := range invalidCases {
		if _, err := dialermask.ParseMaskOptions(tc.masks); err == nil {
			t.Errorf("%s: expected ParseMaskOptions error, got nil", tc.name)
		}
	}
}

func TestTCPFragmentMaskNonTLSAndUnwrapping(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	maskedLn, err := dialermask.WrapTCPListener(context.Background(), ln, []option.MaskOptions{{
		Type: option.MaskTypeFragment,
		FragmentOptions: option.MaskFragmentOptions{
			Length: "4-4",
		},
	}})
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	defer maskedLn.Close()

	if u, ok := maskedLn.(common.WithUpstream); !ok || u.Upstream() != ln {
		t.Fatalf("masked listener Upstream mismatch")
	}

	payload := []byte("0123456789abcdef") // non-TLS 16-byte payload
	serverDone := make(chan []byte, 1)
	go func() {
		conn, acceptErr := maskedLn.Accept()
		if acceptErr != nil {
			close(serverDone)
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		serverDone <- data
	}()

	rawConn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := dialermask.ParseMaskOptions([]option.MaskOptions{{
		Type: option.MaskTypeFragment,
		FragmentOptions: option.MaskFragmentOptions{
			Length: "3-5",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	maskedConn := pipeline.WrapTCPConn(context.Background(), rawConn)
	defer maskedConn.Close()

	readerWithUp, ok := maskedConn.(N.ReaderWithUpstream)
	if !ok || !readerWithUp.ReaderReplaceable() {
		t.Fatalf("expected fragment conn ReaderReplaceable() == true")
	}
	writerWithUp, ok := maskedConn.(N.WriterWithUpstream)
	if !ok || writerWithUp.WriterReplaceable() {
		t.Fatalf("expected fragment conn WriterReplaceable() == false before first write")
	}
	if unwrapped, ok := N.CastReader[*net.TCPConn](maskedConn); !ok || unwrapped == nil {
		t.Fatalf("expected N.CastReader to reach underlying *net.TCPConn")
	}

	if _, err := maskedConn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if !writerWithUp.WriterReplaceable() {
		t.Fatalf("expected fragment conn WriterReplaceable() == true after first write")
	}
	if _, isRaw := maskedConn.(*net.TCPConn); isRaw {
		t.Fatalf("expected wrapped conn, got raw *net.TCPConn")
	}
	if err := maskedConn.Close(); err != nil {
		t.Fatal(err)
	}

	received := <-serverDone
	if !bytes.Equal(received, payload) {
		t.Fatalf("received %q, want %q", received, payload)
	}
}

func TestUDPNoiseAndSalamanderMasks(t *testing.T) {
	t.Parallel()

	// 1. Noise burst on connected UDP conn.
	serverSock, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverSock.Close()

	clientSock, err := net.Dial("udp4", serverSock.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientSock.Close()

	noisePipeline, err := dialermask.ParseMaskOptions([]option.MaskOptions{{
		Type: option.MaskTypeNoise,
		NoiseOptions: option.MaskNoiseOptions{
			Count:   3,
			MinSize: 13,
			MaxSize: 13,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	noiseConn := noisePipeline.WrapUDPConn(clientSock)
	if ew, ok := noiseConn.(N.EarlyWriter); !ok || !ew.NeedHandshakeForWrite() {
		t.Fatalf("expected noiseConn NeedHandshakeForWrite() == true before first write")
	}
	if wu, ok := noiseConn.(N.WriterWithUpstream); !ok || wu.WriterReplaceable() {
		t.Fatalf("expected noiseConn WriterReplaceable() == false before burst")
	}

	realMsg := []byte("real-udp-payload")
	if _, err := noiseConn.Write(realMsg); err != nil {
		t.Fatal(err)
	}
	if ew := noiseConn.(N.EarlyWriter); ew.NeedHandshakeForWrite() {
		t.Fatalf("expected noiseConn NeedHandshakeForWrite() == false after burst")
	}
	if wu := noiseConn.(N.WriterWithUpstream); !wu.WriterReplaceable() {
		t.Fatalf("expected noiseConn WriterReplaceable() == true after burst")
	}

	var noiseCount int
	var gotReal bool
	pktBuf := make([]byte, 2048)
	_ = serverSock.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 4; i++ {
		n, _, err := serverSock.ReadFrom(pktBuf)
		if err != nil {
			t.Fatalf("read pkt %d: %v", i, err)
		}
		if n == 13 {
			noiseCount++
		} else if bytes.Equal(pktBuf[:n], realMsg) {
			gotReal = true
		}
	}
	if noiseCount != 3 || !gotReal {
		t.Fatalf("noiseCount=%d gotReal=%v, want 3 noise + real payload", noiseCount, gotReal)
	}

	// 2. Salamander obfuscation roundtrip (PacketConn + non-replaceable checks).
	srvRaw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvRaw.Close()
	cliRaw, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cliRaw.Close()

	salPipeline, err := dialermask.ParseMaskOptions([]option.MaskOptions{{
		Type:              option.MaskTypeSalamander,
		SalamanderOptions: option.MaskSalamanderOptions{Password: "test-salamander-key"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	srvSal := salPipeline.WrapPacketConn(srvRaw, false)
	cliSal := salPipeline.WrapPacketConn(cliRaw, true)

	if ru, ok := cliSal.(N.ReaderWithUpstream); !ok || ru.ReaderReplaceable() {
		t.Fatalf("salamander must NOT be ReaderReplaceable")
	}
	if wu, ok := cliSal.(N.WriterWithUpstream); !ok || wu.WriterReplaceable() {
		t.Fatalf("salamander must NOT be WriterReplaceable")
	}

	ping := []byte("hello-salamander-mask")
	if _, err := cliSal.WriteTo(ping, srvRaw.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = srvSal.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, srcAddr, err := srvSal.ReadFrom(pktBuf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pktBuf[:n], ping) {
		t.Fatalf("server decoded %q, want %q", pktBuf[:n], ping)
	}
	pong := []byte("pong-salamander")
	if _, err := srvSal.WriteTo(pong, srcAddr); err != nil {
		t.Fatal(err)
	}
	_ = cliSal.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = cliSal.ReadFrom(pktBuf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pktBuf[:n], pong) {
		t.Fatalf("client decoded %q, want %q", pktBuf[:n], pong)
	}
}

func TestUDPHopServerPacketConnAndDeadlineRecovery(t *testing.T) {
	t.Parallel()

	// Allocate two distinct free UDP ports on 127.0.0.1.
	allocPort := func() uint16 {
		c, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return uint16(c.LocalAddr().(*net.UDPAddr).Port)
	}
	p1, p2 := allocPort(), allocPort()
	for p2 == p1 {
		p2 = allocPort()
	}

	hopSrv, err := dialermask.NewHopServerPacketConn([]uint16{p1, p2}, func(port uint16) (net.PacketConn, error) {
		return net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	})
	if err != nil {
		t.Fatalf("NewHopServerPacketConn: %v", err)
	}
	defer hopSrv.Close()

	// Verify ReadFrom deadline expiration does NOT kill reader goroutines, and subsequent packets arrive cleanly.
	_ = hopSrv.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	readBuf := make([]byte, 2048)
	if _, _, err := hopSrv.ReadFrom(readBuf); !errors.Is(err, context.DeadlineExceeded) && !netTimeout(err) {
		t.Fatalf("expected timeout error, got %v", err)
	}
	_ = hopSrv.SetReadDeadline(time.Time{})

	// Client sends to port p1, then hops to port p2, and server replies route back accurately.
	cli, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	for _, targetPort := range []uint16{p1, p2} {
		dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(targetPort)}
		msg := []byte(fmt.Sprintf("hop-msg-%d", targetPort))
		if _, err := cli.WriteTo(msg, dst); err != nil {
			t.Fatal(err)
		}
		_ = hopSrv.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, peerAddr, err := hopSrv.ReadFrom(readBuf)
		if err != nil {
			t.Fatalf("hopSrv.ReadFrom port %d: %v", targetPort, err)
		}
		if !bytes.Equal(readBuf[:n], msg) {
			t.Fatalf("got %q, want %q", readBuf[:n], msg)
		}
		reply := []byte(fmt.Sprintf("reply-%d", targetPort))
		if _, err := hopSrv.WriteTo(reply, peerAddr); err != nil {
			t.Fatalf("hopSrv.WriteTo port %d: %v", targetPort, err)
		}
		_ = cli.SetReadDeadline(time.Now().Add(2 * time.Second))
		rn, raddr, err := cli.ReadFrom(readBuf)
		if err != nil {
			t.Fatalf("cli.ReadFrom port %d: %v", targetPort, err)
		}
		if !bytes.Equal(readBuf[:rn], reply) {
			t.Fatalf("client got %q, want %q", readBuf[:rn], reply)
		}
		if gotPort := uint16(raddr.(*net.UDPAddr).Port); gotPort != targetPort {
			t.Fatalf("server replied from port %d, want active peer port %d", gotPort, targetPort)
		}
	}
}

type stubUDPHandler struct {
	mu      sync.Mutex
	packets [][]byte
	notify  chan struct{}
	writer  N.PacketWriter
}

func (h *stubUDPHandler) NewPacket(buffer *buf.Buffer, source M.Socksaddr) {
	data := slices.Clone(buffer.Bytes())
	buffer.Release()
	h.mu.Lock()
	h.packets = append(h.packets, data)
	h.mu.Unlock()
	select {
	case h.notify <- struct{}{}:
	default:
	}
	if h.writer != nil {
		out := buf.NewPacket()
		_, _ = out.Write(data)
		_ = h.writer.WritePacket(out, source)
	}
}

func TestListenerAndDialerIntegrationWithMasks(t *testing.T) {
	t.Parallel()

	// Allocate free ports for UDP + TCP.
	allocFree := func(network string) uint16 {
		if network == "tcp4" {
			l, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			return uint16(l.Addr().(*net.TCPAddr).Port)
		}
		p, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		return uint16(p.LocalAddr().(*net.UDPAddr).Port)
	}

	udpPort1 := allocFree("udp4")
	udpPort2 := allocFree("udp4")
	for udpPort2 == udpPort1 {
		udpPort2 = allocFree("udp4")
	}
	tcpPort := allocFree("tcp4")

	listenMasks := []option.MaskOptions{
		{
			Type: option.MaskTypeFragment,
			FragmentOptions: option.MaskFragmentOptions{
				Length: "3-5",
			},
		},
		{
			Type:              option.MaskTypeSalamander,
			SalamanderOptions: option.MaskSalamanderOptions{Password: "integration-key"},
		},
		{
			Type: option.MaskTypeUDPHop,
			UDPHopOptions: option.MaskUDPHopOptions{
				Ports:    badoption.Listable[string]{fmt.Sprintf("%d", udpPort2)},
				Interval: badoption.Duration(50 * time.Millisecond),
			},
		},
	}

	var acceptedConns sync.WaitGroup
	tcpHandler := &stubTCPHandler{wg: &acceptedConns}
	acceptedConns.Add(1)

	udpHandler := &stubUDPHandler{notify: make(chan struct{}, 8)}
	addr4 := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	tcpListener := listener.New(listener.Options{
		Context: context.Background(),
		Logger:  logger.NOP(),
		Network: []string{N.NetworkTCP},
		Listen: option.ListenOptions{
			Listen:     &addr4,
			ListenPort: tcpPort,
			Masks:      listenMasks[:1],
		},
		ConnectionHandler: tcpHandler,
	})
	if err := tcpListener.Start(); err != nil {
		t.Fatalf("tcpListener.Start: %v", err)
	}
	defer tcpListener.Close()

	udpListener := listener.New(listener.Options{
		Context: context.Background(),
		Logger:  logger.NOP(),
		Network: []string{N.NetworkUDP},
		Listen: option.ListenOptions{
			Listen:     &addr4,
			ListenPort: udpPort1,
			Masks:      listenMasks[1:],
		},
		PacketHandler: udpHandler,
	})
	udpHandler.writer = udpListener.PacketWriter()
	if err := udpListener.Start(); err != nil {
		t.Fatalf("udpListener.Start: %v", err)
	}
	defer udpListener.Close()

	// Verify dialer.NewWithOptions preserves ParallelInterfaceDialer + Upstream when Masks are configured.
	clientDialer, err := dialer.NewWithOptions(dialer.Options{
		Context: context.Background(),
		Options: option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{
				Masks: []option.MaskOptions{
					{
						Type: option.MaskTypeFragment,
						FragmentOptions: option.MaskFragmentOptions{
							Length: "3-5",
						},
					},
					{
						Type:              option.MaskTypeSalamander,
						SalamanderOptions: option.MaskSalamanderOptions{Password: "integration-key"},
					},
					{
						Type: option.MaskTypeUDPHop,
						UDPHopOptions: option.MaskUDPHopOptions{
							Ports:    badoption.Listable[string]{fmt.Sprintf("%d", udpPort1), fmt.Sprintf("%d", udpPort2)},
							Interval: badoption.Duration(25 * time.Millisecond),
						},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("dialer.NewWithOptions: %v", err)
	}
	if _, ok := clientDialer.(dialer.ParallelInterfaceDialer); !ok {
		t.Fatalf("wrapped dialer lost ParallelInterfaceDialer interface")
	}

	// Test TCP through masked Listener + masked Dialer.
	dstTCP := M.ParseSocksaddrHostPort("127.0.0.1", tcpPort)
	tcpConn, err := clientDialer.DialContext(context.Background(), N.NetworkTCP, dstTCP)
	if err != nil {
		t.Fatalf("DialContext TCP: %v", err)
	}
	tcpPayload := []byte("masked-tcp-roundtrip")
	if _, err := tcpConn.Write(tcpPayload); err != nil {
		t.Fatal(err)
	}
	echoBuf := make([]byte, len(tcpPayload))
	if _, err := io.ReadFull(tcpConn, echoBuf); err != nil {
		t.Fatalf("tcp ReadFull: %v", err)
	}
	if !bytes.Equal(echoBuf, tcpPayload) {
		t.Fatalf("tcp echo = %q, want %q", echoBuf, tcpPayload)
	}
	tcpConn.Close()
	acceptedConns.Wait()

	// Test UDP (salamander + udphop) through masked Listener + masked Dialer.
	dstUDP := M.ParseSocksaddrHostPort("127.0.0.1", udpPort1)
	pc, err := clientDialer.ListenPacket(context.Background(), dstUDP)
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	udpMsg := []byte("masked-udp-echo-via-listener")
	if _, err := pc.WriteTo(udpMsg, dstUDP.UDPAddr()); err != nil {
		t.Fatalf("pc.WriteTo: %v", err)
	}
	select {
	case <-udpHandler.notify:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for masked UDP packet on listener")
	}
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	respBuf := make([]byte, 2048)
	n, _, err := pc.ReadFrom(respBuf)
	if err != nil {
		t.Fatalf("pc.ReadFrom: %v", err)
	}
	if !bytes.Equal(respBuf[:n], udpMsg) {
		t.Fatalf("udp echo = %q, want %q", respBuf[:n], udpMsg)
	}

	// Also verify DialContext("udp", ...) works across multiple hop intervals.
	udpStream, err := clientDialer.DialContext(context.Background(), N.NetworkUDP, dstUDP)
	if err != nil {
		t.Fatalf("DialContext UDP: %v", err)
	}
	defer udpStream.Close()
	for i := 0; i < 4; i++ {
		msg := []byte(fmt.Sprintf("hop-stream-%d", i))
		if _, err := udpStream.Write(msg); err != nil {
			t.Fatalf("udpStream.Write %d: %v", i, err)
		}
		_ = udpStream.SetReadDeadline(time.Now().Add(2 * time.Second))
		rn, err := udpStream.Read(respBuf)
		if err != nil {
			t.Fatalf("udpStream.Read %d: %v", i, err)
		}
		if !bytes.Equal(respBuf[:rn], msg) {
			t.Fatalf("udpStream %d = %q, want %q", i, respBuf[:rn], msg)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

type stubTCPHandler struct {
	wg *sync.WaitGroup
}

func (h *stubTCPHandler) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	defer func() {
		conn.Close()
		if onClose != nil {
			onClose(nil)
		}
		h.wg.Done()
	}()
	_, _ = io.Copy(conn, conn)
}

func netTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
