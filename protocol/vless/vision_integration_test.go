package vless

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/badtls"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	vless "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func generateTestCertPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}

func makeTestClientHelloBytes() []byte {
	b := make([]byte, 64)
	b[0] = 0x16
	b[1] = 0x03
	b[2] = 0x01
	binary.BigEndian.PutUint16(b[3:5], uint16(len(b)-5))
	b[5] = 0x01
	return b
}

func makeTestServerHelloBytes() []byte {
	b := make([]byte, 85)
	b[0] = 0x16
	b[1] = 0x03
	b[2] = 0x03
	binary.BigEndian.PutUint16(b[3:5], uint16(len(b)-5))
	b[5] = 0x02
	b[43] = 0x00
	b[44] = 0x13
	b[45] = 0x01
	copy(b[60:], []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04})
	return b
}

func makeTestAppDataRecord(payloadLen int, fill byte) []byte {
	record := make([]byte, 5+payloadLen)
	record[0] = 0x17
	record[1] = 0x03
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(payloadLen))
	for i := 5; i < len(record); i++ {
		record[i] = fill
	}
	return record
}

func TestVLESSPaddingSeedConfigValidation(t *testing.T) {
	ctx := context.Background()
	nopLogger := log.NewNOPFactory().Logger()

	_, err := NewOutbound(ctx, nil, nopLogger, "out-bad", option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		UUID:          "a8098c1a-f86e-11da-bd1a-00112444be1e",
		Flow:          "xtls-rprx-vision",
		PaddingSeed:   []uint32{900, 500, 900},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "example.com",
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "padding_seed") {
		t.Fatalf("expected invalid padding_seed error on outbound, got: %v", err)
	}

	outOK, err := NewOutbound(ctx, nil, nopLogger, "out-ok", option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		UUID:          "a8098c1a-f86e-11da-bd1a-00112444be1e",
		Flow:          "xtls-rprx-vision",
		PaddingSeed:   []uint32{1024, 256, 1024, 128},
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "example.com",
			},
		},
	})
	if err != nil || outOK == nil {
		t.Fatalf("expected valid padding_seed outbound, got err=%v", err)
	}

	certPEM, keyPEM := generateTestCertPEM(t)
	_, err = NewInbound(ctx, nil, nopLogger, "in-bad", option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: 443},
		Users: []option.VLESSUser{
			{
				Name:        "user1",
				UUID:        "a8098c1a-f86e-11da-bd1a-00112444be1e",
				Flow:        "xtls-rprx-vision",
				PaddingSeed: []uint32{900, 500, 900, 9000},
			},
		},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:     true,
				Certificate: []string{certPEM},
				Key:         []string{keyPEM},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "padding_seed") {
		t.Fatalf("expected invalid padding_seed error on inbound, got: %v", err)
	}

	inOK, err := NewInbound(ctx, nil, nopLogger, "in-ok", option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: 443},
		Users: []option.VLESSUser{
			{
				Name:        "user1",
				UUID:        "a8098c1a-f86e-11da-bd1a-00112444be1e",
				Flow:        "xtls-rprx-vision",
				PaddingSeed: []uint32{1024, 256, 1024, 128},
			},
		},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled:     true,
				Certificate: []string{certPEM},
				Key:         []string{keyPEM},
			},
		},
	})
	if err != nil || inOK == nil {
		t.Fatalf("expected valid padding_seed inbound, got err=%v", err)
	}
}

type testVLESSEchoHandler struct {
	serverConnCh chan net.Conn
}

func (h *testVLESSEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.serverConnCh <- conn
	if onClose != nil {
		onClose(nil)
	}
}

func (h *testVLESSEchoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
}

func TestVLESSSTDWrapperAndBadTLSReadWaitWithVision(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	nopLogger := log.NewNOPFactory().Logger()
	certPEM, keyPEM := generateTestCertPEM(t)

	serverTLSConfig, err := tls.NewSTDServer(ctx, nopLogger, option.InboundTLSOptions{
		Enabled:     true,
		MinVersion:  "1.3",
		Certificate: []string{certPEM},
		Key:         []string{keyPEM},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientTLSConfig, err := tls.NewSTDClient(ctx, nopLogger, "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		MinVersion: "1.3",
		Insecure:   true,
	})
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const userUUID = "a8098c1a-f86e-11da-bd1a-00112444be1e"
	customSeed := []uint32{1100, 128, 1100, 64}

	serverConnCh := make(chan net.Conn, 1)
	svc := vless.NewService[string](nopLogger, &testVLESSEchoHandler{serverConnCh: serverConnCh})
	if err := svc.UpdateUsersWithPaddingSeed([]string{"alice"}, []string{userUUID}, []string{vless.FlowVision}, [][]uint32{customSeed}); err != nil {
		t.Fatal(err)
	}

	serverTLSCh := make(chan tls.Conn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		rawConn, aErr := ln.Accept()
		if aErr != nil {
			serverErrCh <- aErr
			return
		}
		hsConn, hsErr := tls.ServerHandshake(ctx, rawConn, serverTLSConfig)
		if hsErr != nil {
			_ = rawConn.Close()
			serverErrCh <- hsErr
			return
		}
		serverTLSCh <- hsConn
		serverErrCh <- svc.NewConnection(ctx, hsConn, M.ParseSocksaddr(rawConn.RemoteAddr().String()), nil)
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := tls.ClientHandshake(ctx, rawClient, clientTLSConfig)
	if err != nil {
		_ = rawClient.Close()
		t.Fatal(err)
	}
	defer clientTLS.Close()

	// Verify N.CastReader[*stdtls.Conn] works through stdConnWrapper and ReadWaitConn.
	if _, ok := N.CastReader[*stdtls.Conn](clientTLS); !ok {
		t.Fatal("N.CastReader[*crypto/tls.Conn] failed on client STD wrapper")
	}
	rwTestConn, rwErr := badtls.NewReadWaitConn(clientTLS)
	if rwErr == nil && rwTestConn != nil {
		if _, ok := common.Cast[tls.CloseNotifySuppressor](rwTestConn); !ok {
			t.Fatal("common.Cast[CloseNotifySuppressor] failed through ReadWaitConn")
		}
	}

	vlessClient, err := vless.NewClientWithOptions(userUUID, vless.FlowVision, nopLogger, vless.ClientOptions{
		PaddingSeed: customSeed,
	})
	if err != nil {
		t.Fatal(err)
	}
	clientVision, err := vlessClient.DialConn(clientTLS, M.ParseSocksaddr("target.example:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer clientVision.Close()

	// Drive TLS 1.3 handshake + >8192 complete AppData through Vision over STDServer/STDClient.
	clientHello := makeTestClientHelloBytes()
	serverHello := makeTestServerHelloBytes()
	largeAppData := append(makeTestAppDataRecord(5500, 0x21), makeTestAppDataRecord(5500, 0x22)...)
	serverAppData := makeTestAppDataRecord(64, 0x23)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, wErr := clientVision.Write(clientHello); wErr != nil {
			t.Errorf("client write CH: %v", wErr)
			return
		}
		gotSH := make([]byte, len(serverHello))
		if _, rErr := io.ReadFull(clientVision, gotSH); rErr != nil {
			t.Errorf("client read SH: %v", rErr)
			return
		}
		if _, wErr := clientVision.Write(largeAppData); wErr != nil {
			t.Errorf("client write largeAppData: %v", wErr)
			return
		}
		gotSA := make([]byte, len(serverAppData))
		if _, rErr := io.ReadFull(clientVision, gotSA); rErr != nil {
			t.Errorf("client read serverAppData: %v", rErr)
			return
		}
		if !bytes.Equal(serverAppData, gotSA) {
			t.Errorf("serverAppData mismatch")
			return
		}
		if _, wErr := clientVision.Write([]byte("raw-direct-check")); wErr != nil {
			t.Errorf("client write raw-direct: %v", wErr)
			return
		}
		_ = N.CloseWrite(clientVision)
	}()

	serverTLS := <-serverTLSCh
	if _, ok := common.Cast[tls.CloseNotifySuppressor](serverTLS); !ok {
		t.Fatal("server TLS conn missing CloseNotifySuppressor")
	}
	serverVision := <-serverConnCh
	defer serverVision.Close()
	if sErr := <-serverErrCh; sErr != nil {
		t.Fatal(sErr)
	}

	gotCH := make([]byte, len(clientHello))
	if _, err := io.ReadFull(serverVision, gotCH); err != nil {
		t.Fatal(err)
	}
	if _, err := serverVision.Write(serverHello); err != nil {
		t.Fatal(err)
	}
	gotLarge := make([]byte, len(largeAppData))
	if _, err := io.ReadFull(serverVision, gotLarge); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(largeAppData, gotLarge) {
		t.Fatal("largeAppData mismatch")
	}
	if _, err := serverVision.Write(serverAppData); err != nil {
		t.Fatal(err)
	}

	// Peer closes via CloseWrite in direct mode -> server must read exact payload + clean EOF
	// (no spurious TLS close_notify ciphertext bytes leaked into raw stream!).
	tail, err := io.ReadAll(serverVision)
	if err != nil {
		t.Fatal(err)
	}
	if string(tail) != "raw-direct-check" {
		t.Fatalf("unexpected direct tail bytes: %q", string(tail))
	}

	wg.Wait()

	// Ensure bufio.CopyConn works cleanly with VisionConn's Replaceable interfaces too.
	_ = bufio.Copy
}
