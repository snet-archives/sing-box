package tls_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	sTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func generateTestCertPEM(t *testing.T, dnsName string) ([]byte, tls.Certificate, [32]byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM, cert, sha256.Sum256(der)
}

func startLocalTLSServer(t *testing.T, serverCert tls.Certificate) (string, <-chan string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	sniCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		defer conn.Close()
		var sawSNI string
		srv := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				sawSNI = chi.ServerName
				return nil, nil
			},
		})
		err := srv.Handshake()
		sniCh <- sawSNI
		errCh <- err
	}()
	return ln.Addr().String(), sniCh, errCh
}

func TestSTDClientDisableSNIUsesVerifyPeerCertificateAndChromeParrotCompatible(t *testing.T) {
	certPEM, serverCert, certHash := generateTestCertPEM(t, "internal.example")

	clientCfg, err := sTLS.NewSTDClient(context.Background(), logger.NOP(), "127.0.0.1", option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "internal.example",
		DisableSNI:  true,
		Certificate: []string{string(certPEM)},
	})
	if err != nil {
		t.Fatal(err)
	}
	stdCfg, err := clientCfg.STDConfig()
	if err != nil {
		t.Fatal(err)
	}
	if stdCfg.VerifyConnection != nil {
		t.Fatal("VerifyConnection must be nil so quic-go ChromeParrot uTLS conversion succeeds")
	}
	if stdCfg.VerifyPeerCertificate == nil {
		t.Fatal("expected VerifyPeerCertificate to verify server_name when disable_sni is true")
	}
	if stdCfg.ServerName != "" {
		t.Fatalf("expected empty wire ServerName, got %q", stdCfg.ServerName)
	}

	// Verify successful TLS handshake without SNI on the wire
	addr, sniCh, errCh := startLocalTLSServer(t, serverCert)
	rawConn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tlsConn, err := clientCfg.Client(rawConn)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	_ = tlsConn.Close()
	if sawSNI := <-sniCh; sawSNI != "" {
		t.Fatalf("expected empty SNI on wire, server saw %q", sawSNI)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server handshake error: %v", err)
	}

	// Verify SAN mismatch is rejected even with disable_sni=true
	wrongCfg, err := sTLS.NewSTDClient(context.Background(), logger.NOP(), "127.0.0.1", option.OutboundTLSOptions{
		Enabled:     true,
		ServerName:  "wrong.example",
		DisableSNI:  true,
		Certificate: []string{string(certPEM)},
	})
	if err != nil {
		t.Fatal(err)
	}
	wAddr, _, _ := startLocalTLSServer(t, serverCert)
	wRaw, err := net.DialTimeout("tcp", wAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	wConn, err := wrongCfg.Client(wRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := wConn.HandshakeContext(ctx); err == nil {
		t.Fatal("expected SAN mismatch rejection when disable_sni is true")
	}
	_ = wConn.Close()

	// Verify certificate pinning also works alongside disable_sni=true
	pinCfg, err := sTLS.NewSTDClient(context.Background(), logger.NOP(), "127.0.0.1", option.OutboundTLSOptions{
		Enabled:           true,
		ServerName:        "internal.example",
		DisableSNI:        true,
		CertificateSHA256: [][]byte{bytes.Clone(certHash[:])},
	})
	if err != nil {
		t.Fatal(err)
	}
	pAddr, _, pErrCh := startLocalTLSServer(t, serverCert)
	pRaw, err := net.DialTimeout("tcp", pAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pConn, err := pinCfg.Client(pRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := pConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("pinned cert + disable_sni handshake failed: %v", err)
	}
	_ = pConn.Close()
	if err := <-pErrCh; err != nil {
		t.Fatalf("pinned server handshake error: %v", err)
	}
}
