package tls_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	sTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
)

func TestSTDServerStrictSNI(t *testing.T) {
	priv, pub, err := sTLS.GenerateCertificate(nil, nil, time.Now, "allowed.example.com", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("GenerateCertificate: %v", err)
	}

	makeServer := func(strict bool, serverName string) sTLS.ServerConfig {
		cfg, sErr := sTLS.NewServer(context.Background(), logger.NOP(), option.InboundTLSOptions{
			Enabled:     true,
			ServerName:  serverName,
			StrictSNI:   strict,
			Certificate: []string{string(pub)},
			Key:         []string{string(priv)},
		})
		if sErr != nil {
			t.Fatalf("NewServer: %v", sErr)
		}
		if sErr = cfg.Start(); sErr != nil {
			t.Fatalf("cfg.Start: %v", sErr)
		}
		t.Cleanup(func() { _ = cfg.Close() })
		return cfg
	}

	handshake := func(srvCfg sTLS.ServerConfig, clientSNI string) error {
		ln, lErr := net.Listen("tcp", "127.0.0.1:0")
		if lErr != nil {
			t.Fatalf("listen: %v", lErr)
		}
		defer ln.Close()

		srvErr := make(chan error, 1)
		go func() {
			c, aErr := ln.Accept()
			if aErr != nil {
				srvErr <- aErr
				return
			}
			defer c.Close()
			tConn, hErr := sTLS.ServerHandshake(context.Background(), c, srvCfg)
			if tConn != nil {
				_ = tConn.Close()
			}
			srvErr <- hErr
		}()

		client, cErr := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			ServerName:         clientSNI,
			InsecureSkipVerify: true,
		})
		if client != nil {
			_ = client.Close()
		}
		<-srvErr
		return cErr
	}

	strictExplicit := makeServer(true, "allowed.example.com")
	if err := handshake(strictExplicit, "allowed.example.com"); err != nil {
		t.Fatalf("matching SNI failed: %v", err)
	}
	if err := handshake(strictExplicit, "ALLOWED.EXAMPLE.COM"); err != nil {
		t.Fatalf("case-insensitive matching SNI failed: %v", err)
	}
	if err := handshake(strictExplicit, "wrong.example.com"); err == nil {
		t.Fatalf("expected wrong SNI to fail with strict_sni=true")
	}
	if err := handshake(strictExplicit, ""); err == nil {
		t.Fatalf("expected empty SNI to fail with strict_sni=true")
	}

	strictByCert := makeServer(true, "")
	if err := handshake(strictByCert, "allowed.example.com"); err != nil {
		t.Fatalf("cert SAN SNI failed: %v", err)
	}
	if err := handshake(strictByCert, "wrong.example.com"); err == nil {
		t.Fatalf("expected wrong SNI to fail against cert SAN with strict_sni=true")
	}

	permissive := makeServer(false, "allowed.example.com")
	if err := handshake(permissive, "wrong.example.com"); err != nil {
		t.Fatalf("expected strict_sni=false to allow mismatched SNI, got %v", err)
	}
}
