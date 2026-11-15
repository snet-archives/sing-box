package httpclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/browserhdr"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestNewDialerTransport(t *testing.T) {
	if _, err := NewDialerTransport(context.Background(), nil, nil, option.HTTPClientOptions{}); err == nil {
		t.Fatal("expected error when dialer is nil")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &stdtls.Config{
		Certificates: []stdtls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
		}},
		NextProtos: []string{http2.NextProtoTLS},
	}

	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type observed struct {
		settings     []http2.Setting
		windowUpdate uint32
		headers      map[string]string
		err          error
	}
	obsCh := make(chan observed, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			obsCh <- observed{err: err}
			return
		}
		defer conn.Close()

		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(conn, preface); err != nil {
			obsCh <- observed{err: err}
			return
		}
		fr := http2.NewFramer(conn, conn)
		if err := fr.WriteSettings(http2.Setting{ID: http2.SettingNoRFC7540Priorities, Val: 1}); err != nil {
			obsCh <- observed{err: err}
			return
		}

		out := observed{headers: make(map[string]string)}
		dec := hpack.NewDecoder(65536, func(hf hpack.HeaderField) {
			out.headers[hf.Name] = hf.Value
		})
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					out.err = err
				}
				obsCh <- out
				return
			}
			switch f := f.(type) {
			case *http2.SettingsFrame:
				if !f.IsAck() {
					_ = f.ForeachSetting(func(s http2.Setting) error {
						out.settings = append(out.settings, s)
						return nil
					})
					if err := fr.WriteSettingsAck(); err != nil {
						obsCh <- observed{err: err}
						return
					}
				}
			case *http2.WindowUpdateFrame:
				if f.StreamID == 0 && out.windowUpdate == 0 {
					out.windowUpdate = f.Increment
				}
			case *http2.HeadersFrame:
				if _, err := dec.Write(f.HeaderBlockFragment()); err != nil {
					obsCh <- observed{err: err}
					return
				}
				_ = dec.Close()
				var hdrBuf bytes.Buffer
				enc := hpack.NewEncoder(&hdrBuf)
				_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
				if err := fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      f.StreamID,
					BlockFragment: hdrBuf.Bytes(),
					EndStream:     true,
					EndHeaders:    true,
				}); err != nil {
					obsCh <- observed{err: err}
					return
				}
				obsCh <- out
				return
			}
		}
	}()

	var clientOptions option.HTTPClientOptions
	clientOptions.TLS = &option.OutboundTLSOptions{
		Insecure: true,
	}
	transport, err := NewDialerTransport(context.Background(), nil, N.SystemDialer, clientOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()

	client := &http.Client{Transport: transport}
	defer client.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tls.HasUTLS {
		browserhdr.ApplyForUTLS(req.Header, "chrome", "", "fetch")
	} else {
		req.Header.Add("User-Agent", "curl/7.88.0")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do failed: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	obs := <-obsCh
	if obs.err != nil {
		t.Fatalf("server error: %v", obs.err)
	}
	if len(obs.settings) == 0 {
		t.Fatal("expected HTTP/2 client SETTINGS frame")
	}

	if tls.HasUTLS {
		wantSettings := []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		}
		if len(obs.settings) != len(wantSettings) {
			t.Fatalf("unexpected Chrome HTTP/2 settings: got %+v, want %+v", obs.settings, wantSettings)
		}
		for i, want := range wantSettings {
			if obs.settings[i] != want {
				t.Fatalf("setting[%d]=%+v, want %+v", i, obs.settings[i], want)
			}
		}
		if obs.windowUpdate != 15663105 {
			t.Fatalf("Chrome conn WINDOW_UPDATE=%d, want 15663105", obs.windowUpdate)
		}
		if obs.headers["sec-fetch-mode"] == "" || obs.headers["user-agent"] == "curl/7.88.0" {
			t.Fatalf("expected coherent Chrome headers under uTLS, got %+v", obs.headers)
		}
	} else if obs.headers["user-agent"] != "curl/7.88.0" {
		t.Fatalf("expected fallback User-Agent without uTLS, got %q", obs.headers["user-agent"])
	}
}
