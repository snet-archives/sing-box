//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	utls "github.com/metacubex/utls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func generateRealityTestTargetCert(t *testing.T, serverName string) stdtls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	dnsNames := []string{serverName}
	for i := 0; i < 120; i++ {
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
	return stdtls.Certificate{
		Certificate: [][]byte{der, der},
		PrivateKey:  priv,
	}
}

func startRealityTestTarget(t *testing.T, serverName string) (uint16, func()) {
	t.Helper()
	cert := generateRealityTestTargetCert(t, serverName)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tlsConn := stdtls.Server(conn, &stdtls.Config{
					Certificates:     []stdtls.Certificate{cert},
					MinVersion:       stdtls.VersionTLS13,
					MaxVersion:       stdtls.VersionTLS13,
					CurvePreferences: []stdtls.CurveID{stdtls.X25519MLKEM768, stdtls.X25519},
					NextProtos:       []string{"h2", "http/1.1"},
				})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				_, _ = io.Copy(tlsConn, tlsConn)
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return uint16(port), func() {
		ln.Close()
		wg.Wait()
	}
}

func newTestRealityKeypairs(t *testing.T) (privB64, pubB64, mldsaSeedB64, mldsaVerifyB64, shortIDHex string) {
	t.Helper()
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	var mSeed [mldsa65.SeedSize]byte
	_, err = io.ReadFull(rand.Reader, mSeed[:])
	require.NoError(t, err)
	mPub, _ := mldsa65.NewKeyFromSeed(&mSeed)
	mPubBytes, err := mPub.MarshalBinary()
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(xPriv.Bytes()),
		base64.RawURLEncoding.EncodeToString(xPriv.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(mSeed[:]),
		base64.RawURLEncoding.EncodeToString(mPubBytes),
		"0102030405060708"
}

func runRealityPairHandshake(
	t *testing.T,
	serverCfg ServerConfig,
	clientCfg Config,
) (clientConn, serverConn Conn, clientErr, serverErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rawSrv, err := ln.Accept()
		if err != nil {
			serverErr = err
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		serverConn, serverErr = ServerHandshake(ctx, rawSrv, serverCfg)
		if serverErr != nil {
			rawSrv.Close()
		}
	}()

	rawCli, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConn, clientErr = ClientHandshake(ctx, rawCli, clientCfg)
	if clientErr != nil {
		rawCli.Close()
	}
	wg.Wait()
	return clientConn, serverConn, clientErr, serverErr
}

func TestRealityClientServerUpgrade(t *testing.T) {
	const serverName = "target.example.com"
	targetPort, stopTarget := startRealityTestTarget(t, serverName)
	defer stopTarget()

	nopLogger := log.NewNOPFactory().Logger()
	privB64, pubB64, mldsaSeedB64, mldsaVerifyB64, shortIDHex := newTestRealityKeypairs(t)

	newServer := func(seed string, handshakeTimeout time.Duration, limitDown *option.InboundRealityLimitFallbackOptions) (ServerConfig, error) {
		return NewRealityServer(context.Background(), nopLogger, option.InboundTLSOptions{
			Enabled:          true,
			ServerName:       serverName,
			HandshakeTimeout: badoption.Duration(handshakeTimeout),
			Reality: &option.InboundRealityOptions{
				Enabled: true,
				Handshake: option.InboundRealityHandshakeOptions{
					ServerOptions: option.ServerOptions{
						Server:     "127.0.0.1",
						ServerPort: targetPort,
					},
				},
				PrivateKey:            privB64,
				ShortID:               badoption.Listable[string]{shortIDHex},
				MLDSA65Seed:           seed,
				LimitFallbackDownload: limitDown,
			},
		})
	}

	newClient := func(fingerprint, verify string, disablePQ bool) (Config, error) {
		return NewRealityClient(context.Background(), nopLogger, serverName, option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: serverName,
			ALPN:       []string{"h2", "http/1.1"},
			UTLS: &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: fingerprint,
			},
			Reality: &option.OutboundRealityOptions{
				Enabled:               true,
				PublicKey:             pubB64,
				ShortID:               shortIDHex,
				MLDSA65Verify:         verify,
				DisableX25519MLKEM768: disablePQ,
			},
		})
	}

	t.Run("PQ_X25519MLKEM768_And_MLDSA65", func(t *testing.T) {
		srvCfg, err := newServer(mldsaSeedB64, 5*time.Second, nil)
		require.NoError(t, err)
		cliCfg, err := newClient("chrome_133", mldsaVerifyB64, false)
		require.NoError(t, err)

		cliConn, srvConn, cliErr, srvErr := runRealityPairHandshake(t, srvCfg.Clone().(ServerConfig), cliCfg.Clone())
		require.NoError(t, cliErr)
		require.NoError(t, srvErr)
		defer cliConn.Close()
		defer srvConn.Close()

		rc, ok := common.Cast[*realityClientConnWrapper](cliConn)
		require.True(t, ok)
		require.Equal(t, utls.X25519MLKEM768, rc.HandshakeState.ServerHello.ServerShare.Group)
		require.False(t, SupportsQUIC(srvCfg))
		require.False(t, SupportsQUIC(cliCfg))

		errCh := make(chan error, 1)
		go func() {
			buf := make([]byte, 4)
			if _, err := io.ReadFull(srvConn, buf); err != nil {
				errCh <- err
				return
			}
			_, err := srvConn.Write([]byte("pong"))
			errCh <- err
		}()

		_, err = cliConn.Write([]byte("ping"))
		require.NoError(t, err)
		reply := make([]byte, 4)
		_, err = io.ReadFull(cliConn, reply)
		require.NoError(t, err)
		require.Equal(t, "pong", string(reply))
		require.NoError(t, <-errCh)
	})

	t.Run("Chrome131_And_ChromePQ_Fingerprints", func(t *testing.T) {
		srvCfg, err := newServer(mldsaSeedB64, 5*time.Second, nil)
		require.NoError(t, err)
		cli131, err := newClient("chrome_131", mldsaVerifyB64, false)
		require.NoError(t, err)
		cliConn, srvConn, cliErr, srvErr := runRealityPairHandshake(t, srvCfg, cli131)
		require.NoError(t, cliErr)
		require.NoError(t, srvErr)
		rc, ok := common.Cast[*realityClientConnWrapper](cliConn)
		require.True(t, ok)
		require.Equal(t, utls.X25519MLKEM768, rc.HandshakeState.ServerHello.ServerShare.Group)
		cliConn.Close()
		srvConn.Close()

		// chrome_pq maps to HelloChrome_120_PQ (draft Kyber + X25519); a TLS 1.3
		// server supporting X25519MLKEM768 + X25519 selects X25519 cleanly.
		cliPQ, err := newClient("chrome_pq", mldsaVerifyB64, false)
		require.NoError(t, err)
		cliConn, srvConn, cliErr, srvErr = runRealityPairHandshake(t, srvCfg, cliPQ)
		require.NoError(t, cliErr)
		require.NoError(t, srvErr)
		defer cliConn.Close()
		defer srvConn.Close()
		rc, ok = common.Cast[*realityClientConnWrapper](cliConn)
		require.True(t, ok)
		require.Equal(t, utls.X25519, rc.HandshakeState.ServerHello.ServerShare.Group)
	})

	t.Run("DisableX25519MLKEM768", func(t *testing.T) {
		srvCfg, err := newServer(mldsaSeedB64, 5*time.Second, nil)
		require.NoError(t, err)
		cliCfg, err := newClient("chrome_133", mldsaVerifyB64, true)
		require.NoError(t, err)

		cliConn, srvConn, cliErr, srvErr := runRealityPairHandshake(t, srvCfg, cliCfg)
		require.NoError(t, cliErr)
		require.NoError(t, srvErr)
		defer cliConn.Close()
		defer srvConn.Close()

		rc, ok := common.Cast[*realityClientConnWrapper](cliConn)
		require.True(t, ok)
		require.Equal(t, utls.X25519, rc.HandshakeState.ServerHello.ServerShare.Group)
	})

	t.Run("MLDSA65MismatchRejected", func(t *testing.T) {
		srvCfg, err := newServer(mldsaSeedB64, 5*time.Second, nil)
		require.NoError(t, err)
		_, _, _, otherVerifyB64, _ := newTestRealityKeypairs(t)
		cliCfg, err := newClient("chrome_133", otherVerifyB64, false)
		require.NoError(t, err)

		cliConn, srvConn, cliErr, _ := runRealityPairHandshake(t, srvCfg, cliCfg)
		if cliConn != nil {
			cliConn.Close()
		}
		if srvConn != nil {
			srvConn.Close()
		}
		require.Error(t, cliErr)
	})

	t.Run("ConfigValidation", func(t *testing.T) {
		_, err := newServer(privB64, 5*time.Second, nil)
		require.ErrorContains(t, err, "must not equal")

		_, err = newServer("bad_seed", 5*time.Second, nil)
		require.Error(t, err)

		_, err = newClient("chrome_133", base64.RawURLEncoding.EncodeToString([]byte("short")), false)
		require.Error(t, err)
	})

	t.Run("HandshakeTimeoutEnforced", func(t *testing.T) {
		srvCfg, err := newServer("", 80*time.Millisecond, nil)
		require.NoError(t, err)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		srvErrCh := make(chan error, 1)
		go func() {
			rawSrv, err := ln.Accept()
			if err != nil {
				srvErrCh <- err
				return
			}
			defer rawSrv.Close()
			_, err = ServerHandshake(context.Background(), rawSrv, srvCfg)
			srvErrCh <- err
		}()

		rawCli, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)
		defer rawCli.Close()

		select {
		case srvErr := <-srvErrCh:
			require.Error(t, srvErr)
		case <-time.After(2 * time.Second):
			t.Fatal("RealityServerConfig.ServerHandshake ignored configured HandshakeTimeout")
		}
	})

	t.Run("LimitFallbackProxyToTarget", func(t *testing.T) {
		srvCfg, err := newServer("", 5*time.Second, &option.InboundRealityLimitFallbackOptions{
			AfterBytes:       64,
			BytesPerSec:      4096,
			BurstBytesPerSec: 4096,
		})
		require.NoError(t, err)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer ln.Close()

		srvErrCh := make(chan error, 1)
		go func() {
			rawSrv, err := ln.Accept()
			if err != nil {
				srvErrCh <- err
				return
			}
			defer rawSrv.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err = ServerHandshake(ctx, rawSrv, srvCfg)
			srvErrCh <- err
		}()

		rawCli, err := net.Dial("tcp", ln.Addr().String())
		require.NoError(t, err)
		probeConn := stdtls.Client(rawCli, &stdtls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			MinVersion:         stdtls.VersionTLS13,
			MaxVersion:         stdtls.VersionTLS13,
		})
		defer probeConn.Close()
		require.NoError(t, probeConn.Handshake())

		payload := []byte("fallback-probe-echo-data")
		_, err = probeConn.Write(payload)
		require.NoError(t, err)
		echo := make([]byte, len(payload))
		_, err = io.ReadFull(probeConn, echo)
		require.NoError(t, err)
		require.Equal(t, payload, echo)
		probeConn.Close()

		require.Error(t, <-srvErrCh)
	})
}

func TestRealityClientFallbackBrowserHeaders(t *testing.T) {
	const serverName = "target.example.com"
	cert := generateRealityTestTargetCert(t, serverName)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	reqCh := make(chan http.Header, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		tlsSrv := stdtls.Server(conn, &stdtls.Config{
			Certificates: []stdtls.Certificate{cert},
			MinVersion:   stdtls.VersionTLS13,
			NextProtos:   []string{"h2"},
		})
		if err := tlsSrv.Handshake(); err != nil {
			return
		}
		h2Srv := &http2.Server{}
		h2Srv.ServeConn(tlsSrv, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reqCh <- r.Header.Clone()
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			}),
		})
	}()

	rawCli, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	tlsCli := stdtls.Client(rawCli, &stdtls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         stdtls.VersionTLS13,
		NextProtos:         []string{"h2"},
	})
	require.NoError(t, tlsCli.Handshake())

	done := make(chan struct{})
	go func() {
		realityClientFallback(context.Background(), tlsCli, serverName, utls.HelloChrome_133)
		close(done)
	}()

	select {
	case hdr := <-reqCh:
		require.Contains(t, hdr.Get("User-Agent"), "Mozilla/5.0")
		require.Contains(t, hdr.Get("User-Agent"), "Chrome/133.0.0.0")
		require.Equal(t, "navigate", hdr.Get("Sec-Fetch-Mode"))
		require.Equal(t, "document", hdr.Get("Sec-Fetch-Dest"))
		require.Equal(t, "none", hdr.Get("Sec-Fetch-Site"))
		require.Equal(t, "1", hdr.Get("Upgrade-Insecure-Requests"))
		require.Contains(t, hdr.Get("Sec-Ch-Ua"), `"Google Chrome";v="133"`)
		require.True(t, strings.Contains(hdr.Get("Cookie"), "padding="))
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for realityClientFallback HTTP/2 request")
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("realityClientFallback did not exit cleanly")
	}
}

func TestUTLSFingerprintMapping(t *testing.T) {
	names := []string{
		"",
		"chrome",
		"chrome_131",
		"chrome_133",
		"chrome_120",
		"chrome_pq",
		"chrome_pq_psk",
		"chrome_psk",
		"chrome_psk_shuffle",
		"chrome_padding_psk_shuffle",
		"firefox",
		"firefox_120",
		"firefox_148",
		"edge",
		"safari",
		"safari_16_0",
		"safari_26_3",
		"360",
		"qq",
		"ios",
		"android",
		"random",
		"randomized",
		"randomized_no_alpn",
	}
	for _, name := range names {
		id, err := uTLSClientHelloID(name)
		require.NoError(t, err, "fingerprint %q should resolve", name)
		require.NotEmpty(t, id.Client, "fingerprint %q returned empty client ID", name)
	}

	pqID, _ := uTLSClientHelloID("chrome_pq")
	autoID, _ := uTLSClientHelloID("chrome")
	require.NotEqual(t, autoID, pqID, "chrome_pq must not silently alias chrome auto")

	randNoALPN, _ := uTLSClientHelloID("randomized_no_alpn")
	require.Equal(t, utls.HelloRandomizedNoALPN.Client, randNoALPN.Client)
}
