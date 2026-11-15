//go:build with_utls

package v2rayxhttp

import (
	"bytes"
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestXHTTPUTLSAndHTTP2WireFingerprint(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		utlsFP      string
		wantWU      uint32
		wantPseudo  []string
		wantUA      string
		wantNoSecCH bool
	}{
		{
			name:        "chrome",
			utlsFP:      "chrome",
			wantWU:      15663105,
			wantPseudo:  []string{":method", ":authority", ":scheme", ":path"},
			wantUA:      "Chrome/",
			wantNoSecCH: false,
		},
		{
			name:        "firefox",
			utlsFP:      "firefox",
			wantWU:      12517377,
			wantPseudo:  []string{":method", ":path", ":authority", ":scheme"},
			wantUA:      "Firefox/",
			wantNoSecCH: true,
		},
		{
			name:        "safari",
			utlsFP:      "safari_16_0",
			wantWU:      10485760,
			wantPseudo:  []string{":method", ":scheme", ":path", ":authority"},
			wantUA:      "Safari/",
			wantNoSecCH: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certPEM, keyPEM := generateCertPair(t, "xhttp.example")
			cert, err := stdtls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
			require.NoError(t, err)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()

			type wireResult struct {
				settings []http2.Setting
				connWU   uint32
				pseudo   []string
				hdrNames []string
				ua       string
				err      error
			}
			ch := make(chan wireResult, 1)

			go func() {
				raw, err := ln.Accept()
				if err != nil {
					ch <- wireResult{err: err}
					return
				}
				tlsConn := stdtls.Server(raw, &stdtls.Config{
					Certificates: []stdtls.Certificate{cert},
					NextProtos:   []string{"h2"},
				})
				defer tlsConn.Close()
				if err := tlsConn.Handshake(); err != nil {
					ch <- wireResult{err: err}
					return
				}

				preface := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(tlsConn, preface); err != nil {
					ch <- wireResult{err: err}
					return
				}
				fr := http2.NewFramer(tlsConn, tlsConn)
				fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
				if err := fr.WriteSettings(); err != nil {
					ch <- wireResult{err: err}
					return
				}

				var res wireResult
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						res.err = err
						ch <- res
						return
					}
					switch f := f.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							_ = f.ForeachSetting(func(s http2.Setting) error {
								res.settings = append(res.settings, s)
								return nil
							})
							_ = fr.WriteSettingsAck()
						}
					case *http2.WindowUpdateFrame:
						if f.StreamID == 0 {
							res.connWU = f.Increment
						}
					case *http2.MetaHeadersFrame:
						for _, hf := range f.Fields {
							if hf.IsPseudo() {
								res.pseudo = append(res.pseudo, hf.Name)
							} else {
								res.hdrNames = append(res.hdrNames, hf.Name)
								if hf.Name == "user-agent" {
									res.ua = hf.Value
								}
							}
						}
						var buf bytes.Buffer
						enc := hpack.NewEncoder(&buf)
						_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
						_ = fr.WriteHeaders(http2.HeadersFrameParam{
							StreamID:      f.StreamID,
							BlockFragment: buf.Bytes(),
							EndStream:     true,
							EndHeaders:    true,
						})
						ch <- res
						return
					}
				}
			}()

			cliTLS, err := tls.NewClientWithOptions(tls.ClientOptions{
				Context:       context.Background(),
				Logger:        logger.NOP(),
				ServerAddress: "xhttp.example",
				Options: option.OutboundTLSOptions{
					Enabled:     true,
					ServerName:  "xhttp.example",
					ALPN:        []string{"h2"},
					Certificate: []string{certPEM},
					UTLS: &option.OutboundUTLSOptions{
						Enabled:     true,
						Fingerprint: tc.utlsFP,
					},
				},
			})
			require.NoError(t, err)

			tcpAddr := ln.Addr().(*net.TCPAddr)
			client, err := NewClient(
				context.Background(),
				&testDialer{},
				M.SocksaddrFrom(M.AddrFromIP(tcpAddr.IP), uint16(tcpAddr.Port)),
				option.V2RayXHTTPOptions{
					Host: []string{"xhttp.example"},
					Path: "/xhttp",
					Mode: modeStreamOne,
				},
				cliTLS,
			)
			require.NoError(t, err)
			defer client.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx)
			require.NoError(t, err)
			defer conn.Close()

			// Flush first request by waiting for captured server response.
			got := <-ch
			require.NoError(t, got.err)
			require.Equal(t, tc.wantWU, got.connWU)
			require.Equal(t, tc.wantPseudo, got.pseudo)
			require.Contains(t, got.ua, tc.wantUA)
			require.Equal(t, tc.wantNoSecCH, !slices.Contains(got.hdrNames, "sec-ch-ua"))
			if tc.name == "firefox" {
				require.Equal(t, "user-agent", got.hdrNames[0])
			} else if tc.name == "safari" {
				require.Equal(t, "content-type", got.hdrNames[0])
			}
			wantSettings := tls.HTTP2Fingerprint(cliTLS).Settings
			require.True(t, slices.Equal(wantSettings, got.settings), "settings mismatch: got %+v want %+v", got.settings, wantSettings)
		})
	}
}
