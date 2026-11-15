//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"io"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/browserhdr"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestUTLSAndRealityHTTP2FingerprintProvider(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		id         utls.ClientHelloID
		wantClient string
		wantPseudo []string
		wantWU     uint32
	}{
		{
			name:       "chrome",
			id:         utls.HelloChrome_Auto,
			wantClient: "Chrome",
			wantPseudo: []string{":method", ":authority", ":scheme", ":path"},
			wantWU:     15663105,
		},
		{
			name:       "firefox",
			id:         utls.HelloFirefox_Auto,
			wantClient: "Firefox",
			wantPseudo: []string{":method", ":path", ":authority", ":scheme"},
			wantWU:     12517377,
		},
		{
			name:       "safari",
			id:         utls.HelloSafari_16_0,
			wantClient: "Safari",
			wantPseudo: []string{":method", ":scheme", ":path", ":authority"},
			wantWU:     10485760,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uCfg := &UTLSClientConfig{
				ctx:    ctx,
				config: &utls.Config{ServerName: "example.com"},
				id:     tc.id,
			}
			client, _, ok := UTLSFingerprint(uCfg)
			require.True(t, ok)
			require.Equal(t, tc.wantClient, client)

			fp := HTTP2Fingerprint(uCfg)
			require.NotNil(t, fp)
			require.Equal(t, tc.wantPseudo, fp.PseudoHeaderOrder)
			require.Equal(t, tc.wantWU, fp.ConnectionFlow)

			// Verify wrappers preserve UTLSFingerprint.
			realityCfg := &RealityClientConfig{ctx: ctx, uClient: uCfg}
			require.Equal(t, tc.wantWU, HTTP2Fingerprint(realityCfg).ConnectionFlow)

			echCfg := &ECHClientConfig{ECHCapableConfig: uCfg}
			require.Equal(t, tc.wantWU, HTTP2Fingerprint(echCfg).ConnectionFlow)

			ktlsCfg := &KTLSClientConfig{Config: uCfg}
			require.Equal(t, tc.wantWU, HTTP2Fingerprint(ktlsCfg).ConnectionFlow)
		})
	}

	stdCfg, err := NewSTDClient(ctx, logger.NOP(), "example.com", option.OutboundTLSOptions{})
	require.NoError(t, err)
	_, _, ok := UTLSFingerprint(stdCfg)
	require.False(t, ok)
	require.Nil(t, HTTP2Fingerprint(stdCfg))
}

func TestRealityFallbackEmitsMatchedHTTP2Fingerprint(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		id         utls.ClientHelloID
		wantPseudo []string
		wantWU     uint32
		wantUAHint string
	}{
		{
			name:       "chrome",
			id:         utls.HelloChrome_Auto,
			wantPseudo: []string{":method", ":authority", ":scheme", ":path"},
			wantWU:     15663105,
			wantUAHint: "Chrome/",
		},
		{
			name:       "firefox",
			id:         utls.HelloFirefox_Auto,
			wantPseudo: []string{":method", ":path", ":authority", ":scheme"},
			wantWU:     12517377,
			wantUAHint: "Firefox/",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()

			type captured struct {
				settings   []http2.Setting
				connWU     uint32
				pseudo     []string
				userAgent  string
				secFetch   string
				firstHdrs  []string
				frameError error
			}
			ch := make(chan captured, 1)

			go func() {
				var res captured
				serverConn, err := ln.Accept()
				if err != nil {
					res.frameError = err
					ch <- res
					return
				}
				defer serverConn.Close()
				preface := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(serverConn, preface); err != nil {
					res.frameError = err
					ch <- res
					return
				}
				fr := http2.NewFramer(serverConn, serverConn)
				fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
				if err := fr.WriteSettings(); err != nil {
					res.frameError = err
					ch <- res
					return
				}
				for {
					f, err := fr.ReadFrame()
					if err != nil {
						res.frameError = err
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
								res.firstHdrs = append(res.firstHdrs, hf.Name)
								switch hf.Name {
								case "user-agent":
									res.userAgent = hf.Value
								case "sec-fetch-mode":
									res.secFetch = hf.Value
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

			clientConn, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go realityClientFallback(ctx, clientConn, "example.com", tc.id)

			got := <-ch
			require.NoError(t, got.frameError)
			require.Equal(t, tc.wantWU, got.connWU)
			require.Equal(t, tc.wantPseudo, got.pseudo)
			require.Contains(t, got.userAgent, tc.wantUAHint)
			require.Equal(t, "navigate", got.secFetch)

			wantFP := browserhdr.HTTP2Fingerprint(nil, tc.id.Client, tc.id.Version, "document")
			require.True(t, slices.Equal(wantFP.Settings, got.settings), "settings mismatch: got %+v want %+v", got.settings, wantFP.Settings)
			if tc.name == "firefox" {
				// Firefox emits user-agent as the very first regular header and omits sec-ch-ua.
				require.Equal(t, "user-agent", got.firstHdrs[0])
				require.False(t, slices.Contains(got.firstHdrs, "sec-ch-ua"))
			} else {
				require.True(t, slices.Contains(got.firstHdrs, "sec-ch-ua"))
				uaIdx := slices.Index(got.firstHdrs, "user-agent")
				chIdx := slices.Index(got.firstHdrs, "sec-ch-ua")
				require.True(t, chIdx >= 0 && uaIdx > chIdx && strings.Contains(got.userAgent, "Chrome/"))
			}
		})
	}
}
