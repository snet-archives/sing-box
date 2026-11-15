//go:build with_utls

package tls

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	tf "github.com/sagernet/sing-box/common/tlsfragment"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// Guards the wrap gate in UTLSClientConfig.Client(): tf.Conn must wrap the
// underlying connection whenever either `fragment` or `record_fragment` is
// set. Mirrors the STDClientConfig gate tests to keep both code paths in
// lockstep.

func newUTLSClientConfigForGateTest(fragment, recordFragment bool) *UTLSClientConfig {
	return &UTLSClientConfig{
		ctx:            context.Background(),
		config:         &utls.Config{ServerName: "example.com", InsecureSkipVerify: true},
		id:             utls.HelloChrome_Auto,
		fragment:       fragment,
		recordFragment: recordFragment,
	}
}

func TestUTLSClient_Client_NoFragment_DoesNotWrap(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped, err := newUTLSClientConfigForGateTest(false, false).Client(client)
	require.NoError(t, err)
	_, isTF := wrapped.NetConn().(*tf.Conn)
	require.False(t, isTF, "no fragment flags: must not wrap with tf.Conn")
}

func TestUTLSClient_Client_FragmentOnly_Wraps(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped, err := newUTLSClientConfigForGateTest(true, false).Client(client)
	require.NoError(t, err)
	_, isTF := wrapped.NetConn().(*tf.Conn)
	require.True(t, isTF, "fragment=true: must wrap with tf.Conn")
}

func TestUTLSClient_Client_RecordFragmentOnly_Wraps(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped, err := newUTLSClientConfigForGateTest(false, true).Client(client)
	require.NoError(t, err)
	_, isTF := wrapped.NetConn().(*tf.Conn)
	require.True(t, isTF, "record_fragment=true: must wrap with tf.Conn")
}

func TestUTLSClient_Client_BothFragment_Wraps(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	wrapped, err := newUTLSClientConfigForGateTest(true, true).Client(client)
	require.NoError(t, err)
	_, isTF := wrapped.NetConn().(*tf.Conn)
	require.True(t, isTF, "both fragment flags: must wrap with tf.Conn")
}

type realityWriteRecorderConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *realityWriteRecorderConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, bytes.Clone(b))
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *realityWriteRecorderConn) snapshot() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.writes))
	copy(out, c.writes)
	return out
}

func TestRealityClient_Handshake_FragmentsClientHello(t *testing.T) {
	const serverName = "target.example.com"
	targetPort, stopTarget := startRealityTestTarget(t, serverName)
	defer stopTarget()

	nopLogger := log.NewNOPFactory().Logger()
	privB64, pubB64, mldsaSeedB64, mldsaVerifyB64, shortIDHex := newTestRealityKeypairs(t)

	srvCfg, err := NewRealityServer(context.Background(), nopLogger, option.InboundTLSOptions{
		Enabled:          true,
		ServerName:       serverName,
		HandshakeTimeout: badoption.Duration(5 * time.Second),
		Reality: &option.InboundRealityOptions{
			Enabled: true,
			Handshake: option.InboundRealityHandshakeOptions{
				ServerOptions: option.ServerOptions{
					Server:     "127.0.0.1",
					ServerPort: targetPort,
				},
			},
			PrivateKey:  privB64,
			ShortID:     badoption.Listable[string]{shortIDHex},
			MLDSA65Seed: mldsaSeedB64,
		},
	})
	require.NoError(t, err)

	for _, tc := range []struct {
		name           string
		fragment       bool
		recordFragment bool
	}{
		{name: "PacketFragment", fragment: true, recordFragment: false},
		{name: "RecordAndPacketFragment", fragment: true, recordFragment: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cliCfg, err := NewRealityClient(context.Background(), nopLogger, serverName, option.OutboundTLSOptions{
				Enabled:        true,
				ServerName:     serverName,
				ALPN:           []string{"h2", "http/1.1"},
				Fragment:       tc.fragment,
				RecordFragment: tc.recordFragment,
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: "chrome_133",
				},
				Reality: &option.OutboundRealityOptions{
					Enabled:       true,
					PublicKey:     pubB64,
					ShortID:       shortIDHex,
					MLDSA65Verify: mldsaVerifyB64,
				},
			})
			require.NoError(t, err)

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer ln.Close()

			var srvConn Conn
			var srvErr error
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				rawSrv, err := ln.Accept()
				if err != nil {
					srvErr = err
					return
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				srvConn, srvErr = ServerHandshake(ctx, rawSrv, srvCfg.Clone().(ServerConfig))
				if srvErr != nil {
					rawSrv.Close()
				}
			}()

			rawCli, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)
			rec := &realityWriteRecorderConn{Conn: rawCli}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cliConn, cliErr := ClientHandshake(ctx, rec, cliCfg.Clone())
			require.NoError(t, cliErr)
			wg.Wait()
			require.NoError(t, srvErr)
			defer cliConn.Close()
			defer srvConn.Close()

			writes := rec.snapshot()
			require.Greater(t, len(writes), 2, "Reality ClientHello must be split across multiple writes when fragment is enabled")
			if tc.recordFragment {
				handshakeRecords := 0
				for _, w := range writes {
					if len(w) >= 5 && w[0] == 0x16 && w[1] == 0x03 {
						handshakeRecords++
					}
				}
				require.Greater(t, handshakeRecords, 1, "RecordFragment must emit multiple TLS Handshake records")
			}
		})
	}
}
