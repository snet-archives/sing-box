package mux_test

import (
	"context"
	stdjson "encoding/json"
	"io"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/schema"
	singmux "github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestOutboundMultiplexOptionsXmuxJSONAndValidation(t *testing.T) {
	t.Parallel()

	raw := `{
		"enabled": true,
		"protocol": "h2mux",
		"xmux": {
			"max_concurrency": 2,
			"max_connections": "2-4",
			"c_max_reuse_times": {"from": 10, "to": 20},
			"h_max_request_times": {"from": 3},
			"h_max_reusable_secs": "60-120",
			"h_keep_alive_period": 15
		}
	}`

	var opts option.OutboundMultiplexOptions
	err := json.UnmarshalContext(context.Background(), []byte(raw), &opts)
	require.NoError(t, err)
	require.NotNil(t, opts.Xmux)

	muxOpts := opts.Xmux.ToMux()
	require.NoError(t, muxOpts.Validate())
	require.Equal(t, singmux.XmuxRange{From: 2, To: 2}, muxOpts.MaxConcurrency)
	require.Equal(t, singmux.XmuxRange{From: 2, To: 4}, muxOpts.MaxConnections)
	require.Equal(t, singmux.XmuxRange{From: 10, To: 20}, muxOpts.CMaxReuseTimes)
	require.Equal(t, singmux.XmuxRange{From: 3, To: 3}, muxOpts.HMaxRequestTimes)
	require.Equal(t, singmux.XmuxRange{From: 60, To: 120}, muxOpts.HMaxReusableSecs)
	require.Equal(t, singmux.XmuxRange{From: 15, To: 15}, muxOpts.HKeepAlivePeriod)

	encoded, err := stdjson.Marshal(opts)
	require.NoError(t, err)
	var roundTrip option.OutboundMultiplexOptions
	require.NoError(t, json.UnmarshalContext(context.Background(), encoded, &roundTrip))
	require.Equal(t, muxOpts, roundTrip.Xmux.ToMux())

	badCases := []string{
		`{"enabled":true,"xmux":{"max_concurrency":"10-2"}}`,
		`{"enabled":true,"xmux":{"max_connections":{"from":10,"to":2}}}`,
		`{"enabled":true,"xmux":{"h_max_request_times":-1}}`,
		`{"enabled":true,"xmux":{"h_max_reusable_secs":"abc"}}`,
	}
	for _, tc := range badCases {
		var bad option.OutboundMultiplexOptions
		unmarshalErr := json.UnmarshalContext(context.Background(), []byte(tc), &bad)
		if unmarshalErr == nil {
			_, clientErr := mux.NewClientWithOptions(stubDialer{}, logger.NOP(), bad)
			require.Error(t, clientErr, "expected validation error for %s", tc)
		}
	}
}

func TestMuxSchemaIncludesXmuxAndXHTTP(t *testing.T) {
	t.Parallel()

	muxSchemaBytes, err := schema.Generate(context.Background(), reflect.TypeFor[option.OutboundMultiplexOptions]())
	require.NoError(t, err)
	muxSchema := string(muxSchemaBytes)
	for _, field := range []string{"xmux", "max_concurrency", "h_max_request_times", "h_keep_alive_period"} {
		require.True(t, strings.Contains(muxSchema, field), "mux schema missing %q", field)
	}

	v2raySchemaBytes, err := schema.Generate(context.Background(), reflect.TypeFor[option.V2RayTransportOptions]())
	require.NoError(t, err)
	v2raySchema := string(v2raySchemaBytes)
	for _, field := range []string{`"xhttp"`, "x_padding_placement", "uplink_data_placement", "download_dialer", "download_tls", "xmux"} {
		require.True(t, strings.Contains(v2raySchema, field), "v2ray schema missing %q", field)
	}
}

type stubDialer struct{}

func (stubDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, io.EOF
}

func (stubDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, io.EOF
}

type pipeMuxDialer struct {
	dials  atomic.Int32
	router adapter.ConnectionRouterEx
}

func (d *pipeMuxDialer) DialContext(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	cSide, sSide := net.Pipe()
	go d.router.RouteConnectionEx(context.Background(), sSide, adapter.InboundContext{
		Destination: destination,
	}, nil)
	return cSide, nil
}

func (d *pipeMuxDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, io.ErrUnexpectedEOF
}

type echoRouter struct{}

func (echoRouter) RouteConnection(context.Context, net.Conn, adapter.InboundContext) error {
	return nil
}

func (echoRouter) RoutePacketConnection(context.Context, N.PacketConn, adapter.InboundContext) error {
	return nil
}

func (echoRouter) RouteConnectionEx(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	go func() {
		defer func() {
			_ = conn.Close()
			if onClose != nil {
				onClose(nil)
			}
		}()
		_, _ = io.Copy(conn, conn)
	}()
}

func (echoRouter) RoutePacketConnectionEx(_ context.Context, conn N.PacketConn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func TestMuxNewClientWithOptionsXmuxLifecycle(t *testing.T) {
	t.Parallel()

	router, err := mux.NewRouterWithOptions(echoRouter{}, logger.NOP(), option.InboundMultiplexOptions{
		Enabled: true,
	})
	require.NoError(t, err)

	dialer := &pipeMuxDialer{router: router}
	client, err := mux.NewClientWithOptions(dialer, logger.NOP(), option.OutboundMultiplexOptions{
		Enabled:  true,
		Protocol: "h2mux",
		Xmux: &option.XmuxOptions{
			MaxConcurrency:   option.XmuxRange{From: 4, To: 4},
			HMaxRequestTimes: option.XmuxRange{From: 2, To: 2},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	target := M.ParseSocksaddrHostPort("example.com", 443)
	for i := range 5 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stream, dialErr := client.DialContext(ctx, N.NetworkTCP, target)
		cancel()
		require.NoError(t, dialErr, "stream %d", i)

		payload := []byte("xmux-ping")
		_, err = stream.Write(payload)
		require.NoError(t, err)
		buf := make([]byte, len(payload))
		_, err = io.ReadFull(stream, buf)
		require.NoError(t, err)
		require.Equal(t, payload, buf)
		require.NoError(t, stream.Close())
	}

	// With HMaxRequestTimes=2 over 5 sequential streams:
	// conn1 serves 2, conn2 serves 2, conn3 serves 1 => 3 underlying dials.
	require.Equal(t, int32(3), dialer.dials.Load())
}
