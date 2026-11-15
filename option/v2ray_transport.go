package option

import (
	"reflect"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

type _V2RayTransportOptions struct {
	Type               string                  `json:"type" enum:"http,ws,quic,grpc,httpupgrade,xhttp"`
	HTTPOptions        V2RayHTTPOptions        `json:"-"`
	WebsocketOptions   V2RayWebsocketOptions   `json:"-"`
	QUICOptions        V2RayQUICOptions        `json:"-"`
	GRPCOptions        V2RayGRPCOptions        `json:"-"`
	HTTPUpgradeOptions V2RayHTTPUpgradeOptions `json:"-"`
	XHTTPOptions       V2RayXHTTPOptions       `json:"-"`
}

type V2RayTransportOptions _V2RayTransportOptions

func (o V2RayTransportOptions) MarshalJSON() ([]byte, error) {
	var v any
	switch o.Type {
	case C.V2RayTransportTypeHTTP:
		v = o.HTTPOptions
	case C.V2RayTransportTypeWebsocket:
		v = o.WebsocketOptions
	case C.V2RayTransportTypeQUIC:
		v = o.QUICOptions
	case C.V2RayTransportTypeGRPC:
		v = o.GRPCOptions
	case C.V2RayTransportTypeHTTPUpgrade:
		v = o.HTTPUpgradeOptions
	case C.V2RayTransportTypeXHTTP:
		v = o.XHTTPOptions
	case "":
		return nil, E.New("missing transport type")
	default:
		return nil, E.New("unknown transport type: " + o.Type)
	}
	return badjson.MarshallObjects(_V2RayTransportOptions(o), v)
}

func (o *V2RayTransportOptions) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_V2RayTransportOptions)(o))
	if err != nil {
		return err
	}
	var v any
	switch o.Type {
	case C.V2RayTransportTypeHTTP:
		v = &o.HTTPOptions
	case C.V2RayTransportTypeWebsocket:
		v = &o.WebsocketOptions
	case C.V2RayTransportTypeQUIC:
		v = &o.QUICOptions
	case C.V2RayTransportTypeGRPC:
		v = &o.GRPCOptions
	case C.V2RayTransportTypeHTTPUpgrade:
		v = &o.HTTPUpgradeOptions
	case C.V2RayTransportTypeXHTTP:
		v = &o.XHTTPOptions
	default:
		return E.New("unknown transport type: " + o.Type)
	}
	err = badjson.UnmarshallExcluded(bytes, (*_V2RayTransportOptions)(o), v)
	if err != nil {
		return err
	}
	return nil
}

func (o V2RayTransportOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("V2RayTransport", func() (*schema.Node, error) {
		return schema.DiscriminatedUnion(builder, "type", true, []schema.UnionVariant{
			{Value: C.V2RayTransportTypeHTTP, StructType: reflect.TypeFor[V2RayHTTPOptions]()},
			{Value: C.V2RayTransportTypeWebsocket, StructType: reflect.TypeFor[V2RayWebsocketOptions]()},
			{Value: C.V2RayTransportTypeQUIC, StructType: reflect.TypeFor[V2RayQUICOptions]()},
			{Value: C.V2RayTransportTypeGRPC, StructType: reflect.TypeFor[V2RayGRPCOptions]()},
			{Value: C.V2RayTransportTypeHTTPUpgrade, StructType: reflect.TypeFor[V2RayHTTPUpgradeOptions]()},
			{Value: C.V2RayTransportTypeXHTTP, StructType: reflect.TypeFor[V2RayXHTTPOptions]()},
		}, nil)
	})
}

type V2RayHTTPOptions struct {
	Host        badoption.Listable[string] `json:"host,omitempty"`
	Path        string                     `json:"path,omitempty"`
	Method      string                     `json:"method,omitempty"`
	Headers     badoption.HTTPHeader       `json:"headers,omitempty"`
	IdleTimeout badoption.Duration         `json:"idle_timeout,omitempty"`
	PingTimeout badoption.Duration         `json:"ping_timeout,omitempty"`
}

type V2RayWebsocketOptions struct {
	Path                string               `json:"path,omitempty"`
	Headers             badoption.HTTPHeader `json:"headers,omitempty"`
	MaxEarlyData        uint32               `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string               `json:"early_data_header_name,omitempty"`
}

type V2RayQUICOptions struct{}

type V2RayGRPCOptions struct {
	ServiceName         string             `json:"service_name,omitempty"`
	IdleTimeout         badoption.Duration `json:"idle_timeout,omitempty"`
	PingTimeout         badoption.Duration `json:"ping_timeout,omitempty"`
	PermitWithoutStream bool               `json:"permit_without_stream,omitempty"`
	ForceLite           bool               `json:"-"` // for test
}

type V2RayHTTPUpgradeOptions struct {
	Host    string               `json:"host,omitempty"`
	Path    string               `json:"path,omitempty"`
	Headers badoption.HTTPHeader `json:"headers,omitempty"`
}

// V2RayXHTTPOptions configures XHTTP (SplitHTTP) transport with split
// uplink/downlink channels, multi-placement metadata, traffic shaping, and Xmux pooling.
type V2RayXHTTPOptions struct {
	Host                 badoption.Listable[string] `json:"host,omitempty"`
	Path                 string                     `json:"path,omitempty"`
	Mode                 string                     `json:"mode,omitempty" enum:"auto,packet-up,stream-up,stream-one"`
	Headers              badoption.HTTPHeader       `json:"headers,omitempty"`
	NoGRPCHeader         bool                       `json:"no_grpc_header,omitempty"`
	NoSSEHeader          bool                       `json:"no_sse_header,omitempty"`
	XPaddingBytes        XmuxRange                  `json:"x_padding_bytes,omitempty"`
	ScMaxEachPostBytes   XmuxRange                  `json:"sc_max_each_post_bytes,omitempty"`
	ScMinPostsIntervalMs XmuxRange                  `json:"sc_min_posts_interval_ms,omitempty"`
	ScMaxBufferedPosts   XmuxRange                  `json:"sc_max_buffered_posts,omitempty"`
	ScMaxConcurrentPosts XmuxRange                  `json:"sc_max_concurrent_posts,omitempty"`
	ScStreamUpServerSecs XmuxRange                  `json:"sc_stream_up_server_secs,omitempty"`
	ScDownlinkServerSecs XmuxRange                  `json:"sc_downlink_server_secs,omitempty"`
	XPaddingPlacement    string                     `json:"x_padding_placement,omitempty" enum:"header,query,cookie,query_in_header"`
	SessionPlacement     string                     `json:"session_placement,omitempty" enum:"path,query,header,cookie"`
	SeqPlacement         string                     `json:"seq_placement,omitempty" enum:"path,query,header,cookie"`
	UplinkDataPlacement  string                     `json:"uplink_data_placement,omitempty" enum:"body,header,cookie,query"`
	UplinkChunkSize      int                        `json:"uplink_chunk_size,omitempty"`
	Xmux                 *XmuxOptions               `json:"xmux,omitempty"`
	QUIC                 *QUICOptions               `json:"quic,omitempty"`
	DownloadAddress      string                     `json:"download_address,omitempty"`
	DownloadPort         uint16                     `json:"download_port,omitempty"`
	DownloadDialer       *DialerOptions             `json:"download_dialer,omitempty"`
	DownloadTLS          *OutboundTLSOptions        `json:"download_tls,omitempty"`
	IdleTimeout          badoption.Duration         `json:"idle_timeout,omitempty"`
	PingTimeout          badoption.Duration         `json:"ping_timeout,omitempty"`
}
