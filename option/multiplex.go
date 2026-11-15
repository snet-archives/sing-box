package option

import (
	"fmt"
	"reflect"

	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing-mux"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

type InboundMultiplexOptions struct {
	Enabled bool           `json:"enabled,omitempty"`
	Padding bool           `json:"padding,omitempty"`
	Brutal  *BrutalOptions `json:"brutal,omitempty"`
}

type OutboundMultiplexOptions struct {
	Enabled        bool           `json:"enabled,omitempty"`
	Protocol       string         `json:"protocol,omitempty" enum:"h2mux,smux,yamux"`
	MaxConnections int            `json:"max_connections,omitempty"`
	MinStreams     int            `json:"min_streams,omitempty"`
	MaxStreams     int            `json:"max_streams,omitempty"`
	Padding        bool           `json:"padding,omitempty"`
	Brutal         *BrutalOptions `json:"brutal,omitempty"`
	Xmux           *XmuxOptions   `json:"xmux,omitempty"`
}

type BrutalOptions struct {
	Enabled  bool `json:"enabled,omitempty"`
	UpMbps   int  `json:"up_mbps,omitempty"`
	DownMbps int  `json:"down_mbps,omitempty"`
}

// XmuxRange accepts a JSON integer (8), a range string ("4-8"), or an object
// ({"from": 4, "to": 8}) representing bounded randomized Xmux lifecycle bounds.
type XmuxRange mux.XmuxRange

type xmuxRangeObject struct {
	From int  `json:"from"`
	To   *int `json:"to,omitempty"`
}

func (r XmuxRange) IsZero() bool {
	return mux.XmuxRange(r).IsZero()
}

func (r XmuxRange) MarshalJSON() ([]byte, error) {
	norm := mux.XmuxRange(r).Normalized()
	if norm.From == norm.To {
		return json.Marshal(norm.From)
	}
	return json.Marshal(fmt.Sprintf("%d-%d", norm.From, norm.To))
}

func (r *XmuxRange) UnmarshalJSON(data []byte) error {
	var intVal int
	if err := json.Unmarshal(data, &intVal); err == nil {
		if intVal < 0 {
			return E.New("xmux range must be non-negative: ", intVal)
		}
		*r = XmuxRange{From: intVal, To: intVal}
		return nil
	}
	var strVal string
	if err := json.Unmarshal(data, &strVal); err == nil {
		parsed, err := mux.ParseXmuxRange(strVal)
		if err != nil {
			return err
		}
		*r = XmuxRange(parsed)
		return nil
	}
	var obj xmuxRangeObject
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	if obj.From < 0 || (obj.To != nil && *obj.To < 0) {
		return E.New("xmux range values must be non-negative")
	}
	to := obj.From
	if obj.To != nil {
		to = *obj.To
		if obj.From > to {
			return E.New("xmux range min ", obj.From, " exceeds max ", to)
		}
	}
	*r = XmuxRange{From: obj.From, To: to}
	return nil
}

func (r XmuxRange) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	objectForm := schema.StrictObject()
	if err := builder.FlattenStruct(objectForm, reflect.TypeFor[xmuxRangeObject]()); err != nil {
		return nil, err
	}
	return schema.AnyOf(schema.StringNode(), schema.UnsignedNode(32), objectForm), nil
}

// XmuxOptions configures bounded randomized session lifecycle parameters for
// multiplexed transports and HTTP connection pools.
type XmuxOptions struct {
	MaxConcurrency   XmuxRange `json:"max_concurrency,omitempty"`
	MaxConnections   XmuxRange `json:"max_connections,omitempty"`
	CMaxReuseTimes   XmuxRange `json:"c_max_reuse_times,omitempty"`
	HMaxRequestTimes XmuxRange `json:"h_max_request_times,omitempty"`
	HMaxReusableSecs XmuxRange `json:"h_max_reusable_secs,omitempty"`
	HKeepAlivePeriod XmuxRange `json:"h_keep_alive_period,omitempty"`
}

func (o *XmuxOptions) ToMux() mux.XmuxOptions {
	if o == nil {
		return mux.XmuxOptions{}
	}
	return mux.XmuxOptions{
		MaxConcurrency:   mux.XmuxRange(o.MaxConcurrency),
		MaxConnections:   mux.XmuxRange(o.MaxConnections),
		CMaxReuseTimes:   mux.XmuxRange(o.CMaxReuseTimes),
		HMaxRequestTimes: mux.XmuxRange(o.HMaxRequestTimes),
		HMaxReusableSecs: mux.XmuxRange(o.HMaxReusableSecs),
		HKeepAlivePeriod: mux.XmuxRange(o.HKeepAlivePeriod),
	}
}
