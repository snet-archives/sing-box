package option

import (
	"reflect"

	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
)

const (
	MaskTypeFragment   = "fragment"
	MaskTypeNoise      = "noise"
	MaskTypeSalamander = "salamander"
	MaskTypeUDPHop     = "udphop"
)

// MaskFragmentOptions configures TCP first-packet / TLS handshake fragmentation
// as an orthogonal dialer or listener mask.
type MaskFragmentOptions struct {
	Packet        *bool              `json:"packet,omitempty"`
	Record        bool               `json:"record,omitempty"`
	Length        string             `json:"length,omitempty"`
	Interval      string             `json:"interval,omitempty"`
	FallbackDelay badoption.Duration `json:"fallback_delay,omitempty"`
}

// MaskNoiseOptions configures pre-session UDP random padding packets.
type MaskNoiseOptions struct {
	Count    int                `json:"count,omitempty"`
	MinSize  int                `json:"min_size,omitempty"`
	MaxSize  int                `json:"max_size,omitempty"`
	Interval badoption.Duration `json:"interval,omitempty"`
}

// MaskSalamanderOptions configures Hysteria2-compatible BLAKE2b UDP payload
// obfuscation as an orthogonal mask.
type MaskSalamanderOptions struct {
	Password string `json:"password"`
}

// MaskUDPHopOptions configures orthogonal multi-port UDP hopping.
type MaskUDPHopOptions struct {
	Ports       badoption.Listable[string] `json:"ports"`
	Interval    badoption.Duration         `json:"interval,omitempty"`
	IntervalMax badoption.Duration         `json:"interval_max,omitempty"`
}

type _MaskOptions struct {
	Type              string                `json:"type" enum:"fragment,noise,salamander,udphop"`
	FragmentOptions   MaskFragmentOptions   `json:"-"`
	NoiseOptions      MaskNoiseOptions      `json:"-"`
	SalamanderOptions MaskSalamanderOptions `json:"-"`
	UDPHopOptions     MaskUDPHopOptions     `json:"-"`
}

// MaskOptions represents one polymorphic transport mask entry attached to
// DialerOptions or ListenOptions.
type MaskOptions _MaskOptions

func (o MaskOptions) MarshalJSON() ([]byte, error) {
	var v any
	switch o.Type {
	case MaskTypeFragment:
		v = o.FragmentOptions
	case MaskTypeNoise:
		v = o.NoiseOptions
	case MaskTypeSalamander:
		v = o.SalamanderOptions
	case MaskTypeUDPHop:
		v = o.UDPHopOptions
	default:
		return nil, E.New("unknown mask type: ", o.Type)
	}
	return badjson.MarshallObjects(_MaskOptions(o), v)
}

func (o *MaskOptions) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_MaskOptions)(o))
	if err != nil {
		return err
	}
	var v any
	switch o.Type {
	case MaskTypeFragment:
		v = &o.FragmentOptions
	case MaskTypeNoise:
		v = &o.NoiseOptions
	case MaskTypeSalamander:
		v = &o.SalamanderOptions
	case MaskTypeUDPHop:
		v = &o.UDPHopOptions
	default:
		return E.New("unknown mask type: ", o.Type)
	}
	return badjson.UnmarshallExcluded(bytes, (*_MaskOptions)(o), v)
}

func (o MaskOptions) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return schema.DiscriminatedUnion(builder, "type", true, []schema.UnionVariant{
		{Value: MaskTypeFragment, StructType: reflect.TypeFor[MaskFragmentOptions]()},
		{Value: MaskTypeNoise, StructType: reflect.TypeFor[MaskNoiseOptions]()},
		{Value: MaskTypeSalamander, StructType: reflect.TypeFor[MaskSalamanderOptions]()},
		{Value: MaskTypeUDPHop, StructType: reflect.TypeFor[MaskUDPHopOptions]()},
	}, nil)
}
