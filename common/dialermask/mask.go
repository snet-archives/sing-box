package dialermask

import (
	"context"
	"net"
	"time"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ParallelInterfaceDialer matches dialer.ParallelInterfaceDialer structurally
// without introducing an import cycle between common/dialermask and common/dialer.
type ParallelInterfaceDialer interface {
	N.Dialer
	DialParallelInterface(ctx context.Context, network string, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error)
	ListenSerialInterfacePacket(ctx context.Context, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, error)
}

type udpMaskKind uint8

const (
	udpMaskNoise udpMaskKind = iota + 1
	udpMaskSalamander
)

type udpMaskEntry struct {
	kind       udpMaskKind
	noise      compiledNoise
	salamander []byte
}

type compiledFragment struct {
	packet        bool
	record        bool
	fallbackDelay time.Duration
	minLen        int
	maxLen        int
	minWait       time.Duration
	maxWait       time.Duration
}

type compiledUDPHop struct {
	ports       []uint16
	interval    time.Duration
	intervalMax time.Duration
}

// Pipeline is a validated, ordered chain of orthogonal TCP/UDP masks.
// Index 0 sits closest to the upper protocol; the last index sits closest to the wire.
type Pipeline struct {
	fragments []compiledFragment
	udpMasks  []udpMaskEntry
	udphop    *compiledUDPHop
}

// ParseMaskOptions validates masks and builds an immutable Pipeline.
func ParseMaskOptions(masks []option.MaskOptions) (*Pipeline, error) {
	p := &Pipeline{}
	for i, m := range masks {
		switch m.Type {
		case option.MaskTypeFragment:
			splitPacket := true
			if m.FragmentOptions.Packet != nil {
				splitPacket = *m.FragmentOptions.Packet
			}
			if !splitPacket && !m.FragmentOptions.Record {
				return nil, E.New("mask[", i, "] fragment: at least one of packet or record must be enabled")
			}
			minLen, maxLen, err := tf.ParseRange(m.FragmentOptions.Length)
			if err != nil {
				return nil, E.Cause(err, "mask[", i, "] fragment.length")
			}
			minWait, maxWait, err := tf.ParseDurationOrMillisRange(m.FragmentOptions.Interval)
			if err != nil {
				return nil, E.Cause(err, "mask[", i, "] fragment.interval")
			}
			p.fragments = append(p.fragments, compiledFragment{
				packet:        splitPacket,
				record:        m.FragmentOptions.Record,
				fallbackDelay: time.Duration(m.FragmentOptions.FallbackDelay),
				minLen:        minLen,
				maxLen:        maxLen,
				minWait:       minWait,
				maxWait:       maxWait,
			})
		case option.MaskTypeNoise:
			noise, err := compileNoise(m.NoiseOptions)
			if err != nil {
				return nil, E.Cause(err, "mask[", i, "] noise")
			}
			p.udpMasks = append(p.udpMasks, udpMaskEntry{kind: udpMaskNoise, noise: noise})
		case option.MaskTypeSalamander:
			if m.SalamanderOptions.Password == "" {
				return nil, E.New("mask[", i, "] salamander: missing password")
			}
			p.udpMasks = append(p.udpMasks, udpMaskEntry{
				kind:       udpMaskSalamander,
				salamander: []byte(m.SalamanderOptions.Password),
			})
		case option.MaskTypeUDPHop:
			if p.udphop != nil {
				return nil, E.New("mask[", i, "] udphop: duplicate udphop mask")
			}
			ports, err := ParsePorts(m.UDPHopOptions.Ports)
			if err != nil {
				return nil, E.Cause(err, "mask[", i, "] udphop.ports")
			}
			interval := time.Duration(m.UDPHopOptions.Interval)
			intervalMax := time.Duration(m.UDPHopOptions.IntervalMax)
			if interval < 0 || intervalMax < 0 {
				return nil, E.New("mask[", i, "] udphop: negative interval")
			}
			if interval == 0 && intervalMax == 0 {
				interval = defaultHopInterval
				intervalMax = defaultHopInterval
			} else if intervalMax == 0 {
				intervalMax = interval
			} else if interval == 0 {
				return nil, E.New("mask[", i, "] udphop: interval must be set when interval_max is set")
			} else if interval > intervalMax {
				return nil, E.New("mask[", i, "] udphop: interval exceeds interval_max")
			}
			p.udphop = &compiledUDPHop{
				ports:       ports,
				interval:    interval,
				intervalMax: intervalMax,
			}
		default:
			return nil, E.New("mask[", i, "]: unknown mask type: ", m.Type)
		}
	}
	return p, nil
}

func (p *Pipeline) HasTCPMasks() bool {
	return p != nil && len(p.fragments) > 0
}

func (p *Pipeline) HasUDPMasks() bool {
	return p != nil && (len(p.udpMasks) > 0 || p.udphop != nil)
}

func (p *Pipeline) HasUDPHop() bool {
	return p != nil && p.udphop != nil
}

func (p *Pipeline) UDPHopPorts() []uint16 {
	if p == nil || p.udphop == nil {
		return nil
	}
	return p.udphop.ports
}

// WrapTCPConn wraps a TCP stream with TCP masks preserving index 0 closest to upper layers.
func (p *Pipeline) WrapTCPConn(ctx context.Context, conn net.Conn) net.Conn {
	if p == nil || len(p.fragments) == 0 || conn == nil {
		return conn
	}
	for i := len(p.fragments) - 1; i >= 0; i-- {
		f := p.fragments[i]
		conn = tf.NewConnWithOptions(conn, tf.Options{
			Context:         ctx,
			SplitPacket:     f.packet,
			SplitRecord:     f.record,
			FallbackDelay:   f.fallbackDelay,
			FragmentMinLen:  f.minLen,
			FragmentMaxLen:  f.maxLen,
			FragmentMinWait: f.minWait,
			FragmentMaxWait: f.maxWait,
		})
	}
	return conn
}

// WrapUDPConn wraps a connected UDP net.Conn with configured UDP masks (excluding socket-level udphop).
func (p *Pipeline) WrapUDPConn(conn net.Conn) net.Conn {
	if p == nil || len(p.udpMasks) == 0 || conn == nil {
		return conn
	}
	for i := len(p.udpMasks) - 1; i >= 0; i-- {
		entry := p.udpMasks[i]
		switch entry.kind {
		case udpMaskNoise:
			conn = newNoiseConn(conn, entry.noise)
		case udpMaskSalamander:
			conn = wrapSalamanderConn(conn, entry.salamander)
		}
	}
	return conn
}

// WrapPacketConn wraps an unconnected UDP net.PacketConn with configured UDP masks.
func (p *Pipeline) WrapPacketConn(conn net.PacketConn, outboundMode bool) net.PacketConn {
	if p == nil || len(p.udpMasks) == 0 || conn == nil {
		return conn
	}
	for i := len(p.udpMasks) - 1; i >= 0; i-- {
		entry := p.udpMasks[i]
		switch entry.kind {
		case udpMaskNoise:
			conn = newNoisePacketConn(conn, entry.noise, outboundMode)
		case udpMaskSalamander:
			conn = wrapSalamanderPacketConn(conn, entry.salamander)
		}
	}
	return conn
}

// WrapTCPListener wraps a net.Listener so Accepted connections receive TCP masks.
func WrapTCPListener(ctx context.Context, inner net.Listener, masks []option.MaskOptions) (net.Listener, error) {
	if len(masks) == 0 {
		return inner, nil
	}
	pipeline, err := ParseMaskOptions(masks)
	if err != nil {
		return nil, err
	}
	if !pipeline.HasTCPMasks() {
		return inner, nil
	}
	return &maskTCPListener{
		Listener: inner,
		ctx:      ctx,
		pipeline: pipeline,
	}, nil
}

type maskTCPListener struct {
	net.Listener
	ctx      context.Context
	pipeline *Pipeline
}

func (l *maskTCPListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.pipeline.WrapTCPConn(l.ctx, conn), nil
}

func (l *maskTCPListener) Upstream() any {
	return l.Listener
}

// WrapDialer wraps dialer with configured orthogonal masks while preserving
// Upstream() and optional ParallelInterfaceDialer support.
func WrapDialer(dialer N.Dialer, ctx context.Context, masks []option.MaskOptions) (N.Dialer, error) {
	if len(masks) == 0 {
		return dialer, nil
	}
	pipeline, err := ParseMaskOptions(masks)
	if err != nil {
		return nil, err
	}
	if !pipeline.HasTCPMasks() && !pipeline.HasUDPMasks() {
		return dialer, nil
	}
	md := &maskDialer{
		dialer:   dialer,
		pipeline: pipeline,
	}
	if parallel, ok := dialer.(ParallelInterfaceDialer); ok {
		return &parallelMaskDialer{
			maskDialer: md,
			parallel:   parallel,
		}, nil
	}
	return md, nil
}

type maskDialer struct {
	dialer   N.Dialer
	pipeline *Pipeline
}

func (d *maskDialer) Upstream() any {
	return d.dialer
}

func (d *maskDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		conn, err := d.dialer.DialContext(ctx, network, destination)
		if err != nil {
			return nil, err
		}
		return d.pipeline.WrapTCPConn(ctx, conn), nil
	case N.NetworkUDP:
		if d.pipeline.udphop != nil {
			conn, err := newHopConn(func(target M.Socksaddr) (net.Conn, error) {
				return d.dialer.DialContext(ctx, network, target)
			}, destination, d.pipeline.udphop)
			if err != nil {
				return nil, err
			}
			return d.pipeline.WrapUDPConn(conn), nil
		}
		conn, err := d.dialer.DialContext(ctx, network, destination)
		if err != nil {
			return nil, err
		}
		return d.pipeline.WrapUDPConn(conn), nil
	default:
		return d.dialer.DialContext(ctx, network, destination)
	}
}

func (d *maskDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if d.pipeline.udphop != nil {
		conn, err := newHopPacketConn(func() (net.PacketConn, error) {
			return d.dialer.ListenPacket(ctx, destination)
		}, destination, d.pipeline.udphop)
		if err != nil {
			return nil, err
		}
		return d.pipeline.WrapPacketConn(conn, true), nil
	}
	conn, err := d.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return d.pipeline.WrapPacketConn(conn, true), nil
}

type parallelMaskDialer struct {
	*maskDialer
	parallel ParallelInterfaceDialer
}

func (d *parallelMaskDialer) DialParallelInterface(ctx context.Context, network string, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		conn, err := d.parallel.DialParallelInterface(ctx, network, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
		if err != nil {
			return nil, err
		}
		return d.pipeline.WrapTCPConn(ctx, conn), nil
	case N.NetworkUDP:
		if d.pipeline.udphop != nil {
			conn, err := newHopConn(func(target M.Socksaddr) (net.Conn, error) {
				return d.parallel.DialParallelInterface(ctx, network, target, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
			}, destination, d.pipeline.udphop)
			if err != nil {
				return nil, err
			}
			return d.pipeline.WrapUDPConn(conn), nil
		}
		conn, err := d.parallel.DialParallelInterface(ctx, network, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
		if err != nil {
			return nil, err
		}
		return d.pipeline.WrapUDPConn(conn), nil
	default:
		return d.parallel.DialParallelInterface(ctx, network, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
}

func (d *parallelMaskDialer) ListenSerialInterfacePacket(ctx context.Context, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, error) {
	if d.pipeline.udphop != nil {
		conn, err := newHopPacketConn(func() (net.PacketConn, error) {
			return d.parallel.ListenSerialInterfacePacket(ctx, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
		}, destination, d.pipeline.udphop)
		if err != nil {
			return nil, err
		}
		return d.pipeline.WrapPacketConn(conn, true), nil
	}
	conn, err := d.parallel.ListenSerialInterfacePacket(ctx, destination, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	if err != nil {
		return nil, err
	}
	return d.pipeline.WrapPacketConn(conn, true), nil
}

type salamanderConnWrapper struct {
	net.Conn
}

func wrapSalamanderConn(conn net.Conn, password []byte) net.Conn {
	return &salamanderConnWrapper{Conn: hysteria2.NewSalamanderClientConn(conn, password)}
}

func (c *salamanderConnWrapper) ReaderReplaceable() bool {
	return false
}

func (c *salamanderConnWrapper) WriterReplaceable() bool {
	return false
}

func (c *salamanderConnWrapper) Upstream() any {
	return c.Conn
}

type salamanderPacketConnWrapper struct {
	net.PacketConn
	vec N.VectorisedPacketWriter
}

func wrapSalamanderPacketConn(conn net.PacketConn, password []byte) net.PacketConn {
	wrapped := hysteria2.NewSalamanderConn(conn, password)
	vec, _ := wrapped.(N.VectorisedPacketWriter)
	if vec != nil {
		return &vectorisedSalamanderPacketConnWrapper{
			salamanderPacketConnWrapper: salamanderPacketConnWrapper{
				PacketConn: wrapped,
				vec:        vec,
			},
		}
	}
	return &salamanderPacketConnWrapper{PacketConn: wrapped}
}

func (c *salamanderPacketConnWrapper) ReaderReplaceable() bool {
	return false
}

func (c *salamanderPacketConnWrapper) WriterReplaceable() bool {
	return false
}

func (c *salamanderPacketConnWrapper) Upstream() any {
	return c.PacketConn
}

type vectorisedSalamanderPacketConnWrapper struct {
	salamanderPacketConnWrapper
}

func (c *vectorisedSalamanderPacketConnWrapper) WriteVectorisedPacket(buffers []*buf.Buffer, destination M.Socksaddr) error {
	return c.vec.WriteVectorisedPacket(buffers, destination)
}

var _ = common.WithUpstream((*salamanderConnWrapper)(nil))
