package dialermask

import (
	"crypto/rand"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

const (
	defaultNoiseCount   = 4
	maxNoiseCount       = 64
	defaultNoiseMinSize = 64
	defaultNoiseMaxSize = 512
	maxNoiseSize        = 65507
	maxNoisePeers       = 4096
)

type compiledNoise struct {
	count    int
	minSize  int
	maxSize  int
	interval time.Duration
}

func compileNoise(opt option.MaskNoiseOptions) (compiledNoise, error) {
	count := opt.Count
	if count == 0 {
		count = defaultNoiseCount
	}
	if count < 0 || count > maxNoiseCount {
		return compiledNoise{}, E.New("noise count out of range [1, ", maxNoiseCount, "]: ", opt.Count)
	}
	minSize := opt.MinSize
	maxSize := opt.MaxSize
	if minSize < 0 || maxSize < 0 {
		return compiledNoise{}, E.New("noise packet sizes must be non-negative")
	}
	if minSize == 0 && maxSize == 0 {
		minSize = defaultNoiseMinSize
		maxSize = defaultNoiseMaxSize
	} else if maxSize == 0 {
		maxSize = minSize
	} else if minSize == 0 {
		minSize = 1
		if minSize > maxSize {
			minSize = maxSize
		}
	}
	if maxSize < minSize || maxSize > maxNoiseSize {
		return compiledNoise{}, E.New("invalid noise packet size range: ", minSize, "-", maxSize)
	}
	interval := time.Duration(opt.Interval)
	if interval < 0 {
		return compiledNoise{}, E.New("negative noise interval: ", interval)
	}
	return compiledNoise{
		count:    count,
		minSize:  minSize,
		maxSize:  maxSize,
		interval: interval,
	}, nil
}

func randomNoisePayload(cfg compiledNoise) []byte {
	size := cfg.minSize
	if cfg.maxSize > cfg.minSize {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(cfg.maxSize-cfg.minSize+1)))
		if err == nil {
			size += int(n.Int64())
		}
	}
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	return payload
}

type noiseConn struct {
	net.Conn
	cfg     compiledNoise
	once    sync.Once
	emitted atomic.Bool
}

var (
	_ N.ReaderWithUpstream = (*noiseConn)(nil)
	_ N.WriterWithUpstream = (*noiseConn)(nil)
	_ N.EarlyWriter        = (*noiseConn)(nil)
	_ common.WithUpstream  = (*noiseConn)(nil)
)

func newNoiseConn(conn net.Conn, cfg compiledNoise) *noiseConn {
	return &noiseConn{Conn: conn, cfg: cfg}
}

func (c *noiseConn) emit() {
	c.once.Do(func() {
		defer c.emitted.Store(true)
		for i := 0; i < c.cfg.count; i++ {
			payload := randomNoisePayload(c.cfg)
			_, _ = c.Conn.Write(payload)
			if c.cfg.interval > 0 && i+1 < c.cfg.count {
				time.Sleep(c.cfg.interval)
			}
		}
	})
}

func (c *noiseConn) Write(p []byte) (int, error) {
	if !c.emitted.Load() {
		c.emit()
	}
	return c.Conn.Write(p)
}

func (c *noiseConn) ReaderReplaceable() bool {
	return true
}

func (c *noiseConn) WriterReplaceable() bool {
	return c.emitted.Load()
}

func (c *noiseConn) NeedHandshakeForWrite() bool {
	return !c.emitted.Load()
}

func (c *noiseConn) Upstream() any {
	return c.Conn
}

type noisePacketConn struct {
	net.PacketConn
	cfg          compiledNoise
	outboundMode bool
	emittedOnce  atomic.Bool
	peersMu      sync.Mutex
	peers        map[string]struct{}
}

var (
	_ N.ReaderWithUpstream = (*noisePacketConn)(nil)
	_ N.WriterWithUpstream = (*noisePacketConn)(nil)
	_ common.WithUpstream  = (*noisePacketConn)(nil)
)

func newNoisePacketConn(conn net.PacketConn, cfg compiledNoise, outboundMode bool) *noisePacketConn {
	return &noisePacketConn{
		PacketConn:   conn,
		cfg:          cfg,
		outboundMode: outboundMode,
		peers:        make(map[string]struct{}),
	}
}

func (c *noisePacketConn) ensurePeerEmitted(addr net.Addr) {
	if addr == nil {
		return
	}
	key := addr.String()
	c.peersMu.Lock()
	_, seen := c.peers[key]
	if !seen {
		if len(c.peers) >= maxNoisePeers {
			clear(c.peers)
		}
		c.peers[key] = struct{}{}
	}
	c.peersMu.Unlock()
	if seen {
		return
	}
	for i := 0; i < c.cfg.count; i++ {
		payload := randomNoisePayload(c.cfg)
		_, _ = c.PacketConn.WriteTo(payload, addr)
		if c.cfg.interval > 0 && i+1 < c.cfg.count {
			time.Sleep(c.cfg.interval)
		}
	}
	c.emittedOnce.Store(true)
}

func (c *noisePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.ensurePeerEmitted(addr)
	return c.PacketConn.WriteTo(p, addr)
}

func (c *noisePacketConn) ReaderReplaceable() bool {
	return true
}

func (c *noisePacketConn) WriterReplaceable() bool {
	return c.outboundMode && c.emittedOnce.Load()
}

func (c *noisePacketConn) Upstream() any {
	return c.PacketConn
}
