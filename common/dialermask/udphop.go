package dialermask

import (
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	hopPacketQueueSize = 1024
	hopUDPBufferSize   = 65535
	defaultHopInterval = 30 * time.Second
	maxServerHopPorts  = 256
)

// ParsePorts parses single ports ("443") and inclusive ranges ("10000-20000" or
// "10000:20000") into a sorted deduplicated port list.
func ParsePorts(specs []string) ([]uint16, error) {
	if len(specs) == 0 {
		return nil, E.New("empty port list")
	}
	seen := make(map[uint16]struct{})
	var ports []uint16
	for _, raw := range specs {
		spec := strings.TrimSpace(raw)
		if spec == "" {
			continue
		}
		sep := "-"
		if !strings.Contains(spec, "-") && strings.Contains(spec, ":") {
			sep = ":"
		}
		if left, right, ok := strings.Cut(spec, sep); ok {
			start, err := strconv.Atoi(strings.TrimSpace(left))
			if err != nil || start <= 0 || start > 65535 {
				return nil, E.New("invalid start port in range: ", spec)
			}
			end, err := strconv.Atoi(strings.TrimSpace(right))
			if err != nil || end <= 0 || end > 65535 || start > end {
				return nil, E.New("invalid end port in range: ", spec)
			}
			for port := start; port <= end; port++ {
				u16 := uint16(port)
				if _, exists := seen[u16]; !exists {
					seen[u16] = struct{}{}
					ports = append(ports, u16)
				}
			}
			continue
		}
		port, err := strconv.Atoi(spec)
		if err != nil || port <= 0 || port > 65535 {
			return nil, E.New("invalid port: ", spec)
		}
		u16 := uint16(port)
		if _, exists := seen[u16]; !exists {
			seen[u16] = struct{}{}
			ports = append(ports, u16)
		}
	}
	if len(ports) == 0 {
		return nil, E.New("no valid ports resolved")
	}
	slices.Sort(ports)
	return ports, nil
}

func randomHopPort(ports []uint16) uint16 {
	if len(ports) == 1 {
		return ports[0]
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(ports))))
	if err != nil {
		return ports[0]
	}
	return ports[n.Int64()]
}

func nextHopInterval(interval, intervalMax time.Duration) time.Duration {
	if intervalMax <= interval {
		return interval
	}
	diff := int64(intervalMax - interval + 1)
	n, err := rand.Int(rand.Reader, big.NewInt(diff))
	if err != nil {
		return interval
	}
	return interval + time.Duration(n.Int64())
}

type receivedPacket struct {
	buffer *buf.Buffer
	addr   net.Addr
}

type hopDeadlineState struct {
	mu             sync.Mutex
	readDeadline   time.Time
	writeDeadline  time.Time
	deadlineNotify chan struct{}
}

func newHopDeadlineState() hopDeadlineState {
	return hopDeadlineState{
		deadlineNotify: make(chan struct{}),
	}
}

func (s *hopDeadlineState) setReadDeadline(t time.Time) {
	s.mu.Lock()
	s.readDeadline = t
	close(s.deadlineNotify)
	s.deadlineNotify = make(chan struct{})
	s.mu.Unlock()
}

func (s *hopDeadlineState) getReadDeadline() (time.Time, <-chan struct{}) {
	s.mu.Lock()
	d, ch := s.readDeadline, s.deadlineNotify
	s.mu.Unlock()
	return d, ch
}

func (s *hopDeadlineState) popPacket(packetChan <-chan receivedPacket, doneChan <-chan struct{}) (receivedPacket, error) {
	for {
		deadline, notifyCh := s.getReadDeadline()
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return receivedPacket{}, os.ErrDeadlineExceeded
		}
		select {
		case pkt := <-packetChan:
			return pkt, nil
		case <-doneChan:
			return receivedPacket{}, net.ErrClosed
		default:
		}
		var timer *time.Timer
		var timerCh <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timerCh = timer.C
		}
		select {
		case pkt := <-packetChan:
			if timer != nil {
				timer.Stop()
			}
			return pkt, nil
		case <-timerCh:
			return receivedPacket{}, os.ErrDeadlineExceeded
		case <-notifyCh:
			if timer != nil {
				timer.Stop()
			}
		case <-doneChan:
			if timer != nil {
				timer.Stop()
			}
			return receivedPacket{}, net.ErrClosed
		}
	}
}

func isTemporaryHopErr(err error) bool {
	if errors.Is(err, syscall.EMSGSIZE) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

type hopConn struct {
	dialFunc    func(M.Socksaddr) (net.Conn, error)
	destination M.Socksaddr
	cfg         *compiledUDPHop
	access      sync.Mutex
	prevConn    net.Conn
	currentConn net.Conn
	deadlines   hopDeadlineState
	packetChan  chan receivedPacket
	doneChan    chan struct{}
	done        bool
}

var (
	_ N.ReaderWithUpstream = (*hopConn)(nil)
	_ N.WriterWithUpstream = (*hopConn)(nil)
	_ common.WithUpstream  = (*hopConn)(nil)
)

func newHopConn(dialFunc func(M.Socksaddr) (net.Conn, error), destination M.Socksaddr, cfg *compiledUDPHop) (*hopConn, error) {
	c := &hopConn{
		dialFunc:    dialFunc,
		destination: destination,
		cfg:         cfg,
		deadlines:   newHopDeadlineState(),
		packetChan:  make(chan receivedPacket, hopPacketQueueSize),
		doneChan:    make(chan struct{}),
	}
	firstPort := randomHopPort(cfg.ports)
	firstTarget := M.Socksaddr{
		Addr: destination.Addr,
		Fqdn: destination.Fqdn,
		Port: firstPort,
	}
	conn, err := dialFunc(firstTarget)
	if err != nil {
		return nil, err
	}
	if destination.IsFqdn() {
		remoteAddr := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
		if remoteAddr.IsIP() {
			c.destination = M.Socksaddr{Addr: remoteAddr.Addr}
		}
	}
	c.currentConn = conn
	go c.recvLoop(conn)
	go c.hopLoop()
	return c, nil
}

func (c *hopConn) recvLoop(conn net.Conn) {
	for {
		buffer := buf.NewSize(hopUDPBufferSize)
		n, err := conn.Read(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			if isTemporaryHopErr(err) {
				select {
				case <-c.doneChan:
					return
				default:
					continue
				}
			}
			return
		}
		buffer.Truncate(n)
		select {
		case c.packetChan <- receivedPacket{buffer: buffer}:
		default:
			buffer.Release()
		}
	}
}

func (c *hopConn) hopLoop() {
	timer := time.NewTimer(nextHopInterval(c.cfg.interval, c.cfg.intervalMax))
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			c.hop()
			timer.Reset(nextHopInterval(c.cfg.interval, c.cfg.intervalMax))
		case <-c.doneChan:
			return
		}
	}
}

func (c *hopConn) hop() {
	c.access.Lock()
	if c.done {
		c.access.Unlock()
		return
	}
	target := M.Socksaddr{
		Addr: c.destination.Addr,
		Fqdn: c.destination.Fqdn,
		Port: randomHopPort(c.cfg.ports),
	}
	c.access.Unlock()

	newConn, err := c.dialFunc(target)
	if err != nil {
		return
	}

	c.access.Lock()
	if c.done {
		c.access.Unlock()
		_ = newConn.Close()
		return
	}
	c.deadlines.mu.Lock()
	wd := c.deadlines.writeDeadline
	c.deadlines.mu.Unlock()
	if !wd.IsZero() {
		_ = newConn.SetWriteDeadline(wd)
	}
	oldPrev := c.prevConn
	c.prevConn = c.currentConn
	c.currentConn = newConn
	c.access.Unlock()

	if oldPrev != nil {
		_ = oldPrev.Close()
	}
	go c.recvLoop(newConn)
}

func (c *hopConn) Read(b []byte) (int, error) {
	pkt, err := c.deadlines.popPacket(c.packetChan, c.doneChan)
	if err != nil {
		return 0, err
	}
	n := copy(b, pkt.buffer.Bytes())
	pkt.buffer.Release()
	return n, nil
}

func (c *hopConn) Write(b []byte) (int, error) {
	c.access.Lock()
	conn := c.currentConn
	closed := c.done
	c.access.Unlock()
	if closed || conn == nil {
		return 0, net.ErrClosed
	}
	return conn.Write(b)
}

func (c *hopConn) Close() error {
	c.access.Lock()
	if c.done {
		c.access.Unlock()
		return nil
	}
	c.done = true
	close(c.doneChan)
	prevConn := c.prevConn
	currentConn := c.currentConn
	c.access.Unlock()

	drainPacketChan(c.packetChan)
	var err error
	if prevConn != nil {
		err = prevConn.Close()
	}
	if currentConn != nil {
		if err2 := currentConn.Close(); err == nil {
			err = err2
		}
	}
	return err
}

func (c *hopConn) LocalAddr() net.Addr {
	c.access.Lock()
	conn := c.currentConn
	c.access.Unlock()
	if conn == nil {
		return nil
	}
	return conn.LocalAddr()
}

func (c *hopConn) RemoteAddr() net.Addr {
	return c.destination.UDPAddr()
}

func (c *hopConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *hopConn) SetReadDeadline(t time.Time) error {
	c.deadlines.setReadDeadline(t)
	return nil
}

func (c *hopConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.mu.Lock()
	c.deadlines.writeDeadline = t
	c.deadlines.mu.Unlock()
	c.access.Lock()
	prevConn := c.prevConn
	currentConn := c.currentConn
	c.access.Unlock()
	if prevConn != nil {
		_ = prevConn.SetWriteDeadline(t)
	}
	if currentConn != nil {
		return currentConn.SetWriteDeadline(t)
	}
	return nil
}

func (c *hopConn) ReaderReplaceable() bool {
	return false
}

func (c *hopConn) WriterReplaceable() bool {
	return false
}

func (c *hopConn) Upstream() any {
	c.access.Lock()
	conn := c.currentConn
	c.access.Unlock()
	return conn
}

type hopPacketConn struct {
	listenFunc  func() (net.PacketConn, error)
	logicalDst  M.Socksaddr
	cfg         *compiledUDPHop
	access      sync.Mutex
	prevConn    net.PacketConn
	currentConn net.PacketConn
	remotePort  uint16
	deadlines   hopDeadlineState
	packetChan  chan receivedPacket
	doneChan    chan struct{}
	done        bool
}

var (
	_ N.ReaderWithUpstream = (*hopPacketConn)(nil)
	_ N.WriterWithUpstream = (*hopPacketConn)(nil)
	_ common.WithUpstream  = (*hopPacketConn)(nil)
)

func newHopPacketConn(listenFunc func() (net.PacketConn, error), destination M.Socksaddr, cfg *compiledUDPHop) (*hopPacketConn, error) {
	conn, err := listenFunc()
	if err != nil {
		return nil, err
	}
	c := &hopPacketConn{
		listenFunc:  listenFunc,
		logicalDst:  destination,
		cfg:         cfg,
		currentConn: conn,
		remotePort:  randomHopPort(cfg.ports),
		deadlines:   newHopDeadlineState(),
		packetChan:  make(chan receivedPacket, hopPacketQueueSize),
		doneChan:    make(chan struct{}),
	}
	go c.recvLoop(conn)
	go c.hopLoop()
	return c, nil
}

func (c *hopPacketConn) recvLoop(conn net.PacketConn) {
	for {
		buffer := buf.NewSize(hopUDPBufferSize)
		n, addr, err := conn.ReadFrom(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			if isTemporaryHopErr(err) {
				select {
				case <-c.doneChan:
					return
				default:
					continue
				}
			}
			return
		}
		buffer.Truncate(n)
		if c.logicalDst.Port != 0 {
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				norm := *udpAddr
				norm.Port = int(c.logicalDst.Port)
				addr = &norm
			}
		}
		select {
		case c.packetChan <- receivedPacket{buffer: buffer, addr: addr}:
		default:
			buffer.Release()
		}
	}
}

func (c *hopPacketConn) hopLoop() {
	timer := time.NewTimer(nextHopInterval(c.cfg.interval, c.cfg.intervalMax))
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			c.hop()
			timer.Reset(nextHopInterval(c.cfg.interval, c.cfg.intervalMax))
		case <-c.doneChan:
			return
		}
	}
}

func (c *hopPacketConn) hop() {
	c.access.Lock()
	if c.done {
		c.access.Unlock()
		return
	}
	c.remotePort = randomHopPort(c.cfg.ports)
	c.access.Unlock()

	newConn, err := c.listenFunc()
	if err != nil {
		return
	}

	c.access.Lock()
	if c.done {
		c.access.Unlock()
		_ = newConn.Close()
		return
	}
	c.deadlines.mu.Lock()
	wd := c.deadlines.writeDeadline
	c.deadlines.mu.Unlock()
	if !wd.IsZero() {
		_ = newConn.SetWriteDeadline(wd)
	}
	oldPrev := c.prevConn
	c.prevConn = c.currentConn
	c.currentConn = newConn
	c.access.Unlock()

	if oldPrev != nil {
		_ = oldPrev.Close()
	}
	go c.recvLoop(newConn)
}

func (c *hopPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, err := c.deadlines.popPacket(c.packetChan, c.doneChan)
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, pkt.buffer.Bytes())
	pkt.buffer.Release()
	return n, pkt.addr, nil
}

func (c *hopPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.access.Lock()
	conn := c.currentConn
	port := c.remotePort
	closed := c.done
	c.access.Unlock()
	if closed || conn == nil {
		return 0, net.ErrClosed
	}
	targetAddr := addr
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		rewritten := *udpAddr
		rewritten.Port = int(port)
		targetAddr = &rewritten
	} else {
		sa := M.SocksaddrFromNet(addr)
		sa.Port = port
		targetAddr = sa.UDPAddr()
	}
	return conn.WriteTo(p, targetAddr)
}

func (c *hopPacketConn) Close() error {
	c.access.Lock()
	if c.done {
		c.access.Unlock()
		return nil
	}
	c.done = true
	close(c.doneChan)
	prevConn := c.prevConn
	currentConn := c.currentConn
	c.access.Unlock()

	drainPacketChan(c.packetChan)
	var err error
	if prevConn != nil {
		err = prevConn.Close()
	}
	if currentConn != nil {
		if err2 := currentConn.Close(); err == nil {
			err = err2
		}
	}
	return err
}

func (c *hopPacketConn) LocalAddr() net.Addr {
	c.access.Lock()
	conn := c.currentConn
	c.access.Unlock()
	if conn == nil {
		return nil
	}
	return conn.LocalAddr()
}

func (c *hopPacketConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *hopPacketConn) SetReadDeadline(t time.Time) error {
	c.deadlines.setReadDeadline(t)
	return nil
}

func (c *hopPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlines.mu.Lock()
	c.deadlines.writeDeadline = t
	c.deadlines.mu.Unlock()
	c.access.Lock()
	prevConn := c.prevConn
	currentConn := c.currentConn
	c.access.Unlock()
	if prevConn != nil {
		_ = prevConn.SetWriteDeadline(t)
	}
	if currentConn != nil {
		return currentConn.SetWriteDeadline(t)
	}
	return nil
}

func (c *hopPacketConn) ReaderReplaceable() bool {
	return false
}

func (c *hopPacketConn) WriterReplaceable() bool {
	return false
}

func (c *hopPacketConn) Upstream() any {
	c.access.Lock()
	conn := c.currentConn
	c.access.Unlock()
	return conn
}

// HopServerPacketConn multiplexes multiple bound UDP sockets into one PacketConn
// and remembers the active local socket per peer for symmetric return traffic.
type HopServerPacketConn struct {
	conns      []net.PacketConn
	deadlines  hopDeadlineState
	packetChan chan receivedPacket
	doneChan   chan struct{}
	access     sync.Mutex
	done       bool
	peerMu     sync.RWMutex
	peerSocket map[string]int
}

var (
	_ N.ReaderWithUpstream = (*HopServerPacketConn)(nil)
	_ N.WriterWithUpstream = (*HopServerPacketConn)(nil)
	_ common.WithUpstream  = (*HopServerPacketConn)(nil)
)

// NewHopServerPacketConn opens a UDP PacketConn for every port in ports via listenPortFn.
func NewHopServerPacketConn(ports []uint16, listenPortFn func(port uint16) (net.PacketConn, error)) (*HopServerPacketConn, error) {
	if len(ports) == 0 {
		return nil, E.New("udphop server: empty port list")
	}
	if len(ports) > maxServerHopPorts {
		return nil, E.New("udphop server: port count ", len(ports), " exceeds limit ", maxServerHopPorts)
	}
	conns := make([]net.PacketConn, 0, len(ports))
	for _, port := range ports {
		c, err := listenPortFn(port)
		if err != nil {
			for _, opened := range conns {
				_ = opened.Close()
			}
			return nil, E.Cause(err, "udphop server listen port ", port)
		}
		conns = append(conns, c)
	}
	s := &HopServerPacketConn{
		conns:      conns,
		deadlines:  newHopDeadlineState(),
		packetChan: make(chan receivedPacket, hopPacketQueueSize),
		doneChan:   make(chan struct{}),
		peerSocket: make(map[string]int),
	}
	for idx, conn := range conns {
		go s.recvLoop(idx, conn)
	}
	return s, nil
}

func (s *HopServerPacketConn) recvLoop(index int, conn net.PacketConn) {
	for {
		buffer := buf.NewSize(hopUDPBufferSize)
		n, addr, err := conn.ReadFrom(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			if isTemporaryHopErr(err) {
				select {
				case <-s.doneChan:
					return
				default:
					continue
				}
			}
			return
		}
		buffer.Truncate(n)
		if addr != nil {
			s.peerMu.Lock()
			if len(s.peerSocket) >= maxNoisePeers {
				clear(s.peerSocket)
			}
			s.peerSocket[addr.String()] = index
			s.peerMu.Unlock()
		}
		select {
		case s.packetChan <- receivedPacket{buffer: buffer, addr: addr}:
		default:
			buffer.Release()
		}
	}
}

func (s *HopServerPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, err := s.deadlines.popPacket(s.packetChan, s.doneChan)
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, pkt.buffer.Bytes())
	pkt.buffer.Release()
	return n, pkt.addr, nil
}

func (s *HopServerPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	s.access.Lock()
	closed := s.done
	s.access.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	idx := 0
	if addr != nil {
		s.peerMu.RLock()
		if mapped, ok := s.peerSocket[addr.String()]; ok {
			idx = mapped
		}
		s.peerMu.RUnlock()
	}
	return s.conns[idx].WriteTo(p, addr)
}

func (s *HopServerPacketConn) Close() error {
	s.access.Lock()
	if s.done {
		s.access.Unlock()
		return nil
	}
	s.done = true
	close(s.doneChan)
	s.access.Unlock()

	drainPacketChan(s.packetChan)
	var err error
	for _, conn := range s.conns {
		if err2 := conn.Close(); err == nil {
			err = err2
		}
	}
	return err
}

func (s *HopServerPacketConn) LocalAddr() net.Addr {
	return s.conns[0].LocalAddr()
}

func (s *HopServerPacketConn) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)
	return s.SetWriteDeadline(t)
}

func (s *HopServerPacketConn) SetReadDeadline(t time.Time) error {
	s.deadlines.setReadDeadline(t)
	return nil
}

func (s *HopServerPacketConn) SetWriteDeadline(t time.Time) error {
	var err error
	for _, conn := range s.conns {
		if err2 := conn.SetWriteDeadline(t); err == nil {
			err = err2
		}
	}
	return err
}

func (s *HopServerPacketConn) ReaderReplaceable() bool {
	return false
}

func (s *HopServerPacketConn) WriterReplaceable() bool {
	return false
}

func (s *HopServerPacketConn) Upstream() any {
	return s.conns[0]
}

func drainPacketChan(ch chan receivedPacket) {
	for {
		select {
		case pkt := <-ch:
			if pkt.buffer != nil {
				pkt.buffer.Release()
			}
		default:
			return
		}
	}
}
