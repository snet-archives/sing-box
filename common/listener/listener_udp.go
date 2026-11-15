package listener

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialermask"
	"github.com/sagernet/sing-box/common/redir"
	"github.com/sagernet/sing/common/buf"
	sBufio "github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const udpOutputBatchSize = 128

func (l *Listener) ListenUDP() (net.PacketConn, error) {
	return l.ListenUDPWithConfig(net.ListenConfig{})
}

func (l *Listener) ListenUDPWithConfig(listenConfig net.ListenConfig) (net.PacketConn, error) {
	var (
		maskPipeline *dialermask.Pipeline
		err          error
	)
	if len(l.listenOptions.Masks) > 0 {
		maskPipeline, err = dialermask.ParseMaskOptions(l.listenOptions.Masks)
		if err != nil {
			return nil, E.Cause(err, "masks")
		}
		if l.tproxy && maskPipeline.HasUDPMasks() {
			return nil, E.New("masks for UDP are not supported with tproxy")
		}
	}
	bindAddr := M.SocksaddrFrom(l.listenOptions.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1})), l.listenOptions.ListenPort)
	var followInterface func(conn syscall.Conn)
	if l.listenOptions.BindInterface != "" {
		var bindFunc control.Func
		bindFunc, followInterface = l.followBindInterface()
		listenConfig.Control = control.Append(listenConfig.Control, bindFunc)
	}
	if l.listenOptions.RoutingMark != 0 {
		listenConfig.Control = control.Append(listenConfig.Control, control.RoutingMark(uint32(l.listenOptions.RoutingMark)))
	}
	if l.listenOptions.ReuseAddr {
		listenConfig.Control = control.Append(listenConfig.Control, control.ReuseAddr())
	}
	var udpFragment bool
	if l.listenOptions.UDPFragment != nil {
		udpFragment = *l.listenOptions.UDPFragment
	} else {
		udpFragment = l.listenOptions.UDPFragmentDefault
	}
	if udpFragment {
		listenConfig.Control = control.Append(listenConfig.Control, control.EnableUDPFragment())
	} else {
		listenConfig.Control = control.Append(listenConfig.Control, control.DisableUDPFragment())
	}
	if l.tproxy {
		listenConfig.Control = control.Append(listenConfig.Control, func(network, address string, conn syscall.RawConn) error {
			return control.Raw(conn, func(fd uintptr) error {
				return redir.TProxy(fd, !strings.HasSuffix(network, "4"), true)
			})
		})
	}
	if maskPipeline != nil && maskPipeline.HasUDPHop() {
		hopPorts := maskPipeline.UDPHopPorts()
		if bindAddr.Port != 0 && !slices.Contains(hopPorts, bindAddr.Port) {
			hopPorts = append([]uint16{bindAddr.Port}, hopPorts...)
		}
		listenPortFn := func(port uint16) (net.PacketConn, error) {
			target := M.SocksaddrFrom(bindAddr.Addr, port)
			conn, listenErr := ListenNetworkNamespace[net.PacketConn](l.ctx, l.listenOptions.NetNs, func() (net.PacketConn, error) {
				return listenConfig.ListenPacket(l.ctx, M.NetworkFromNetAddr(N.NetworkUDP, target.Addr), target.String())
			})
			if listenErr != nil {
				return nil, listenErr
			}
			if followInterface != nil {
				if rawConn, ok := conn.(syscall.Conn); ok {
					followInterface(rawConn)
				}
			}
			return conn, nil
		}
		hopConn, err := dialermask.NewHopServerPacketConn(hopPorts, listenPortFn)
		if err != nil {
			return nil, err
		}
		maskedConn := maskPipeline.WrapPacketConn(hopConn, false)
		l.udpMaskConn = maskedConn
		l.udpAddr = bindAddr
		l.logger.Info("udp hop server started at ", hopConn.LocalAddr(), " ports=", hopPorts)
		return maskedConn, nil
	}
	udpConn, err := ListenNetworkNamespace[net.PacketConn](l.ctx, l.listenOptions.NetNs, func() (net.PacketConn, error) {
		return listenConfig.ListenPacket(l.ctx, M.NetworkFromNetAddr(N.NetworkUDP, bindAddr.Addr), bindAddr.String())
	})
	if err != nil {
		return nil, err
	}
	l.udpConn = udpConn.(*net.UDPConn)
	l.udpAddr = bindAddr
	if followInterface != nil {
		followInterface(l.udpConn)
	}
	if maskPipeline != nil && maskPipeline.HasUDPMasks() {
		maskedConn := maskPipeline.WrapPacketConn(udpConn, false)
		l.udpMaskConn = maskedConn
		l.logger.Info("udp server started at ", udpConn.LocalAddr())
		return maskedConn, nil
	}
	l.logger.Info("udp server started at ", udpConn.LocalAddr())
	return udpConn, err
}

func (l *Listener) DialContext(dialer net.Dialer, ctx context.Context, network string, address string) (net.Conn, error) {
	return ListenNetworkNamespace[net.Conn](l.ctx, l.listenOptions.NetNs, func() (net.Conn, error) {
		if l.listenOptions.BindInterface != "" {
			dialer.Control = control.Append(dialer.Control, l.bindInterfaceFunc())
		}
		if l.listenOptions.RoutingMark != 0 {
			dialer.Control = control.Append(dialer.Control, control.RoutingMark(uint32(l.listenOptions.RoutingMark)))
		}
		if l.listenOptions.ReuseAddr {
			dialer.Control = control.Append(dialer.Control, control.ReuseAddr())
		}
		return dialer.DialContext(ctx, network, address)
	})
}

func (l *Listener) ListenPacket(listenConfig net.ListenConfig, ctx context.Context, network string, address string) (net.PacketConn, error) {
	return ListenNetworkNamespace[net.PacketConn](l.ctx, l.listenOptions.NetNs, func() (net.PacketConn, error) {
		listenConfig.Control = control.Append(listenConfig.Control, control.UDPSocketBuffer(UDPSocketBufferSize()))
		if l.listenOptions.BindInterface != "" {
			listenConfig.Control = control.Append(listenConfig.Control, l.bindInterfaceFunc())
		}
		if l.listenOptions.RoutingMark != 0 {
			listenConfig.Control = control.Append(listenConfig.Control, control.RoutingMark(uint32(l.listenOptions.RoutingMark)))
		}
		if l.listenOptions.ReuseAddr {
			listenConfig.Control = control.Append(listenConfig.Control, control.ReuseAddr())
		}
		return listenConfig.ListenPacket(ctx, network, address)
	})
}

func (l *Listener) UDPAddr() M.Socksaddr {
	return l.udpAddr
}

func (l *Listener) PacketWriter() N.PacketWriter {
	return (*packetWriter)(l)
}

func (l *Listener) activeUDPConn() net.PacketConn {
	if l.udpMaskConn != nil {
		return l.udpMaskConn
	}
	return l.udpConn
}

func (l *Listener) loopUDPIn() {
	defer close(l.packetOutboundClosed)
	udpSource := l.activeUDPConn()
	if l.oobPacketHandler == nil {
		if batchHandler, isBatchHandler := l.packetHandler.(adapter.PacketBatchHandler); isBatchHandler {
			packetConn := sBufio.NewPacketConn(udpSource)
			if readWaiter, created := sBufio.CreatePacketBatchReadWaiter(packetConn); created {
				l.loopUDPInBatch(batchHandler, readWaiter, udpSource)
				return
			}
		}
	}
	var buffer *buf.Buffer
	if !l.threadUnsafePacketWriter {
		buffer = buf.NewPacket()
		defer buffer.Release()
		buffer.IncRef()
		defer buffer.DecRef()
	}
	if l.oobPacketHandler != nil {
		oob := make([]byte, 1024)
		for {
			if l.threadUnsafePacketWriter {
				buffer = buf.NewPacket()
			} else {
				buffer.Reset()
			}
			n, oobN, _, addr, err := l.udpConn.ReadMsgUDPAddrPort(buffer.FreeBytes(), oob)
			if err != nil {
				if l.threadUnsafePacketWriter {
					buffer.Release()
				}
				if l.shutdown.Load() && E.IsClosed(err) {
					return
				}
				l.udpConn.Close()
				l.logger.Error("udp listener closed: ", err)
				return
			}
			buffer.Truncate(n)
			l.oobPacketHandler.NewPacket(buffer, oob[:oobN], M.SocksaddrFromNetIP(addr).Unwrap())
		}
	} else {
		for {
			if l.threadUnsafePacketWriter {
				buffer = buf.NewPacket()
			} else {
				buffer.Reset()
			}
			var (
				n    int
				addr net.Addr
				ap   netip.AddrPort
				err  error
			)
			if l.udpMaskConn != nil {
				n, addr, err = l.udpMaskConn.ReadFrom(buffer.FreeBytes())
			} else {
				n, ap, err = l.udpConn.ReadFromUDPAddrPort(buffer.FreeBytes())
			}
			if err != nil {
				if l.threadUnsafePacketWriter {
					buffer.Release()
				}
				if l.shutdown.Load() && E.IsClosed(err) {
					return
				}
				udpSource.Close()
				l.logger.Error("udp listener closed: ", err)
				return
			}
			buffer.Truncate(n)
			if l.udpMaskConn != nil {
				l.packetHandler.NewPacket(buffer, M.SocksaddrFromNet(addr).Unwrap())
			} else {
				l.packetHandler.NewPacket(buffer, M.SocksaddrFromNetIP(ap).Unwrap())
			}
		}
	}
}

func (l *Listener) loopUDPInBatch(handler adapter.PacketBatchHandler, readWaiter N.PacketBatchReadWaiter, udpSource net.PacketConn) {
	readWaitOptions := N.ReadWaitOptions{
		BatchSize: sBufio.DefaultPacketReadBatchSize,
	}
	readWaiter.InitializeReadWaiter(readWaitOptions)
	for {
		buffers, sources, err := readWaiter.WaitReadPackets()
		if err != nil {
			buf.ReleaseMulti(buffers)
			if l.shutdown.Load() && E.IsClosed(err) {
				return
			}
			udpSource.Close()
			l.logger.Error("udp listener closed: ", err)
			return
		}
		handler.NewPacketBatch(buffers, sources)
	}
}

func (l *Listener) loopUDPOut() {
	packetConn := sBufio.NewPacketConn(l.activeUDPConn())
	batchWriter := sBufio.NewPacketBatchWriter(packetConn)
	packets := make([]*N.PacketBuffer, 0, udpOutputBatchSize)
	buffers := make([]*buf.Buffer, 0, udpOutputBatchSize)
	destinations := make([]M.Socksaddr, 0, udpOutputBatchSize)
	for {
		select {
		case packet := <-l.packetOutbound:
			packets = append(packets, packet)
		case <-l.packetOutboundClosed:
			l.releasePacketOutbound()
			return
		}
	drain:
		for len(packets) < udpOutputBatchSize {
			select {
			case packet := <-l.packetOutbound:
				packets = append(packets, packet)
			default:
				break drain
			}
		}
		for _, packet := range packets {
			buffers = append(buffers, packet.Buffer)
			destinations = append(destinations, packet.Destination)
		}
		err := batchWriter.WritePacketBatch(buffers, destinations)
		for _, packet := range packets {
			N.PutPacketBuffer(packet)
		}
		packets = packets[:0]
		buffers = buffers[:0]
		destinations = destinations[:0]
		if err != nil {
			if l.shutdown.Load() && E.IsClosed(err) {
				return
			}
			l.logger.Error("udp listener write back: ", err)
		}
	}
}

func (l *Listener) releasePacketOutbound() {
	for {
		select {
		case packet := <-l.packetOutbound:
			packet.Buffer.Release()
			N.PutPacketBuffer(packet)
		default:
			return
		}
	}
}

type packetWriter Listener

func (w *packetWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	packet := N.NewPacketBuffer()
	packet.Buffer = buffer
	packet.Destination = destination
	select {
	case w.packetOutbound <- packet:
		return nil
	default:
		buffer.Release()
		N.PutPacketBuffer(packet)
		if w.shutdown.Load() {
			return os.ErrClosed
		}
		w.logger.Trace("dropped packet to ", destination)
		return nil
	}
}

func (w *packetWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	for index, buffer := range buffers {
		packet := N.NewPacketBuffer()
		packet.Buffer = buffer
		packet.Destination = destinations[index]
		select {
		case w.packetOutbound <- packet:
		default:
			buffer.Release()
			N.PutPacketBuffer(packet)
			buf.ReleaseMulti(buffers[index+1:])
			if w.shutdown.Load() {
				return os.ErrClosed
			}
			w.logger.Trace("dropped packet batch to ", destinations[index])
			return nil
		}
	}
	return nil
}

func (w *packetWriter) WriteIsThreadUnsafe() {
}
