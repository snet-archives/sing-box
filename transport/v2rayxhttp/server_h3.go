//go:build with_quic

package v2rayxhttp

import (
	"context"
	"io"
	"net"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	C "github.com/sagernet/sing-box/constant"
	qtls "github.com/sagernet/sing-quic"
	congestion_meta2 "github.com/sagernet/sing-quic/congestion_meta2"
	aTLS "github.com/sagernet/sing/common/tls"
)

const h3ServerSupported = true

func (s *Server) servePacket(listener net.PacketConn) error {
	if s.tlsConfig == nil {
		_ = listener.Close()
		return C.ErrTLSRequired
	}
	h3TLS, ok := s.tlsConfig.Clone().(aTLS.ServerConfig)
	if !ok {
		_ = listener.Close()
		return C.ErrTLSRequired
	}
	h3TLS.SetNextProtos([]string{h3NextProto})
	if err := qtls.ConfigureHTTP3(h3TLS); err != nil {
		_ = listener.Close()
		return err
	}

	if udpAddr, isUDP := listener.LocalAddr().(*net.UDPAddr); isUDP && udpAddr.Port > 0 {
		s.h3Port.Store(int32(udpAddr.Port))
	}
	qtls.SetDesiredBufferSizes(listener)

	quicConfig := buildXHTTPQUICConfig(s.quicOptions, s.idleTimeout, s.pingTimeout, true, false)
	earlyListener, err := qtls.ListenEarly(listener, h3TLS, quicConfig)
	if err != nil {
		_ = listener.Close()
		return err
	}

	h3Handler := s.httpServer.Handler
	if h3Handler == nil {
		h3Handler = s
	}
	h3Server := &http3.Server{
		Handler:     h3Handler,
		IdleTimeout: s.idleTimeout,
		QUICConfig:  quicConfig,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			conn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(conn.InitialPacketSize(), congestion_meta2.ProfileStandard))
			return ctx
		},
	}
	s.trackH3Closers(h3Server, earlyListener)
	defer func() {
		_ = h3Server.Close()
		_ = earlyListener.Close()
	}()
	return h3Server.ServeListener(earlyListener)
}

func (s *Server) trackH3Closers(closers ...io.Closer) {
	s.h3Mu.Lock()
	defer s.h3Mu.Unlock()
	if s.closed.Load() {
		for _, c := range closers {
			if c != nil {
				_ = c.Close()
			}
		}
		return
	}
	s.h3Closers = append(s.h3Closers, closers...)
}
