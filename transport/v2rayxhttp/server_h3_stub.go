//go:build !with_quic

package v2rayxhttp

import (
	"net"

	C "github.com/sagernet/sing-box/constant"
)

const h3ServerSupported = false

func (s *Server) servePacket(listener net.PacketConn) error {
	if listener != nil {
		_ = listener.Close()
	}
	return C.ErrQUICNotIncluded
}
