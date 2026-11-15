package tls

import (
	"net"
	"sync/atomic"

	N "github.com/sagernet/sing/common/network"
)

// CloseNotifySuppressor marks a TLS wrapper to skip emitting TLS close_notify
// when closing or half-closing after XTLS Vision enters direct mode.
type CloseNotifySuppressor interface {
	SuppressCloseNotify()
}

type closeNotifySuppressor struct {
	suppressed atomic.Bool
}

func (s *closeNotifySuppressor) SuppressCloseNotify() {
	s.suppressed.Store(true)
}

func (s *closeNotifySuppressor) closeConn(tlsConn net.Conn, netConn net.Conn) error {
	if s.suppressed.Load() && netConn != nil {
		return netConn.Close()
	}
	return tlsConn.Close()
}

func (s *closeNotifySuppressor) closeWriteConn(tlsConn net.Conn, netConn net.Conn) error {
	if s.suppressed.Load() && netConn != nil {
		return N.CloseWrite(netConn)
	}
	return N.CloseWrite(tlsConn)
}

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304

	// Deprecated: SSLv3 is cryptographically broken, and is no longer
	// supported by this package. See golang.org/issue/32716.
	VersionSSL30 = 0x0300
)
