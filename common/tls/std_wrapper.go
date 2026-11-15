package tls

import (
	"crypto/tls"

	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

// stdConnWrapper wraps Go's standard *tls.Conn so Vision can suppress emitting
// TLS close_notify during direct mode while preserving Reader/Writer unwrapping
// for kTLS and ReadWaitConn.
type stdConnWrapper struct {
	*tls.Conn
	closeNotifySuppressor
}

var (
	_ Conn                  = (*stdConnWrapper)(nil)
	_ CloseNotifySuppressor = (*stdConnWrapper)(nil)
	_ N.ReaderWithUpstream  = (*stdConnWrapper)(nil)
	_ N.WriterWithUpstream  = (*stdConnWrapper)(nil)
	_ N.WriteCloser         = (*stdConnWrapper)(nil)
	_ common.WithUpstream   = (*stdConnWrapper)(nil)
)

func (c *stdConnWrapper) Close() error {
	return c.closeConn(c.Conn, c.Conn.NetConn())
}

func (c *stdConnWrapper) CloseWrite() error {
	return c.closeWriteConn(c.Conn, c.Conn.NetConn())
}

func (c *stdConnWrapper) ReaderReplaceable() bool {
	return true
}

func (c *stdConnWrapper) WriterReplaceable() bool {
	return true
}

func (c *stdConnWrapper) Upstream() any {
	return c.Conn
}
