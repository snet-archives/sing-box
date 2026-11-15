//go:build !with_quic

package v2rayxhttp

import (
	"context"
	"net/http"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-mux"
)

const h3Supported = false

type h3ClientConn struct{}

func (p *xmuxHTTPPool) dialH3Conn(context.Context, mux.XmuxSessionLimit) (*xmuxHTTPConn, error) {
	return nil, C.ErrQUICNotIncluded
}

func (c *h3ClientConn) roundTrip(*http.Request) (*http.Response, error) {
	return nil, C.ErrQUICNotIncluded
}

func (c *h3ClientConn) isAlive() bool {
	return false
}

func (c *h3ClientConn) close() {}
