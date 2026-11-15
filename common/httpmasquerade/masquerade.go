package httpmasquerade

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/service/filemanager"

	"golang.org/x/net/http2"
)

// BuildHandler builds an HTTP masquerade handler matching option.Hysteria2Masquerade.
func BuildHandler(ctx context.Context, masquerade *option.Hysteria2Masquerade) (http.Handler, error) {
	if masquerade == nil || masquerade.Type == "" {
		return nil, nil
	}
	switch masquerade.Type {
	case C.Hysterai2MasqueradeTypeFile:
		masqueradeDirectory := filemanager.BasePath(ctx, os.ExpandEnv(masquerade.FileOptions.Directory))
		_, err := filemanager.ReadDir(ctx, masqueradeDirectory)
		if err != nil && !os.IsNotExist(err) {
			return nil, E.Cause(err, "read masquerade directory")
		}
		return http.FileServer(http.Dir(masqueradeDirectory)), nil
	case C.Hysterai2MasqueradeTypeProxy:
		masqueradeURL, err := url.Parse(masquerade.ProxyOptions.URL)
		if err != nil {
			return nil, E.Cause(err, "parse masquerade URL")
		}
		return &httputil.ReverseProxy{
			Rewrite: func(r *httputil.ProxyRequest) {
				r.SetURL(masqueradeURL)
				if !masquerade.ProxyOptions.RewriteHost {
					r.Out.Host = r.In.Host
				}
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				w.WriteHeader(http.StatusBadGateway)
			},
		}, nil
	case C.Hysterai2MasqueradeTypeString:
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for key, values := range masquerade.StringOptions.Headers {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			if masquerade.StringOptions.StatusCode != 0 {
				w.WriteHeader(masquerade.StringOptions.StatusCode)
			}
			_, _ = w.Write([]byte(masquerade.StringOptions.Content))
		}), nil
	default:
		return nil, E.New("unknown masquerade type: ", masquerade.Type)
	}
}

// ServeConn serves HTTP/1.1 or HTTP/2 masquerade responses on a single fallback connection.
func ServeConn(ctx context.Context, handler http.Handler, conn net.Conn, onClose N.CloseHandlerFunc) {
	defer func() {
		_ = conn.Close()
		if onClose != nil {
			onClose(nil)
		}
	}()
	tlsConn, isTLS := common.Cast[aTLS.Conn](conn)
	if isTLS && tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{
			Context: ctx,
			Handler: handler,
		})
		return
	}
	ln := newSingleConnListener(conn)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: C.TCPTimeout,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}
	// Plain-TCP fallbacks come from reverse proxies whose HTTP/1.1 upstream pool
	// would otherwise keep reusing this masquerade socket for later client requests.
	server.SetKeepAlivesEnabled(isTLS)
	_ = server.Serve(ln)
}

type singleConnListener struct {
	conn      net.Conn
	accepted  bool
	acceptMu  sync.Mutex
	closeOnce sync.Once
	closed    chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	ln := &singleConnListener{
		closed: make(chan struct{}),
	}
	ln.conn = &closeNotifyConn{
		Conn:    conn,
		onClose: ln.signalClosed,
	}
	return ln
}

func (l *singleConnListener) signalClosed() {
	l.closeOnce.Do(func() {
		close(l.closed)
	})
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.acceptMu.Lock()
	if !l.accepted {
		l.accepted = true
		l.acceptMu.Unlock()
		return l.conn, nil
	}
	l.acceptMu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.signalClosed()
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

type closeNotifyConn struct {
	net.Conn
	onClose func()
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.onClose()
	return err
}

func (c *closeNotifyConn) Upstream() any {
	return c.Conn
}
