package v2rayxhttp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck
)

var _ adapter.V2RayServerTransport = (*Server)(nil)

const (
	serverOrphanTimeout         = 30 * time.Second
	maxChunkReadBytes           = 8 * 1024 * 1024
	maxDownlinkReplayBytes      = 1 << 20
	resumablePostCloseLinger    = 10 * time.Second
	defaultDownlinkRotatePeriod = 50 * time.Second
)

// Server implements the XHTTP (SplitHTTP) V2Ray server transport handling
// stream-one, stream-up, and packet-up client requests on HTTP/1.1, H2/h2c, and HTTP/3.
type Server struct {
	ctx                   context.Context
	logger                logger.ContextLogger
	tlsConfig             tls.ServerConfig
	quicOptions           *option.QUICOptions
	idleTimeout           time.Duration
	pingTimeout           time.Duration
	handler               adapter.V2RayServerTransportHandler
	httpServer            *http.Server
	h2Server              *http2.Server
	h2cHandler            http.Handler
	host                  []string
	headers               http.Header
	cfg                   placementConfig
	noSSEHeader           bool
	maxBufferedPosts      int
	defaultDownlinkRotate time.Duration

	h3Port    atomic.Int32
	h3Mu      sync.Mutex
	h3Closers []io.Closer
	closed    atomic.Bool

	sessMu     sync.Mutex
	sessions   map[string]*serverSession
	reaperStop chan struct{}
	closeOnce  sync.Once
}

// NewServer constructs an XHTTP server transport.
func NewServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayXHTTPOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, error) {
	cfg, err := parsePlacementConfig(options)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		enableH3, allowTCP, _ := resolveXHTTPProtos(tlsConfig.NextProtos(), options.QUIC != nil)
		if enableH3 && !allowTCP {
			if !tls.SupportsQUIC(tlsConfig) {
				return nil, E.New("xhttp: server TLS configuration does not support HTTP/3 (QUIC)")
			}
			if !h3ServerSupported {
				return nil, C.ErrQUICNotIncluded
			}
		}
	}
	maxBuf := defaultScMaxBufferedPosts
	if !cfg.maxBufferedPosts.IsZero() && cfg.maxBufferedPosts.From > 0 {
		maxBuf = cfg.maxBufferedPosts.Sample()
	}
	s := &Server{
		ctx:              ctx,
		logger:           logger,
		tlsConfig:        tlsConfig,
		quicOptions:      options.QUIC,
		idleTimeout:      time.Duration(options.IdleTimeout),
		pingTimeout:      time.Duration(options.PingTimeout),
		handler:          handler,
		host:             options.Host,
		headers:          options.Headers.Build(),
		cfg:              cfg,
		noSSEHeader:      options.NoSSEHeader,
		maxBufferedPosts: maxBuf,
		sessions:         make(map[string]*serverSession),
		reaperStop:       make(chan struct{}),
		h2Server: &http2.Server{
			IdleTimeout: time.Duration(options.IdleTimeout),
		},
	}
	s.httpServer = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: C.TCPTimeout,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
		ConnContext: func(connCtx context.Context, _ net.Conn) context.Context {
			return connCtx
		},
	}
	//nolint:staticcheck
	s.h2cHandler = h2c.NewHandler(s, s.h2Server)
	_ = http2.ConfigureServer(s.httpServer, s.h2Server)
	go s.reapLoop()
	return s, nil
}

func (s *Server) reapLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			s.reapOnce(now)
		case <-s.reaperStop:
			return
		}
	}
}

func (s *Server) reapOnce(now time.Time) {
	cutoff := now.Add(-serverOrphanTimeout).UnixNano()
	s.sessMu.Lock()
	var stale []*serverSession
	for id, sess := range s.sessions {
		finishedAt := sess.finishedAt()
		if !finishedAt.IsZero() {
			if now.Sub(finishedAt) > resumablePostCloseLinger {
				delete(s.sessions, id)
				sess.clearReplayBuffer()
			}
			continue
		}
		if !sess.isDownlinkAttached() && sess.lastActive.Load() < cutoff {
			stale = append(stale, sess)
		}
	}
	s.sessMu.Unlock()
	for _, sess := range stale {
		_ = sess.Close()
	}
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == "PRI" && len(request.Header) == 0 && request.URL.Path == "*" && request.Proto == "HTTP/2.0" {
		s.h2cHandler.ServeHTTP(writer, request)
		return
	}
	host := request.Host
	if len(s.host) > 0 && !common.Contains(s.host, host) {
		s.invalidRequest(writer, request, http.StatusBadRequest, E.New("xhttp bad host: ", host))
		return
	}

	meta, matched, err := s.cfg.decodeRequest(request)
	if !matched {
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("xhttp bad path: ", request.URL.Path))
		return
	}
	if err != nil {
		s.invalidRequest(writer, request, http.StatusBadRequest, err)
		return
	}

	// Stream-one: single POST without session ID.
	if meta.sessionID == "" {
		if request.Method != http.MethodPost {
			s.invalidRequest(writer, request, http.StatusNotFound, E.New("xhttp unexpected method without session: ", request.Method))
			return
		}
		s.serveStreamOne(writer, request)
		return
	}

	switch request.Method {
	case http.MethodGet:
		s.serveDownlinkGet(writer, request, meta.sessionID)
	case http.MethodPost, http.MethodPut:
		s.serveUplinkPost(writer, request, meta)
	default:
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("xhttp unsupported method: ", request.Method))
	}
}

func (s *Server) writeCommonResponseHeaders(writer http.ResponseWriter, request *http.Request, streaming bool) {
	writer.Header().Set("Cache-Control", "no-store, no-transform")
	if port := s.h3Port.Load(); port > 0 && request != nil && request.ProtoMajor < 3 {
		writer.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=86400`, port))
	}
	if streaming {
		writer.Header().Set("X-Accel-Buffering", "no")
		if !s.noSSEHeader {
			writer.Header().Set("Content-Type", "text/event-stream")
		}
	}
	for k, vals := range s.headers {
		for _, v := range vals {
			writer.Header().Set(k, v)
		}
	}
}

func (s *Server) serveStreamOne(writer http.ResponseWriter, request *http.Request) {
	flusher, hasFlusher := writer.(http.Flusher)
	if !hasFlusher {
		s.invalidRequest(writer, request, http.StatusInternalServerError, E.New("xhttp response writer not flushable"))
		return
	}
	s.writeCommonResponseHeaders(writer, request, true)
	source := badhttp.SourceAddress(request)
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	done := make(chan struct{})
	conn := v2rayhttp.NewHTTP2Wrapper(&v2rayhttp.ServerHTTPConn{
		HTTP2Conn: v2rayhttp.NewHTTPConn(request.Body, writer),
		Flusher:   flusher,
	})
	s.handler.NewConnectionEx(request.Context(), conn, source, M.Socksaddr{}, N.OnceClose(func(error) {
		close(done)
	}))
	<-done
	conn.CloseWrapper()
}

func (s *Server) removeSession(sess *serverSession) {
	s.sessMu.Lock()
	if cur, ok := s.sessions[sess.id]; ok && cur == sess {
		delete(s.sessions, sess.id)
	}
	s.sessMu.Unlock()
}

func (s *Server) getOrCreateSession(id string, request *http.Request) *serverSession {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	sess, ok := s.sessions[id]
	if ok {
		sess.lastActive.Store(time.Now().UnixNano())
		return sess
	}
	pr, pw := io.Pipe()
	sessCtx, cancel := context.WithCancel(s.ctx)
	sess = &serverSession{
		id:           id,
		server:       s,
		ctx:          sessCtx,
		cancel:       cancel,
		source:       badhttp.SourceAddress(request),
		uplinkReader: pr,
		uplinkWriter: pw,
		pending:      make(map[uint64][]byte),
		dlReady:      make(chan struct{}),
		done:         make(chan struct{}),
	}
	sess.seqCond = sync.NewCond(&sess.seqMu)
	sess.dlCond = sync.NewCond(&sess.dlMu)
	sess.lastActive.Store(time.Now().UnixNano())
	s.sessions[id] = sess
	return sess
}

func (s *Server) serveDownlinkGet(writer http.ResponseWriter, request *http.Request, sessionID string) {
	sess := s.getOrCreateSession(sessionID, request)
	flusher, hasFlusher := writer.(http.Flusher)
	if !hasFlusher {
		s.invalidRequest(writer, request, http.StatusInternalServerError, E.New("xhttp response writer not flushable"))
		return
	}
	if seqStr := request.Header.Get(headerDownlinkSeq); seqStr != "" {
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			s.invalidRequest(writer, request, http.StatusBadRequest, E.Cause(err, "xhttp invalid ", headerDownlinkSeq))
			return
		}
		var offset uint64
		if offsetStr := request.Header.Get(headerDownlinkOffset); offsetStr != "" {
			offset, err = strconv.ParseUint(offsetStr, 10, 64)
			if err != nil {
				s.invalidRequest(writer, request, http.StatusBadRequest, E.Cause(err, "xhttp invalid ", headerDownlinkOffset))
				return
			}
		}
		s.serveResumableDownlinkGet(writer, request, sess, flusher, seq, offset)
		return
	}

	if !sess.claimLegacyDownlink() {
		s.invalidRequest(writer, request, http.StatusConflict, E.New("xhttp duplicate downlink GET for session ", sessionID))
		return
	}
	s.writeCommonResponseHeaders(writer, request, true)
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	sess.attachLegacyDownlink(writer, flusher)
	defer sess.detachLegacyDownlink()
	go sess.dispatch()

	select {
	case <-sess.done:
	case <-request.Context().Done():
		_ = sess.Close()
	}
}

func (s *Server) serveResumableDownlinkGet(writer http.ResponseWriter, request *http.Request, sess *serverSession, flusher http.Flusher, seq uint64, offset uint64) {
	sess.dlMu.Lock()
	if !sess.dlResumable && (sess.dlAttached.Load() || sess.dlLegacyDone) {
		sess.dlMu.Unlock()
		s.invalidRequest(writer, request, http.StatusConflict, E.New("xhttp duplicate downlink GET for session ", sess.id))
		return
	}
	if sess.dlGeneration > 0 && seq <= sess.dlSeq {
		sess.dlMu.Unlock()
		s.invalidRequest(writer, request, http.StatusConflict, E.New("xhttp stale downlink seq ", seq, " for session ", sess.id))
		return
	}
	if offset < sess.dlBaseOffset || offset > sess.dlTotalBytes {
		sess.dlMu.Unlock()
		s.invalidRequest(writer, request, http.StatusRequestedRangeNotSatisfiable, E.New("xhttp invalid downlink offset ", offset, " outside [", sess.dlBaseOffset, ",", sess.dlTotalBytes, "]"))
		return
	}
	sess.discardReplayBeforeLocked(offset)
	sess.dlResumable = true
	sess.lastActive.Store(time.Now().UnixNano())

	if sess.dlEOF && offset == sess.dlTotalBytes {
		sess.dlAttached.Store(false)
		sess.dlBuf = nil
		sess.dlMu.Unlock()
		s.removeSession(sess)
		s.writeCommonResponseHeaders(writer, request, false)
		writer.Header().Set(headerStreamEnd, "1")
		writer.WriteHeader(http.StatusOK)
		return
	}

	sess.dlGeneration++
	gen := sess.dlGeneration
	sess.dlSeq = seq
	sess.dlSentOffset = offset
	if sess.dlActiveStop != nil {
		close(sess.dlActiveStop)
		sess.dlActiveStop = nil
	}
	stopCh := make(chan struct{})
	sess.dlActiveStop = stopCh
	sess.dlWriter = nil
	sess.dlFlusher = nil
	sess.dlAttached.Store(true)
	sess.dlReadyOnce.Do(func() { close(sess.dlReady) })
	alreadyEOF := sess.dlEOF
	sess.dlMu.Unlock()

	s.writeCommonResponseHeaders(writer, request, true)
	writer.Header().Add("Trailer", headerStreamEnd)
	if alreadyEOF {
		writer.Header().Set(headerStreamEnd, "1")
	}
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	go sess.dispatch()

	for {
		sess.dlMu.Lock()
		if sess.dlGeneration != gen {
			sess.dlMu.Unlock()
			return
		}
		if sess.dlSentOffset < sess.dlTotalBytes {
			start := int(sess.dlSentOffset - sess.dlBaseOffset)
			chunk := append([]byte(nil), sess.dlBuf[start:]...)
			nextOff := sess.dlTotalBytes
			sess.dlMu.Unlock()
			if _, err := writer.Write(chunk); err != nil {
				sess.detachDownlinkGeneration(gen, false)
				return
			}
			flusher.Flush()
			sess.dlMu.Lock()
			if sess.dlGeneration == gen && nextOff > sess.dlSentOffset {
				sess.dlSentOffset = nextOff
				sess.trimReplayBufferLocked()
			}
			sess.dlMu.Unlock()
			continue
		}
		if sess.dlEOF {
			if !alreadyEOF {
				writer.Header().Set(headerStreamEnd, "1")
			}
			if sess.dlActiveStop == stopCh {
				close(stopCh)
				sess.dlActiveStop = nil
			}
			sess.dlAttached.Store(false)
			sess.dlCond.Broadcast()
			sess.dlMu.Unlock()
			flusher.Flush()
			return
		}
		sess.dlWriter = writer
		sess.dlFlusher = flusher
		sess.dlCond.Broadcast()
		sess.dlMu.Unlock()
		break
	}

	var rotateCh <-chan time.Time
	var rotateTimer *time.Timer
	rotateInterval := time.Duration(samplePaddingLen(s.cfg.downlinkServerSecs)) * time.Second
	if rotateInterval <= 0 {
		rotateInterval = s.defaultDownlinkRotate
		if rotateInterval <= 0 {
			rotateInterval = defaultDownlinkRotatePeriod
		}
	}
	rotateTimer = time.NewTimer(rotateInterval)
	rotateCh = rotateTimer.C
	defer rotateTimer.Stop()

	select {
	case <-stopCh:
		sess.dlMu.Lock()
		if sess.dlGeneration == gen && sess.dlEOF {
			for sess.dlGeneration == gen && sess.dlSentOffset < sess.dlTotalBytes {
				start := int(sess.dlSentOffset - sess.dlBaseOffset)
				chunk := sess.dlBuf[start:]
				if _, err := writer.Write(chunk); err != nil {
					break
				}
				sess.dlSentOffset = sess.dlTotalBytes
			}
			if !alreadyEOF {
				writer.Header().Set(headerStreamEnd, "1")
			}
			if sess.dlWriter == writer {
				sess.dlWriter = nil
				sess.dlFlusher = nil
			}
		}
		sess.dlMu.Unlock()
		flusher.Flush()
	case <-rotateCh:
		sess.detachDownlinkGeneration(gen, true)
		flusher.Flush()
	case <-request.Context().Done():
		sess.detachDownlinkGeneration(gen, false)
	}
}

func (s *Server) serveUplinkPost(writer http.ResponseWriter, request *http.Request, meta decodedRequestMeta) {
	sess := s.getOrCreateSession(meta.sessionID, request)
	go sess.dispatch()

	var seq uint64
	if meta.hasSeq {
		seq = meta.seq
	}
	endAfter := request.Header.Get("X-Stream-End") == "1"

	if len(meta.nonBodyPayload) > 0 || request.ContentLength >= 0 {
		payload := meta.nonBodyPayload
		if request.ContentLength > 0 {
			if request.ContentLength > maxChunkReadBytes {
				s.invalidRequest(writer, request, http.StatusRequestEntityTooLarge, E.New("xhttp chunk too large"))
				return
			}
			bodyBytes, err := io.ReadAll(io.LimitReader(request.Body, maxChunkReadBytes))
			if err != nil {
				s.invalidRequest(writer, request, http.StatusBadRequest, err)
				return
			}
			if len(payload) == 0 {
				payload = bodyBytes
			} else {
				payload = append(payload, bodyBytes...)
			}
		}
		if err := sess.pushChunk(seq, payload, endAfter); err != nil {
			s.invalidRequest(writer, request, http.StatusTooManyRequests, err)
			return
		}
	} else {
		if err := sess.streamUplink(request.Context(), seq, request.Body, endAfter); err != nil {
			s.invalidRequest(writer, request, http.StatusBadRequest, err)
			return
		}
	}

	s.writeCommonResponseHeaders(writer, request, false)
	writer.WriteHeader(http.StatusOK)
}

func (s *Server) invalidRequest(writer http.ResponseWriter, request *http.Request, statusCode int, err error) {
	if statusCode > 0 {
		writer.WriteHeader(statusCode)
	}
	s.logger.DebugContext(request.Context(), E.Cause(err, "xhttp invalid request from ", request.RemoteAddr))
}

func (s *Server) Network() []string {
	if s.tlsConfig == nil {
		return []string{N.NetworkTCP}
	}
	enableH3, allowTCP, _ := resolveXHTTPProtos(s.tlsConfig.NextProtos(), s.quicOptions != nil)
	var nets []string
	if allowTCP {
		nets = append(nets, N.NetworkTCP)
	}
	if enableH3 && h3ServerSupported && tls.SupportsQUIC(s.tlsConfig) {
		nets = append(nets, N.NetworkUDP)
	}
	if len(nets) == 0 {
		return []string{N.NetworkTCP}
	}
	return nets
}

func (s *Server) Serve(listener net.Listener) error {
	if s.tlsConfig != nil {
		tcpTLS, ok := s.tlsConfig.Clone().(tls.ServerConfig)
		if !ok {
			tcpTLS = s.tlsConfig
		}
		_, _, tcpProtos := resolveXHTTPProtos(tcpTLS.NextProtos(), s.quicOptions != nil)
		if len(tcpProtos) == 0 {
			tcpProtos = []string{http2.NextProtoTLS, "http/1.1"}
		} else if !common.Contains(tcpProtos, http2.NextProtoTLS) {
			tcpProtos = append([]string{http2.NextProtoTLS}, tcpProtos...)
		}
		tcpTLS.SetNextProtos(tcpProtos)
		listener = aTLS.NewListener(listener, tcpTLS)
	}
	return s.httpServer.Serve(listener)
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	return s.servePacket(listener)
}

func (s *Server) Close() error {
	s.closed.Store(true)
	s.closeOnce.Do(func() {
		close(s.reaperStop)
	})
	s.h3Mu.Lock()
	h3Closers := s.h3Closers
	s.h3Closers = nil
	s.h3Mu.Unlock()
	for _, closer := range h3Closers {
		if closer != nil {
			_ = closer.Close()
		}
	}
	s.sessMu.Lock()
	conns := make([]*serverSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		conns = append(conns, sess)
	}
	clear(s.sessions)
	s.sessMu.Unlock()
	for _, sess := range conns {
		_ = sess.Close()
	}
	return common.Close(common.PtrOrNil(s.httpServer))
}

type serverSession struct {
	id         string
	server     *Server
	ctx        context.Context
	cancel     context.CancelFunc
	source     M.Socksaddr
	lastActive atomic.Int64

	uplinkReader *io.PipeReader
	uplinkWriter *io.PipeWriter

	seqMu          sync.Mutex
	seqCond        *sync.Cond
	nextSeq        uint64
	pending        map[uint64][]byte
	uplinkDraining bool
	endSet         bool
	endSeq         uint64
	uplinkClosed   bool

	dlMu         sync.Mutex
	dlCond       *sync.Cond
	dlAttached   atomic.Bool
	dlResumable  bool
	dlGeneration uint64
	dlSeq        uint64
	dlReady      chan struct{}
	dlReadyOnce  sync.Once
	dlWriter     http.ResponseWriter
	dlFlusher    http.Flusher
	dlActiveStop chan struct{}
	dlBuf        []byte
	dlBaseOffset uint64
	dlSentOffset uint64
	dlTotalBytes uint64
	dlEOF        bool
	dlFinishedAt time.Time
	dlClosed     bool
	dlLegacyDone bool

	done         chan struct{}
	closeOnce    sync.Once
	dispatchOnce sync.Once
}

func (s *serverSession) isDownlinkAttached() bool {
	return s.dlAttached.Load()
}

func (s *serverSession) finishedAt() time.Time {
	s.dlMu.Lock()
	defer s.dlMu.Unlock()
	return s.dlFinishedAt
}

func (s *serverSession) clearReplayBuffer() {
	s.dlMu.Lock()
	s.dlBuf = nil
	s.dlMu.Unlock()
}

func (s *serverSession) discardReplayBeforeLocked(offset uint64) {
	if offset <= s.dlBaseOffset {
		return
	}
	acked := int(offset - s.dlBaseOffset)
	if acked >= len(s.dlBuf) {
		s.dlBuf = s.dlBuf[:0]
	} else {
		copy(s.dlBuf, s.dlBuf[acked:])
		s.dlBuf = s.dlBuf[:len(s.dlBuf)-acked]
	}
	s.dlBaseOffset = offset
}

func (s *serverSession) trimReplayBufferLocked() {
	if len(s.dlBuf) <= maxDownlinkReplayBytes {
		return
	}
	trim := len(s.dlBuf) - maxDownlinkReplayBytes
	maxSafe := int(s.dlSentOffset - s.dlBaseOffset)
	if trim > maxSafe {
		trim = maxSafe
	}
	if trim > 0 {
		copy(s.dlBuf, s.dlBuf[trim:])
		s.dlBuf = s.dlBuf[:len(s.dlBuf)-trim]
		s.dlBaseOffset += uint64(trim)
	}
}

func (s *serverSession) claimLegacyDownlink() bool {
	s.dlMu.Lock()
	defer s.dlMu.Unlock()
	if s.dlResumable || s.dlLegacyDone || s.dlAttached.Load() {
		return false
	}
	return s.dlAttached.CompareAndSwap(false, true)
}

func (s *serverSession) attachLegacyDownlink(w http.ResponseWriter, flusher http.Flusher) {
	s.dlMu.Lock()
	s.dlWriter = w
	s.dlFlusher = flusher
	s.dlCond.Broadcast()
	s.dlMu.Unlock()
	s.dlReadyOnce.Do(func() { close(s.dlReady) })
}

func (s *serverSession) detachLegacyDownlink() {
	s.dlMu.Lock()
	s.dlLegacyDone = true
	s.dlClosed = true
	s.dlWriter = nil
	s.dlFlusher = nil
	s.dlAttached.Store(false)
	s.dlCond.Broadcast()
	s.dlMu.Unlock()
}

func (s *serverSession) detachDownlinkGeneration(gen uint64, refreshActivity bool) {
	s.dlMu.Lock()
	if s.dlGeneration == gen {
		if refreshActivity {
			s.lastActive.Store(time.Now().UnixNano())
		}
		s.dlWriter = nil
		s.dlFlusher = nil
		s.dlAttached.Store(false)
		if s.dlActiveStop != nil {
			close(s.dlActiveStop)
			s.dlActiveStop = nil
		}
		s.dlCond.Broadcast()
	}
	s.dlMu.Unlock()
}

func (s *serverSession) dispatch() {
	s.dispatchOnce.Do(func() {
		s.server.handler.NewConnectionEx(v2rayhttp.DupContext(s.ctx), s, s.source, M.Socksaddr{}, N.OnceClose(func(error) {
			_ = s.Close()
		}))
	})
}

func (s *serverSession) pushChunk(seq uint64, data []byte, endAfter bool) error {
	s.lastActive.Store(time.Now().UnixNano())
	s.seqMu.Lock()
	if s.uplinkClosed {
		s.seqMu.Unlock()
		return net.ErrClosed
	}
	if endAfter && (!s.endSet || seq < s.endSeq) {
		s.endSet = true
		s.endSeq = seq
	}
	if seq < s.nextSeq {
		s.seqMu.Unlock()
		return nil
	}
	if s.uplinkDraining || seq != s.nextSeq {
		if _, exists := s.pending[seq]; !exists {
			if len(s.pending) >= s.server.maxBufferedPosts {
				s.seqMu.Unlock()
				return E.New("xhttp buffered post limit exceeded")
			}
			s.pending[seq] = data
		}
		s.seqMu.Unlock()
		return nil
	}

	s.uplinkDraining = true
	s.nextSeq++
	return s.drainPendingLocked(data, true)
}

// drainPendingLocked writes initialChunk (if hasInitial) and then drains any
// contiguous chunks queued in s.pending starting at s.nextSeq. Caller must hold
// s.seqMu with s.uplinkDraining == true; s.seqMu is released before returning.
func (s *serverSession) drainPendingLocked(initialChunk []byte, hasInitial bool) error {
	chunk := initialChunk
	hasChunk := hasInitial
	for {
		if hasChunk {
			if len(chunk) > 0 {
				s.seqMu.Unlock()
				_, err := s.uplinkWriter.Write(chunk)
				s.seqMu.Lock()
				if err != nil {
					s.uplinkDraining = false
					s.seqCond.Broadcast()
					s.seqMu.Unlock()
					return err
				}
			}
			hasChunk = false
		}

		if s.uplinkClosed {
			s.uplinkDraining = false
			s.seqCond.Broadcast()
			s.seqMu.Unlock()
			return nil
		}
		nextData, ok := s.pending[s.nextSeq]
		if !ok {
			s.uplinkDraining = false
			shouldCloseUplink := s.endSet && s.nextSeq > s.endSeq
			s.seqCond.Broadcast()
			s.seqMu.Unlock()
			if shouldCloseUplink {
				_ = s.uplinkWriter.Close()
			}
			return nil
		}
		delete(s.pending, s.nextSeq)
		chunk = nextData
		hasChunk = true
		s.nextSeq++
	}
}

func (s *serverSession) streamUplink(reqCtx context.Context, seq uint64, body io.Reader, endAfter bool) error {
	s.lastActive.Store(time.Now().UnixNano())
	stopWake := context.AfterFunc(reqCtx, func() {
		s.seqMu.Lock()
		s.seqCond.Broadcast()
		s.seqMu.Unlock()
	})
	defer stopWake()

	s.seqMu.Lock()
	for !s.uplinkClosed && reqCtx.Err() == nil && ((seq > s.nextSeq) || (seq == s.nextSeq && s.uplinkDraining)) {
		s.seqCond.Wait()
	}
	if s.uplinkClosed {
		s.seqMu.Unlock()
		return net.ErrClosed
	}
	if reqCtx.Err() != nil {
		s.seqMu.Unlock()
		return reqCtx.Err()
	}
	if seq < s.nextSeq {
		// Stale/retried chunked or H2/H3 POST after seq was already consumed.
		s.seqMu.Unlock()
		return nil
	}
	if endAfter && (!s.endSet || seq < s.endSeq) {
		s.endSet = true
		s.endSeq = seq
	}
	s.uplinkDraining = true
	s.seqMu.Unlock()

	_, err := io.Copy(s.uplinkWriter, body)

	s.seqMu.Lock()
	s.nextSeq++
	if err != nil {
		s.uplinkDraining = false
		s.seqCond.Broadcast()
		s.seqMu.Unlock()
		return err
	}
	return s.drainPendingLocked(nil, false)
}

func (s *serverSession) Read(p []byte) (int, error) {
	return s.uplinkReader.Read(p)
}

func (s *serverSession) Write(p []byte) (int, error) {
	select {
	case <-s.dlReady:
	case <-s.done:
		return 0, net.ErrClosed
	case <-s.ctx.Done():
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	s.lastActive.Store(time.Now().UnixNano())
	s.dlMu.Lock()
	defer s.dlMu.Unlock()

	if s.dlEOF || s.dlClosed || s.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	if !s.dlResumable {
		if s.dlWriter == nil {
			return 0, net.ErrClosed
		}
		n, err := s.dlWriter.Write(p)
		if err == nil && s.dlFlusher != nil {
			s.dlFlusher.Flush()
		}
		return n, err
	}

	for s.dlWriter == nil && len(s.dlBuf) >= maxDownlinkReplayBytes && !s.dlEOF && !s.dlClosed && s.ctx.Err() == nil {
		s.dlCond.Wait()
	}
	if s.dlEOF || s.dlClosed || s.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	s.dlBuf = append(s.dlBuf, p...)
	s.dlTotalBytes += uint64(len(p))
	if s.dlWriter != nil {
		_, err := s.dlWriter.Write(p)
		if err != nil {
			s.dlWriter = nil
			s.dlFlusher = nil
			s.dlAttached.Store(false)
			if s.dlActiveStop != nil {
				close(s.dlActiveStop)
				s.dlActiveStop = nil
			}
			s.dlCond.Broadcast()
			return len(p), nil
		}
		if s.dlFlusher != nil {
			s.dlFlusher.Flush()
		}
		s.dlSentOffset = s.dlTotalBytes
		s.trimReplayBufferLocked()
	}
	return len(p), nil
}

func (s *serverSession) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.seqMu.Lock()
		s.uplinkClosed = true
		clear(s.pending)
		s.seqCond.Broadcast()
		s.seqMu.Unlock()

		s.dlMu.Lock()
		resumable := s.dlResumable
		s.dlEOF = true
		s.dlClosed = true
		s.dlFinishedAt = time.Now()
		s.dlAttached.Store(false)
		if s.dlActiveStop != nil {
			close(s.dlActiveStop)
			s.dlActiveStop = nil
		}
		s.dlWriter = nil
		s.dlFlusher = nil
		s.dlCond.Broadcast()
		s.dlMu.Unlock()

		_ = s.uplinkReader.Close()
		_ = s.uplinkWriter.Close()
		close(s.done)

		if !resumable {
			s.server.removeSession(s)
		}
	})
	return nil
}

func (s *serverSession) LocalAddr() net.Addr                { return M.Socksaddr{} }
func (s *serverSession) RemoteAddr() net.Addr               { return s.source }
func (s *serverSession) SetDeadline(t time.Time) error      { return nil }
func (s *serverSession) SetReadDeadline(t time.Time) error  { return nil }
func (s *serverSession) SetWriteDeadline(t time.Time) error { return nil }
