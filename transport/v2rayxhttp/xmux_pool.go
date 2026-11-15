package v2rayxhttp

import (
	"context"
	stdtls "crypto/tls"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

const (
	h3NextProto               = "h3"
	h3FallbackDialTimeout     = 3 * time.Second
	h3HappyEyeballsDelay      = 250 * time.Millisecond
	h3HeaderWatchdogTimeout   = 4 * time.Second
	h3FallbackCooldown        = 30 * time.Second
	h3FallbackMaxCooldown     = 5 * time.Minute
	h3AltSvcMaxAge            = 24 * time.Hour
	h3DegradeFailureThreshold = 2
	h3DegradeFailureWindow    = 30 * time.Second
)

func resolveXHTTPProtos(protos []string, hasQUICOptions bool) (enableH3 bool, allowTCP bool, tcpProtos []string) {
	hasH3 := false
	for _, proto := range protos {
		if proto == h3NextProto {
			hasH3 = true
			continue
		}
		tcpProtos = append(tcpProtos, proto)
	}
	enableH3 = hasH3 || hasQUICOptions
	if len(protos) == 0 {
		allowTCP = true
		tcpProtos = []string{http2.NextProtoTLS, "http/1.1"}
		return
	}
	allowTCP = len(tcpProtos) > 0
	return
}

type dialAttempt struct {
	done           chan struct{}
	conn           *xmuxHTTPConn
	err            error
	leaderCanceled bool
}

type xmuxHTTPPool struct {
	dialer           N.Dialer
	target           M.Socksaddr
	tlsConfig        tls.Config
	tlsDialer        tls.Dialer
	preferH2         bool
	enableH3         bool
	allowAltSvcH3    bool
	hasTCPFallback   bool
	quicOptions      *option.QUICOptions
	idleTimeout      time.Duration
	pingTimeout      time.Duration
	h2Fingerprint    *http2.FingerprintProfile
	xmux             mux.XmuxOptions
	maxConnections   int
	canCoalesce      bool
	closeIdle        atomic.Bool
	h3HasFailures    atomic.Bool
	h3LeadDelay      time.Duration
	h3HeaderWatchdog time.Duration

	mu              sync.Mutex
	conns           []*xmuxHTTPConn
	inflightDial    *dialAttempt
	h3RetryAfter    time.Time
	h3CooldownShift int
	h3Failures      int
	h3FailureAt     time.Time
	altSvcTarget    M.Socksaddr
	altSvcUntil     time.Time
	altSvcProbed    bool
	closed          bool
}

type xmuxHTTPConn struct {
	isH3      bool
	h3Conn    *h3ClientConn
	isH2      bool
	h2cc      *http2.ClientConn
	h1        *http.Transport
	rawConn   net.Conn
	limit     mux.XmuxSessionLimit
	active    int
	total     int
	closedErr atomic.Bool
}

func newXmuxHTTPPool(dialer N.Dialer, target M.Socksaddr, tlsConfig tls.Config, preferH2 bool, idleTimeout, pingTimeout time.Duration, xmuxOpts mux.XmuxOptions, quicOptions *option.QUICOptions) *xmuxHTTPPool {
	var (
		tlsDialer      tls.Dialer
		enableH3       bool
		hasTCPFallback = true
		tcpCanH2       bool
	)
	if tlsConfig != nil {
		var tcpProtos []string
		rawProtos := tlsConfig.NextProtos()
		enableH3, hasTCPFallback, tcpProtos = resolveXHTTPProtos(rawProtos, quicOptions != nil)
		if !tls.SupportsQUIC(tlsConfig) {
			enableH3 = false
		}
		if hasTCPFallback {
			tcpCanH2 = len(tcpProtos) == 0 || slices.Contains(tcpProtos, http2.NextProtoTLS)
			dialerTLS := tlsConfig
			if slices.Contains(rawProtos, h3NextProto) {
				dialerTLS = tlsConfig.Clone()
				dialerTLS.SetNextProtos(tcpProtos)
			}
			tlsDialer = tls.NewDialer(dialer, dialerTLS)
		}
	}
	maxConns := 0
	if !xmuxOpts.MaxConnections.IsZero() {
		maxConns = xmuxOpts.MaxConnections.Sample()
	}
	return &xmuxHTTPPool{
		dialer:         dialer,
		target:         target,
		tlsConfig:      tlsConfig,
		tlsDialer:      tlsDialer,
		preferH2:       preferH2,
		enableH3:       enableH3,
		allowAltSvcH3:  enableH3,
		hasTCPFallback: hasTCPFallback,
		quicOptions:    quicOptions,
		idleTimeout:    idleTimeout,
		pingTimeout:    pingTimeout,
		h2Fingerprint:  tls.HTTP2Fingerprint(tlsConfig),
		xmux:           xmuxOpts,
		maxConnections: maxConns,
		canCoalesce:    enableH3 || preferH2 || tcpCanH2,
	}
}

func (p *xmuxHTTPPool) setAllowAltSvcH3(allow bool) {
	p.mu.Lock()
	p.allowAltSvcH3 = allow && tls.SupportsQUIC(p.tlsConfig)
	if p.allowAltSvcH3 {
		p.canCoalesce = true
	}
	p.mu.Unlock()
}

func (c *xmuxHTTPConn) isMultiplexed() bool {
	return c.isH2 || c.isH3
}

func (c *xmuxHTTPConn) isTransportAlive() bool {
	if c.isH3 {
		return c.h3Conn.isAlive()
	}
	if c.isH2 {
		st := c.h2cc.State()
		return !st.Closed && !st.Closing && c.h2cc.CanTakeNewRequest()
	}
	return true
}

func (c *xmuxHTTPConn) isAlive() bool {
	if c.closedErr.Load() {
		return false
	}
	return c.isTransportAlive()
}

func (c *xmuxHTTPConn) close() {
	c.closedErr.Store(true)
	if c.isH3 {
		c.h3Conn.close()
	}
	if c.isH2 {
		_ = c.h2cc.Close()
	}
	if c.h1 != nil {
		c.h1.CloseIdleConnections()
	}
	if c.rawConn != nil {
		_ = c.rawConn.Close()
	}
}

func isReplayableRequest(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

func (p *xmuxHTTPPool) roundTrip(req *http.Request) (*http.Response, error) {
	resp, err, tripped := p.roundTripOnce(req)
	if tripped && req.Context().Err() == nil && isReplayableRequest(req) {
		retryReq := req
		if req.GetBody != nil {
			body, bodyErr := req.GetBody()
			if bodyErr != nil {
				return nil, err
			}
			retryReq = req.Clone(req.Context())
			retryReq.Body = body
		}
		resp, err, _ = p.roundTripOnce(retryReq)
	}
	return resp, err
}

func (p *xmuxHTTPPool) effectiveH3HeaderWatchdog() time.Duration {
	if p.h3HeaderWatchdog > 0 {
		return p.h3HeaderWatchdog
	}
	return h3HeaderWatchdogTimeout
}

func (p *xmuxHTTPPool) effectiveH3LeadDelay() time.Duration {
	if p.h3LeadDelay > 0 {
		return p.h3LeadDelay
	}
	return h3HappyEyeballsDelay
}

// roundTripH3WithWatchdog guards HTTP/3 response-header waits when a TCP HTTP/2
// fallback exists so post-handshake UDP blackholes fail fast instead of
// stalling for ChromeParrot's full 30s QUIC MaxIdleTimeout. Non-replayable
// streaming uploads (stream-up / stream-one) are exempt because origin headers
// can legitimately wait for upload completion or stream-one auto timeout.
func (p *xmuxHTTPPool) roundTripH3WithWatchdog(req *http.Request, conn *xmuxHTTPConn) (*http.Response, error, bool) {
	if !p.hasTCPFallback || req.Method == http.MethodConnect || !isReplayableRequest(req) {
		resp, err := conn.h3Conn.roundTrip(req)
		return resp, err, false
	}
	timeout := p.effectiveH3HeaderWatchdog()
	if timeout <= 0 {
		resp, err := conn.h3Conn.roundTrip(req)
		return resp, err, false
	}
	var watchdogFired atomic.Bool
	timer := time.AfterFunc(timeout, func() {
		if req.Context().Err() != nil {
			return
		}
		watchdogFired.Store(true)
		conn.close()
	})
	resp, err := conn.h3Conn.roundTrip(req)
	stopped := timer.Stop()
	return resp, err, !stopped && watchdogFired.Load()
}

func (p *xmuxHTTPPool) roundTripOnce(req *http.Request) (*http.Response, error, bool) {
	conn, err := p.acquireConn(req.Context())
	if err != nil {
		return nil, err, false
	}
	var (
		resp    *http.Response
		tripped bool
	)
	switch {
	case conn.isH3:
		resp, err, tripped = p.roundTripH3WithWatchdog(req, conn)
	case conn.isH2:
		resp, err = conn.h2cc.RoundTrip(req)
	default:
		resp, err = conn.h1.RoundTrip(req)
	}
	if tripped {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			err = E.New("http3 response header watchdog timeout")
		}
		conn.closedErr.Store(true)
		p.markH3Failed(time.Now())
		p.releaseConn(conn, false)
		return nil, err, true
	}
	if err != nil {
		// Caller-initiated stream cancellation on multiplexed H2/H3 transports
		// should not poison the shared underlying connection for other streams.
		isCallerCancel := req.Context().Err() != nil && conn.isMultiplexed() && conn.isTransportAlive()
		if !isCallerCancel {
			conn.closedErr.Store(true)
			if conn.isH3 {
				p.recordH3RuntimeFailure(time.Now(), conn)
			}
		}
		keep := false
		if isCallerCancel {
			keep = adapter.KeepSessionFromContext(req.Context())
		}
		p.releaseConn(conn, keep)
		return nil, err, false
	}
	if conn.isH3 && p.h3HasFailures.Load() {
		p.recordH3RuntimeSuccess()
	}
	if !conn.isH3 && p.allowAltSvcH3 {
		if altSvcVals := resp.Header.Values("Alt-Svc"); len(altSvcVals) > 0 {
			p.recordAltSvc(altSvcVals, time.Now())
		}
	}
	var bodyErrOnce sync.Once
	trc := &trackedReadCloser{
		ReadCloser: resp.Body,
		onClose: func() {
			keep := adapter.KeepSessionFromContext(req.Context())
			p.releaseConn(conn, keep)
		},
	}
	if conn.isH3 && p.hasTCPFallback {
		trc.onReadError = func(_ error) {
			bodyErrOnce.Do(func() {
				if req.Context().Err() == nil && !conn.isTransportAlive() {
					conn.closedErr.Store(true)
					p.recordH3RuntimeFailure(time.Now(), conn)
				}
			})
		}
	}
	resp.Body = trc
	return resp, nil, false
}

func (p *xmuxHTTPPool) acquireConn(ctx context.Context) (*xmuxHTTPConn, error) {
	for {
		p.mu.Lock()
		canCoalesce := p.canCoalesce
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		now := time.Now()
		h3Degraded := p.isH3DegradedLocked(now)
		var toClose []*xmuxHTTPConn
		kept := p.conns[:0]
		var best *xmuxHTTPConn
		eligibleCount := 0
		hasAliveH3 := false
		for _, slot := range p.conns {
			if !slot.isAlive() || (slot.isH3 && h3Degraded) {
				if slot.active <= 0 {
					toClose = append(toClose, slot)
					continue
				}
				kept = append(kept, slot)
				continue
			}
			if slot.active == 0 && slot.limit.IsRetired(slot.total, now) {
				toClose = append(toClose, slot)
				continue
			}
			if slot.isH3 {
				hasAliveH3 = true
			}
			kept = append(kept, slot)
			if !slot.limit.CanTakeNewRequest(slot.active, slot.total, now) {
				continue
			}
			if !slot.isMultiplexed() && slot.active > 0 {
				// HTTP/1.1 connection cannot multiplex active requests concurrently.
				continue
			}
			eligibleCount++
			if best == nil ||
				(!h3Degraded && slot.isH3 && !best.isH3) ||
				(slot.isH3 == best.isH3 && slot.active < best.active) {
				best = slot
			}
		}
		if hasAliveH3 && !h3Degraded {
			filtered := kept[:0]
			for _, slot := range kept {
				if !slot.isH3 && slot.active <= 0 {
					toClose = append(toClose, slot)
					continue
				}
				filtered = append(filtered, slot)
			}
			kept = filtered
		}
		p.conns = kept

		if !h3Degraded && p.isH3EnabledLocked(now) && h3Supported && p.hasTCPFallback && p.tlsConfig != nil && best != nil && !best.isH3 && p.inflightDial == nil {
			needAltSvcProbe := p.allowAltSvcH3 && !p.altSvcUntil.IsZero() && now.Before(p.altSvcUntil) && !p.altSvcProbed
			if !p.h3RetryAfter.IsZero() || needAltSvcProbe {
				// H3 cooldown expired or Alt-Svc just advertised HTTP/3: probe once.
				p.h3RetryAfter = time.Time{}
				if needAltSvcProbe {
					p.altSvcProbed = true
				}
				best = nil
			}
		}

		shouldReuse := best != nil && (best.active == 0 || (p.maxConnections > 0 && eligibleCount >= p.maxConnections) || (p.maxConnections == 0 && best.isMultiplexed()))
		if shouldReuse {
			best.active++
			best.total++
			p.mu.Unlock()
			closeHTTPConns(toClose)
			return best, nil
		}
		if canCoalesce && p.inflightDial != nil {
			attempt := p.inflightDial
			p.mu.Unlock()
			closeHTTPConns(toClose)
			select {
			case <-attempt.done:
				if attempt.err != nil {
					if attempt.leaderCanceled && ctx.Err() == nil {
						continue
					}
					return nil, attempt.err
				}
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var attempt *dialAttempt
		if canCoalesce {
			attempt = &dialAttempt{done: make(chan struct{})}
			p.inflightDial = attempt
		}
		p.mu.Unlock()
		closeHTTPConns(toClose)

		fresh, err := p.dialNewConn(ctx)
		if err != nil {
			if attempt != nil {
				p.mu.Lock()
				attempt.err = err
				attempt.leaderCanceled = ctx.Err() != nil
				if p.inflightDial == attempt {
					p.inflightDial = nil
				}
				p.mu.Unlock()
				close(attempt.done)
			}
			return nil, err
		}
		p.mu.Lock()
		if p.closed {
			if attempt != nil {
				attempt.err = net.ErrClosed
				if p.inflightDial == attempt {
					p.inflightDial = nil
				}
			}
			p.mu.Unlock()
			if attempt != nil {
				close(attempt.done)
			}
			fresh.close()
			return nil, net.ErrClosed
		}
		fresh.active = 1
		fresh.total = 1
		var idleFallbackToClose []*xmuxHTTPConn
		if fresh.isH3 {
			keptAfterRecovery := p.conns[:0]
			for _, slot := range p.conns {
				if !slot.isH3 && slot.active <= 0 {
					idleFallbackToClose = append(idleFallbackToClose, slot)
					continue
				}
				keptAfterRecovery = append(keptAfterRecovery, slot)
			}
			p.conns = keptAfterRecovery
		}
		p.conns = append(p.conns, fresh)
		if attempt != nil {
			attempt.conn = fresh
			if p.inflightDial == attempt {
				p.inflightDial = nil
			}
		}
		p.mu.Unlock()
		closeHTTPConns(idleFallbackToClose)
		if attempt != nil {
			close(attempt.done)
		}
		return fresh, nil
	}
}

func (p *xmuxHTTPPool) hasAliveH3Locked() bool {
	for _, c := range p.conns {
		if c.isH3 && c.isAlive() {
			return true
		}
	}
	return false
}

func (p *xmuxHTTPPool) releaseConn(slot *xmuxHTTPConn, keepSession bool) {
	now := time.Now()
	p.mu.Lock()
	slot.active--
	shouldClose := slot.active <= 0 && (!slot.isAlive() || slot.limit.IsRetired(slot.total, now) || (!keepSession && p.closeIdle.Load()) || (!slot.isH3 && !p.isH3DegradedLocked(now) && p.hasAliveH3Locked()))
	if !shouldClose {
		p.mu.Unlock()
		return
	}
	for i, c := range p.conns {
		if c == slot {
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
	slot.close()
}

func (p *xmuxHTTPPool) isH3EnabledLocked(now time.Time) bool {
	if p.enableH3 {
		return true
	}
	return p.allowAltSvcH3 && !p.altSvcUntil.IsZero() && now.Before(p.altSvcUntil)
}

func (p *xmuxHTTPPool) h3DialTarget() M.Socksaddr {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.allowAltSvcH3 && !p.altSvcUntil.IsZero() && time.Now().Before(p.altSvcUntil) && p.altSvcTarget.Port != 0 {
		return p.altSvcTarget
	}
	return p.target
}

func parseAltSvcH3(values []string, baseTarget M.Socksaddr, serverName string) (target M.Socksaddr, maxAge time.Duration, clear bool, ok bool) {
	for _, header := range values {
		for _, rawEntry := range strings.Split(header, ",") {
			entry := strings.TrimSpace(rawEntry)
			if entry == "" {
				continue
			}
			if strings.EqualFold(entry, "clear") {
				clear = true
				continue
			}
			parts := strings.Split(entry, ";")
			proto, auth, hasEq := strings.Cut(strings.TrimSpace(parts[0]), "=")
			if !hasEq || !strings.EqualFold(strings.TrimSpace(proto), h3NextProto) {
				continue
			}
			auth = strings.Trim(strings.TrimSpace(auth), `"`)
			host, portStr, err := net.SplitHostPort(auth)
			if err != nil {
				continue
			}
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil || port == 0 {
				continue
			}
			if host != "" && !strings.EqualFold(host, serverName) && !strings.EqualFold(host, baseTarget.AddrString()) {
				// Reject third-party authority redirects in Alt-Svc to prevent target hijacking.
				continue
			}
			ma := h3AltSvcMaxAge
			for _, param := range parts[1:] {
				k, v, hasParamEq := strings.Cut(strings.TrimSpace(param), "=")
				if !hasParamEq || !strings.EqualFold(strings.TrimSpace(k), "ma") {
					continue
				}
				v = strings.Trim(strings.TrimSpace(v), `"`)
				secs, err := strconv.ParseInt(v, 10, 64)
				if err != nil || secs <= 0 {
					ma = 0
					break
				}
				ma = min(time.Duration(secs)*time.Second, h3AltSvcMaxAge)
			}
			if ma <= 0 {
				continue
			}
			return M.Socksaddr{
				Addr: baseTarget.Addr,
				Fqdn: baseTarget.Fqdn,
				Port: uint16(port),
			}, ma, false, true
		}
	}
	return M.Socksaddr{}, 0, clear, false
}

func (p *xmuxHTTPPool) recordAltSvc(values []string, now time.Time) {
	if p.tlsConfig == nil || !h3Supported {
		return
	}
	serverName := p.tlsConfig.ServerName()
	target, ma, clear, ok := parseAltSvcH3(values, p.target, serverName)
	if !ok && !clear {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if clear && !ok {
		p.altSvcTarget = M.Socksaddr{}
		p.altSvcUntil = time.Time{}
		p.altSvcProbed = false
		return
	}
	wasActive := !p.altSvcUntil.IsZero() && now.Before(p.altSvcUntil)
	prevTarget := p.altSvcTarget
	if prevTarget.Port == 0 {
		prevTarget = p.target
	}
	if target != prevTarget || !wasActive {
		p.altSvcProbed = false
		if target != prevTarget {
			p.h3RetryAfter = time.Time{}
			p.h3CooldownShift = 0
		}
	}
	p.altSvcTarget = target
	p.altSvcUntil = now.Add(ma)
}

func (p *xmuxHTTPPool) nextH3CooldownLocked() time.Duration {
	shift := p.h3CooldownShift
	if shift > 4 {
		shift = 4
	}
	cooldown := h3FallbackCooldown << shift
	if cooldown > h3FallbackMaxCooldown {
		cooldown = h3FallbackMaxCooldown
	}
	p.h3CooldownShift++
	return cooldown
}

func (p *xmuxHTTPPool) isH3DegradedLocked(now time.Time) bool {
	if !p.hasTCPFallback {
		return false
	}
	return !p.h3RetryAfter.IsZero() && now.Before(p.h3RetryAfter)
}

func (p *xmuxHTTPPool) shouldAttemptH3(now time.Time) (tryH3 bool, allowFallback bool) {
	if p.tlsConfig == nil {
		return false, true
	}
	p.mu.Lock()
	h3Enabled := p.isH3EnabledLocked(now)
	retryAfter := p.h3RetryAfter
	p.mu.Unlock()
	if !h3Enabled {
		return false, true
	}
	if !retryAfter.IsZero() && now.Before(retryAfter) {
		if p.hasTCPFallback {
			return false, true
		}
		return true, false
	}
	return true, p.hasTCPFallback
}

func (p *xmuxHTTPPool) markH3Failed(now time.Time) {
	p.mu.Lock()
	p.h3RetryAfter = now.Add(p.nextH3CooldownLocked())
	p.h3Failures = 0
	p.h3FailureAt = time.Time{}
	p.h3HasFailures.Store(false)
	p.mu.Unlock()
}

func (p *xmuxHTTPPool) clearH3Failure() {
	p.mu.Lock()
	p.h3RetryAfter = time.Time{}
	p.h3CooldownShift = 0
	p.h3Failures = 0
	p.h3FailureAt = time.Time{}
	p.h3HasFailures.Store(false)
	p.mu.Unlock()
}

func (p *xmuxHTTPPool) recordH3RuntimeSuccess() {
	p.mu.Lock()
	p.h3Failures = 0
	p.h3FailureAt = time.Time{}
	p.h3HasFailures.Store(false)
	p.h3CooldownShift = 0
	p.mu.Unlock()
}

func (p *xmuxHTTPPool) recordH3RuntimeFailure(now time.Time, conn *xmuxHTTPConn) {
	if !p.hasTCPFallback {
		return
	}
	p.mu.Lock()
	if p.h3FailureAt.IsZero() || now.Sub(p.h3FailureAt) > h3DegradeFailureWindow {
		p.h3Failures = 1
	} else {
		p.h3Failures++
	}
	p.h3FailureAt = now
	if p.h3Failures >= h3DegradeFailureThreshold {
		p.h3RetryAfter = now.Add(p.nextH3CooldownLocked())
		p.h3Failures = 0
		p.h3FailureAt = time.Time{}
		p.h3HasFailures.Store(false)
		if conn != nil {
			conn.closedErr.Store(true)
		}
	} else {
		p.h3HasFailures.Store(true)
	}
	p.mu.Unlock()
}

func (p *xmuxHTTPPool) dialNewConn(ctx context.Context) (*xmuxHTTPConn, error) {
	limit := mux.NewXmuxSessionLimit(p.xmux, time.Now())
	tryH3, allowFallback := p.shouldAttemptH3(time.Now())
	if tryH3 {
		if !h3Supported {
			if !allowFallback {
				return nil, C.ErrQUICNotIncluded
			}
			p.markH3Failed(time.Now())
		} else if allowFallback {
			return p.dialH3WithHappyEyeballs(ctx, limit)
		} else {
			conn, err := p.dialH3Conn(ctx, limit)
			if err == nil {
				p.clearH3Failure()
				return conn, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
	}
	if p.tlsConfig != nil && !allowFallback {
		return nil, C.ErrQUICNotIncluded
	}
	return p.dialTCPConn(ctx, limit)
}

// dialH3WithHappyEyeballs races HTTP/3 (after a short lead window) against TCP
// HTTP/2 so UDP blackholes fail over in ~250ms instead of blocking the full
// QUIC fallback dial timeout.
func (p *xmuxHTTPPool) dialH3WithHappyEyeballs(ctx context.Context, limit mux.XmuxSessionLimit) (*xmuxHTTPConn, error) {
	h3Ctx, h3Cancel := context.WithCancel(ctx)
	tcpCtx, tcpCancel := context.WithCancel(ctx)

	type dialRaceResult struct {
		isH3 bool
		conn *xmuxHTTPConn
		err  error
	}
	resCh := make(chan dialRaceResult, 2)
	var wg sync.WaitGroup
	var tcpStarted bool

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := p.dialH3Conn(h3Ctx, limit)
		resCh <- dialRaceResult{isH3: true, conn: conn, err: err}
	}()

	startTCP := func() {
		if tcpStarted {
			return
		}
		tcpStarted = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := p.dialTCPConn(tcpCtx, limit)
			resCh <- dialRaceResult{isH3: false, conn: conn, err: err}
		}()
	}

	var (
		h3Err    error
		h3Failed bool
		tcpErr   error
		received int
	)

	cleanup := func() {
		h3Cancel()
		tcpCancel()
		pending := (tcpStarted && received < 2) || (!tcpStarted && received < 1)
		drain := func() {
			wg.Wait()
			close(resCh)
			for r := range resCh {
				if r.conn != nil {
					r.conn.close()
				}
			}
		}
		if pending {
			go drain()
		} else {
			drain()
		}
	}

	leadTimer := time.NewTimer(p.effectiveH3LeadDelay())
	defer leadTimer.Stop()
	leadCh := leadTimer.C

	for {
		expected := 1
		if tcpStarted {
			expected = 2
		}
		if received >= expected && tcpStarted {
			cleanup()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if h3Failed {
				p.markH3Failed(time.Now())
			}
			if tcpErr != nil {
				return nil, tcpErr
			}
			return nil, h3Err
		}

		select {
		case <-ctx.Done():
			cleanup()
			return nil, ctx.Err()
		case <-leadCh:
			leadCh = nil
			startTCP()
		case res := <-resCh:
			received++
			if res.err == nil && res.conn != nil {
				if res.isH3 {
					p.clearH3Failure()
				} else if h3Failed {
					p.markH3Failed(time.Now())
				} else {
					p.recordH3RuntimeFailure(time.Now(), nil)
				}
				cleanup()
				return res.conn, nil
			}
			if res.isH3 {
				h3Err = res.err
				if ctx.Err() == nil && h3Ctx.Err() == nil {
					h3Failed = true
				}
				if !tcpStarted {
					leadTimer.Stop()
					leadCh = nil
					startTCP()
				}
			} else {
				tcpErr = res.err
			}
		}
	}
}

func (p *xmuxHTTPPool) dialTCPConn(ctx context.Context, limit mux.XmuxSessionLimit) (*xmuxHTTPConn, error) {
	dialCtx := adapter.ContextForMultiplexSession(ctx)
	if p.tlsConfig != nil {
		if p.tlsDialer == nil {
			return nil, C.ErrQUICNotIncluded
		}
		rawConn, err := p.tlsDialer.DialTLSContext(dialCtx, p.target)
		if err != nil {
			return nil, err
		}
		useH2 := p.preferH2
		if csConn, ok := rawConn.(interface{ ConnectionState() stdtls.ConnectionState }); ok {
			switch csConn.ConnectionState().NegotiatedProtocol {
			case "http/1.1":
				useH2 = false
			case http2.NextProtoTLS:
				useH2 = true
			}
		}
		if useH2 {
			h2Tr := p.newH2Transport(limit.KeepAlivePeriod)
			cc, err := h2Tr.NewClientConn(rawConn)
			if err != nil {
				_ = rawConn.Close()
				return nil, E.Cause(err, "xhttp h2 client conn")
			}
			return &xmuxHTTPConn{isH2: true, h2cc: cc, rawConn: rawConn, limit: limit}, nil
		}
		var once sync.Once
		h1Tr := &http.Transport{
			MaxConnsPerHost: 1,
			MaxIdleConns:    1,
			DialTLSContext: func(dCtx context.Context, _, _ string) (net.Conn, error) {
				var pre net.Conn
				once.Do(func() {
					pre = rawConn
				})
				if pre != nil {
					return pre, nil
				}
				return p.tlsDialer.DialTLSContext(adapter.ContextForMultiplexSession(dCtx), p.target)
			},
		}
		return &xmuxHTTPConn{isH2: false, h1: h1Tr, limit: limit}, nil
	}

	if p.preferH2 {
		rawConn, err := p.dialer.DialContext(dialCtx, N.NetworkTCP, p.target)
		if err != nil {
			return nil, err
		}
		h2Tr := p.newH2Transport(limit.KeepAlivePeriod)
		h2Tr.AllowHTTP = true
		cc, err := h2Tr.NewClientConn(rawConn)
		if err != nil {
			_ = rawConn.Close()
			return nil, E.Cause(err, "xhttp h2c client conn")
		}
		return &xmuxHTTPConn{isH2: true, h2cc: cc, rawConn: rawConn, limit: limit}, nil
	}

	h1Tr := &http.Transport{
		MaxConnsPerHost: 1,
		MaxIdleConns:    1,
		IdleConnTimeout: p.idleTimeout,
		DialContext: func(dCtx context.Context, network, _ string) (net.Conn, error) {
			return p.dialer.DialContext(adapter.ContextForMultiplexSession(dCtx), network, p.target)
		},
	}
	return &xmuxHTTPConn{isH2: false, h1: h1Tr, limit: limit}, nil
}

func (p *xmuxHTTPPool) newH2Transport(xmuxKeepAlive time.Duration) *http2.Transport {
	readIdle := p.idleTimeout
	pingTimeout := p.pingTimeout
	if xmuxKeepAlive > 0 {
		readIdle = xmuxKeepAlive
		if pingTimeout <= 0 {
			pingTimeout = 15 * time.Second
		}
	}
	return &http2.Transport{
		ReadIdleTimeout:  readIdle,
		PingTimeout:      pingTimeout,
		MaxReadFrameSize: buf.BufferSize,
		Fingerprint:      p.h2Fingerprint.Clone(),
	}
}

func (p *xmuxHTTPPool) setKeepIdleConnections(keep bool) {
	p.closeIdle.Store(!keep)
	if !keep {
		p.closeIdleConnections()
	}
}

func (p *xmuxHTTPPool) closeIdleConnections() {
	p.mu.Lock()
	var toClose []*xmuxHTTPConn
	kept := p.conns[:0]
	for _, slot := range p.conns {
		if slot.active == 0 {
			toClose = append(toClose, slot)
			continue
		}
		kept = append(kept, slot)
	}
	p.conns = kept
	p.mu.Unlock()
	closeHTTPConns(toClose)
}

func (p *xmuxHTTPPool) closeAll() {
	p.mu.Lock()
	p.closed = true
	toClose := p.conns
	p.conns = nil
	p.mu.Unlock()
	closeHTTPConns(toClose)
}

func closeHTTPConns(conns []*xmuxHTTPConn) {
	for _, c := range conns {
		c.close()
	}
}

type trackedReadCloser struct {
	io.ReadCloser
	once        sync.Once
	onClose     func()
	onReadError func(err error)
}

func (r *trackedReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if err != nil && err != io.EOF && r.onReadError != nil {
		r.onReadError(err)
	}
	return n, err
}

func (r *trackedReadCloser) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(func() {
		if r.onClose != nil {
			r.onClose()
		}
	})
	return err
}

func (r *trackedReadCloser) Upstream() any {
	return r.ReadCloser
}
