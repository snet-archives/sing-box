package v2rayxhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/badhttp"
	"github.com/sagernet/sing-box/common/browserhdr"
	sdialer "github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common/baderror"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/http2"
)

var (
	_ adapter.V2RayMultiplexClientTransport = (*Client)(nil)
	_ adapter.IdleConnectionKeeper          = (*Client)(nil)
)

const (
	defaultStreamBufferBytes     = 256 * 1024
	maxDownlinkResumeAttempts    = 4
	maxUplinkChunkAttempts       = 4
	minAdaptiveChunkBytes        = 4096
	minAdaptiveNonBodyChunkBytes = 512
	defaultStreamOneAutoTimeout  = 8 * time.Second
	defaultStreamUpRotatePeriod  = 50 * time.Second
	defaultAutoFallbackCooldown  = 2 * time.Minute
	maxAutoFallbackCooldown      = 15 * time.Minute
	minAdaptivePostInterval      = 50 * time.Millisecond
	maxAdaptivePostInterval      = 1000 * time.Millisecond
	maxRetryAfterWait            = 15 * time.Second
	rateLimitRecoveryStreak      = 4
)

var errChunkTooLarge = errors.New("xhttp chunk exceeds proxy limit")

func isAdaptiveChunkTooLargeStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestEntityTooLarge,
		http.StatusRequestURITooLong,
		http.StatusRequestHeaderFieldsTooLarge:
		return true
	default:
		return false
	}
}

func isRetryableXHTTPStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		// Cloudflare/CDN transient origin errors (520-524).
		return statusCode >= 520 && statusCode <= 524
	}
}

func waitDurationContext(ctx context.Context, d time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

func waitRetryBackoff(ctx context.Context, attempt int) bool {
	if attempt <= 0 {
		return ctx.Err() == nil
	}
	return waitDurationContext(ctx, time.Duration(attempt*100)*time.Millisecond)
}

func parseRetryAfter(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(value, 10, 64); err == nil {
		if secs <= 0 {
			return minAdaptivePostInterval, true
		}
		d := time.Duration(secs) * time.Second
		if d > maxRetryAfterWait {
			d = maxRetryAfterWait
		}
		return d, true
	}
	if ts, err := http.ParseTime(value); err == nil {
		d := ts.Sub(now)
		if d <= 0 {
			return minAdaptivePostInterval, true
		}
		if d > maxRetryAfterWait {
			d = maxRetryAfterWait
		}
		return d, true
	}
	return 0, false
}

// Client implements the XHTTP (SplitHTTP) V2Ray client transport supporting
// packet-up, stream-up, stream-one, auto mode, download channel separation,
// browserhdr fetch headers, multi-placement encoding, and Xmux pooling.
type Client struct {
	ctx          context.Context
	mode         string
	cfg          placementConfig
	hosts        []string
	dlHosts      []string
	headers      http.Header
	baseURL      url.URL
	dlURL        url.URL
	noGRPCHeader bool

	uplinkPool             *xmuxHTTPPool
	downlinkPool           *xmuxHTTPPool
	closeIdle              atomic.Bool
	autoMode               bool
	autoFallbackPacketUp   atomic.Bool
	autoFallbackUntil      atomic.Int64
	autoFallbackCount      atomic.Int32
	autoProbing            atomic.Bool
	confirmedMaxChunkBytes atomic.Int64
	streamOneAutoTimeout   time.Duration
	streamUpAutoRotate     time.Duration
	autoFallbackCooldown   time.Duration
	adaptiveMaxChunkBytes  atomic.Int64
	rateLimitUntil         atomic.Int64
	adaptivePostIntervalNs atomic.Int64
	rateLimitOKStreak      atomic.Int32
}

func (c *Client) effectiveStreamOneAutoTimeout() time.Duration {
	if c.streamOneAutoTimeout > 0 {
		return c.streamOneAutoTimeout
	}
	return defaultStreamOneAutoTimeout
}

func (c *Client) effectiveStreamUpRotatePeriod() time.Duration {
	if c.streamUpAutoRotate > 0 {
		return c.streamUpAutoRotate
	}
	return defaultStreamUpRotatePeriod
}

func (c *Client) effectiveAutoFallbackCooldown() time.Duration {
	if c.autoFallbackCooldown > 0 {
		return c.autoFallbackCooldown
	}
	return defaultAutoFallbackCooldown
}

func (c *Client) acquireAutoRoute() (usePacketUp bool, probing bool) {
	if !c.autoMode || !c.autoFallbackPacketUp.Load() {
		return false, false
	}
	until := c.autoFallbackUntil.Load()
	if until == 0 || time.Now().UnixNano() < until {
		return true, false
	}
	if c.autoProbing.CompareAndSwap(false, true) {
		return false, true
	}
	return true, false
}

func (c *Client) triggerAutoFallback() {
	if !c.autoMode {
		return
	}
	shift := int(c.autoFallbackCount.Add(1) - 1)
	if shift < 0 {
		shift = 0
	} else if shift > 3 {
		shift = 3
	}
	base := c.effectiveAutoFallbackCooldown()
	cooldown := base << shift
	if c.autoFallbackCooldown <= 0 && cooldown > maxAutoFallbackCooldown {
		cooldown = maxAutoFallbackCooldown
	}
	until := time.Now().Add(cooldown).UnixNano()
	for {
		cur := c.autoFallbackUntil.Load()
		if cur >= until || c.autoFallbackUntil.CompareAndSwap(cur, until) {
			break
		}
	}
	c.autoFallbackPacketUp.Store(true)
	c.autoProbing.Store(false)
}

func (c *Client) recordAutoStreamSuccess() {
	c.autoFallbackUntil.Store(0)
	c.autoFallbackCount.Store(0)
	c.autoFallbackPacketUp.Store(false)
	c.autoProbing.Store(false)
}

func (c *Client) releaseAutoProbe() {
	c.autoProbing.Store(false)
}

func (c *Client) shouldProbeChunkSize(chunkLen int, minFloor int) bool {
	if chunkLen <= minFloor {
		return false
	}
	if capBytes := c.adaptiveMaxChunkBytes.Load(); capBytes > 0 && capBytes <= int64(minFloor) {
		return false
	}
	return int64(chunkLen) > c.confirmedMaxChunkBytes.Load()
}

func (c *Client) recordProbedChunkSize(chunkLen int, minFloor int) {
	if chunkLen <= minFloor {
		return
	}
	for {
		cur := c.confirmedMaxChunkBytes.Load()
		if int64(chunkLen) <= cur {
			return
		}
		if c.confirmedMaxChunkBytes.CompareAndSwap(cur, int64(chunkLen)) {
			return
		}
	}
}

func (c *Client) effectiveChunkCap(configured int) int {
	if capBytes := int(c.adaptiveMaxChunkBytes.Load()); capBytes > 0 && capBytes < configured {
		return capBytes
	}
	return configured
}

func (c *Client) shrinkChunkCap(rejectedLen int, minFloor int) bool {
	if minFloor <= 0 {
		minFloor = minAdaptiveChunkBytes
	}
	if rejectedLen <= minFloor {
		return false
	}
	next := rejectedLen / 2
	if next < minFloor {
		next = minFloor
	}
	clampConfirmed := func(limit int64) {
		for {
			confirmed := c.confirmedMaxChunkBytes.Load()
			if confirmed <= limit {
				return
			}
			if c.confirmedMaxChunkBytes.CompareAndSwap(confirmed, limit) {
				return
			}
		}
	}
	for {
		cur := c.adaptiveMaxChunkBytes.Load()
		if cur > 0 && int(cur) <= next {
			clampConfirmed(cur)
			return int(cur) < rejectedLen
		}
		if c.adaptiveMaxChunkBytes.CompareAndSwap(cur, int64(next)) {
			clampConfirmed(int64(next))
			return true
		}
	}
}

func (c *Client) recordRateLimit(retryAfter time.Duration) {
	c.rateLimitOKStreak.Store(0)
	wait := retryAfter
	if wait <= 0 {
		wait = minAdaptivePostInterval
	}
	until := time.Now().Add(wait).UnixNano()
	for {
		cur := c.rateLimitUntil.Load()
		if cur >= until || c.rateLimitUntil.CompareAndSwap(cur, until) {
			break
		}
	}
	for {
		cur := time.Duration(c.adaptivePostIntervalNs.Load())
		next := cur * 2
		if next < minAdaptivePostInterval {
			next = minAdaptivePostInterval
		}
		if next > maxAdaptivePostInterval {
			next = maxAdaptivePostInterval
		}
		if cur >= next || c.adaptivePostIntervalNs.CompareAndSwap(int64(cur), int64(next)) {
			break
		}
	}
}

func (c *Client) recordPostSuccess() {
	if c.adaptivePostIntervalNs.Load() == 0 {
		return
	}
	if c.rateLimitOKStreak.Add(1) < rateLimitRecoveryStreak {
		return
	}
	c.rateLimitOKStreak.Store(0)
	for {
		cur := time.Duration(c.adaptivePostIntervalNs.Load())
		if cur <= 0 {
			return
		}
		next := cur / 2
		if next < minAdaptivePostInterval/2 {
			next = 0
		}
		if c.adaptivePostIntervalNs.CompareAndSwap(int64(cur), int64(next)) {
			return
		}
	}
}

func (c *Client) waitRateLimitPace(ctx context.Context) (waited bool, ok bool) {
	until := c.rateLimitUntil.Load()
	if until <= 0 {
		return false, ctx.Err() == nil
	}
	wait := time.Until(time.Unix(0, until))
	if wait <= 0 {
		return false, ctx.Err() == nil
	}
	return true, waitDurationContext(ctx, wait)
}

func (c *Client) effectivePostInterval(configured time.Duration) time.Duration {
	adaptive := time.Duration(c.adaptivePostIntervalNs.Load())
	if adaptive > configured {
		return adaptive
	}
	return configured
}

func (c *Client) isRateThrottled() bool {
	if c.adaptivePostIntervalNs.Load() > 0 {
		return true
	}
	until := c.rateLimitUntil.Load()
	return until > 0 && time.Now().UnixNano() < until
}

func formatHostFromAddr(addr M.Socksaddr) string {
	if addr.IsIPv6() {
		return "[" + addr.AddrString() + "]"
	}
	return addr.AddrString()
}

func buildHeaders(raw option.V2RayXHTTPOptions, tlsConfig tls.Config) http.Header {
	userHeaders := raw.Headers.Build()
	headers := userHeaders.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	if len(userHeaders.Values("User-Agent")) == 0 {
		if client, version, ok := tls.UTLSFingerprint(tlsConfig); ok {
			browserhdr.ApplyForUTLS(headers, client, version, "fetch")
		} else {
			browserhdr.TryDefaultHeadersWith(headers, "fetch")
		}
	} else {
		browserhdr.TryDefaultHeadersWith(headers, "fetch")
	}
	// Preserve caller-supplied non-UA header overrides over generated defaults.
	for k, vals := range userHeaders {
		if http.CanonicalHeaderKey(k) == "User-Agent" {
			continue
		}
		headers[k] = append([]string(nil), vals...)
	}
	return headers
}

func allowAltSvcForTLS(tlsConfig tls.Config, hasQUIC bool) bool {
	if !tls.SupportsQUIC(tlsConfig) {
		return false
	}
	protos := tlsConfig.NextProtos()
	return len(protos) == 0 || hasQUIC || slices.Contains(protos, h3NextProto)
}

func configureClientTLSForXHTTP(tlsConfig tls.Config, hasQUIC bool) error {
	if tlsConfig == nil {
		return nil
	}
	supportsQUIC := tls.SupportsQUIC(tlsConfig)
	if len(tlsConfig.NextProtos()) == 0 {
		if hasQUIC && supportsQUIC {
			tlsConfig.SetNextProtos([]string{h3NextProto, http2.NextProtoTLS, "http/1.1"})
		} else {
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
		}
	}
	enableH3, allowTCP, _ := resolveXHTTPProtos(tlsConfig.NextProtos(), hasQUIC)
	if enableH3 && !allowTCP {
		if !supportsQUIC {
			return E.New("xhttp: TLS configuration does not support HTTP/3 (QUIC)")
		}
		if !h3Supported {
			return C.ErrQUICNotIncluded
		}
	}
	return nil
}

// NewClient constructs a validated XHTTP client transport.
func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (*Client, error) {
	cfg, err := parsePlacementConfig(options)
	if err != nil {
		return nil, err
	}

	hasDownloadSplit := options.DownloadDialer != nil || options.DownloadTLS != nil || options.DownloadAddress != "" || options.DownloadPort != 0
	requestedAuto := options.Mode == "" || options.Mode == modeAuto
	mode := options.Mode
	if requestedAuto {
		if hasDownloadSplit {
			mode = modeStreamUp
		} else if tlsConfig != nil {
			mode = modeStreamOne
		} else {
			mode = modePacketUp
		}
	}

	uplinkAllowAltSvc := allowAltSvcForTLS(tlsConfig, options.QUIC != nil)
	if err = configureClientTLSForXHTTP(tlsConfig, options.QUIC != nil); err != nil {
		return nil, err
	}

	hosts := append([]string(nil), options.Host...)
	if len(hosts) == 0 {
		if tlsConfig != nil && tlsConfig.ServerName() != "" {
			hosts = []string{tlsConfig.ServerName()}
		} else if tlsConfig != nil {
			hosts = []string{"www.example.com"}
		} else {
			hosts = []string{formatHostFromAddr(serverAddr)}
		}
	}

	baseURL := url.URL{
		Scheme: "http",
		Host:   serverAddr.String(),
		Path:   cfg.basePath,
	}
	if tlsConfig != nil {
		baseURL.Scheme = "https"
	}
	if err = badhttp.URLSetPath(&baseURL, cfg.basePath); err != nil {
		return nil, E.Cause(err, "xhttp: parse path")
	}

	xmuxOpts := options.Xmux.ToMux()
	idleTimeout := time.Duration(options.IdleTimeout)
	pingTimeout := time.Duration(options.PingTimeout)
	uplinkPool := newXmuxHTTPPool(dialer, serverAddr, tlsConfig, mode != modePacketUp, idleTimeout, pingTimeout, xmuxOpts, options.QUIC)
	uplinkPool.setAllowAltSvcH3(uplinkAllowAltSvc)

	downlinkPool := uplinkPool
	dlURL := baseURL
	dlHosts := hosts
	if hasDownloadSplit {
		dlAddr := serverAddr
		if options.DownloadAddress != "" {
			dlPort := serverAddr.Port
			if options.DownloadPort != 0 {
				dlPort = options.DownloadPort
			}
			dlAddr = M.ParseSocksaddrHostPort(options.DownloadAddress, dlPort)
		} else if options.DownloadPort != 0 {
			dlAddr.Port = options.DownloadPort
		}

		dlDialer := dialer
		if options.DownloadDialer != nil {
			dlDialer, err = sdialer.New(ctx, *options.DownloadDialer, dlAddr.IsDomain())
			if err != nil {
				return nil, E.Cause(err, "xhttp: download_dialer")
			}
		}

		dlTLS := tlsConfig
		dlAllowAltSvc := uplinkAllowAltSvc
		if options.DownloadTLS != nil {
			if options.DownloadTLS.Enabled {
				serverName := dlAddr.AddrString()
				dlTLS, err = tls.NewClientWithOptions(tls.ClientOptions{
					Context:       ctx,
					Logger:        logger.NOP(),
					ServerAddress: serverName,
					Options:       *options.DownloadTLS,
				})
				if err != nil {
					return nil, E.Cause(err, "xhttp: download_tls")
				}
				dlAllowAltSvc = allowAltSvcForTLS(dlTLS, options.QUIC != nil)
				if err = configureClientTLSForXHTTP(dlTLS, options.QUIC != nil); err != nil {
					return nil, err
				}
			} else {
				dlTLS = nil
				dlAllowAltSvc = false
			}
		}

		downlinkPool = newXmuxHTTPPool(dlDialer, dlAddr, dlTLS, dlTLS != nil || mode != modePacketUp, idleTimeout, pingTimeout, xmuxOpts, options.QUIC)
		downlinkPool.setAllowAltSvcH3(dlAllowAltSvc)
		dlURL = url.URL{
			Scheme: "http",
			Host:   dlAddr.String(),
			Path:   cfg.basePath,
		}
		if dlTLS != nil {
			dlURL.Scheme = "https"
		}
		if err = badhttp.URLSetPath(&dlURL, cfg.basePath); err != nil {
			return nil, E.Cause(err, "xhttp: parse download path")
		}
		if len(options.Host) == 0 && dlTLS != nil && dlTLS.ServerName() != "" {
			dlHosts = []string{dlTLS.ServerName()}
		}
	}

	headers := buildHeaders(options, tlsConfig)
	uplinkPool.h2Fingerprint = tls.HTTP2FingerprintForHeaders(tlsConfig, headers, "fetch")
	if downlinkPool != uplinkPool {
		downlinkPool.h2Fingerprint = tls.HTTP2FingerprintForHeaders(downlinkPool.tlsConfig, headers, "fetch")
	}

	return &Client{
		ctx:          ctx,
		mode:         mode,
		autoMode:     requestedAuto && mode != modePacketUp,
		cfg:          cfg,
		hosts:        hosts,
		dlHosts:      dlHosts,
		headers:      headers,
		baseURL:      baseURL,
		dlURL:        dlURL,
		noGRPCHeader: options.NoGRPCHeader,
		uplinkPool:   uplinkPool,
		downlinkPool: downlinkPool,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	usePacketUp, probing := c.acquireAutoRoute()
	if usePacketUp {
		return c.dialSplit(ctx, modePacketUp, false)
	}
	if c.mode == modeStreamOne {
		return c.dialStreamOne(ctx, probing)
	}
	return c.dialSplit(ctx, c.mode, probing)
}

type autoBufferingWatchdog struct {
	client       *Client
	openedAt     time.Time
	probing      bool
	upSentBytes  atomic.Int64
	dlBytesRead  atomic.Int64
	timerOnce    sync.Once
	fallbackOnce sync.Once
	mu           sync.Mutex
	timer        *time.Timer
	stopped      bool
	onStall      func()
}

func newAutoBufferingWatchdog(client *Client, probing bool, onStall func()) *autoBufferingWatchdog {
	return &autoBufferingWatchdog{
		client:   client,
		openedAt: time.Now(),
		probing:  probing,
		onStall:  onStall,
	}
}

func (w *autoBufferingWatchdog) triggerFallback() {
	w.fallbackOnce.Do(func() {
		w.client.triggerAutoFallback()
	})
}

func (w *autoBufferingWatchdog) onUplinkSent(n int) {
	if n <= 0 {
		return
	}
	w.upSentBytes.Add(int64(n))
	if w.dlBytesRead.Load() != 0 {
		return
	}
	w.timerOnce.Do(func() {
		timeout := w.client.effectiveStreamOneAutoTimeout()
		if timeout <= 0 {
			return
		}
		w.mu.Lock()
		if w.stopped || w.dlBytesRead.Load() != 0 {
			w.mu.Unlock()
			return
		}
		w.timer = time.AfterFunc(timeout, func() {
			w.mu.Lock()
			stopped := w.stopped
			w.stopped = true
			w.mu.Unlock()
			if !stopped && w.dlBytesRead.Load() == 0 && w.upSentBytes.Load() > 0 {
				w.triggerFallback()
				if w.onStall != nil {
					w.onStall()
				}
			}
		})
		w.mu.Unlock()
	})
}

func (w *autoBufferingWatchdog) onDownlinkRead(n int) {
	if n <= 0 {
		return
	}
	if w.dlBytesRead.Add(int64(n)) == int64(n) {
		w.mu.Lock()
		w.stopped = true
		timer := w.timer
		w.timer = nil
		w.mu.Unlock()
		if timer != nil {
			timer.Stop()
		}
		if w.probing {
			w.client.recordAutoStreamSuccess()
		}
	}
}

func (w *autoBufferingWatchdog) onClose() {
	w.mu.Lock()
	w.stopped = true
	timer := w.timer
	w.timer = nil
	w.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
	dlRead := w.dlBytesRead.Load()
	if dlRead == 0 && w.upSentBytes.Load() > 0 && time.Since(w.openedAt) >= w.client.effectiveStreamOneAutoTimeout() {
		w.triggerFallback()
	} else if w.probing && dlRead == 0 {
		w.client.releaseAutoProbe()
	}
}

type streamOneClientConn struct {
	*v2rayhttp.HTTP2Conn
	watchdog  *autoBufferingWatchdog
	closeOnce sync.Once
}

func (c *streamOneClientConn) Read(b []byte) (int, error) {
	n, err := c.HTTP2Conn.Read(b)
	if n > 0 && c.watchdog != nil {
		c.watchdog.onDownlinkRead(n)
	}
	return n, err
}

func (c *streamOneClientConn) Write(b []byte) (int, error) {
	n, err := c.HTTP2Conn.Write(b)
	if n > 0 && c.watchdog != nil {
		c.watchdog.onUplinkSent(n)
	}
	return n, err
}

func (c *streamOneClientConn) Close() error {
	c.closeOnce.Do(func() {
		if c.watchdog != nil {
			c.watchdog.onClose()
		}
	})
	return c.HTTP2Conn.Close()
}

func (c *Client) dialStreamOne(ctx context.Context, probing bool) (net.Conn, error) {
	pipeInReader, pipeInWriter := io.Pipe()
	reqCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	request := c.cfg.buildRequest(c.baseURL, http.MethodPost, randomChoice(c.hosts), c.headers, "", nil, nil)
	request.Body = pipeInReader
	request = request.WithContext(reqCtx)
	if !c.noGRPCHeader && request.Header.Get("Content-Type") == "" {
		request.Header.Set("Content-Type", "application/grpc")
	}
	conn := v2rayhttp.NewLateHTTPConn(pipeInWriter, cancel)
	var outConn net.Conn = conn
	var wrapped *streamOneClientConn
	if c.autoMode {
		wrapped = &streamOneClientConn{HTTP2Conn: conn}
		wrapped.watchdog = newAutoBufferingWatchdog(c, probing, func() {
			cancel()
			_ = conn.Close()
		})
		outConn = wrapped
	}
	onHandshakeFailure := func(allowFallback bool) {
		if allowFallback && c.autoMode {
			if wrapped != nil && wrapped.watchdog != nil {
				wrapped.watchdog.triggerFallback()
			} else {
				c.triggerAutoFallback()
			}
			return
		}
		if probing {
			c.releaseAutoProbe()
		}
	}
	handshakeTimeout := C.TCPTimeout
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		handshakeTimeout = time.Until(deadline)
	}
	if c.autoMode {
		if autoTimeout := c.effectiveStreamOneAutoTimeout(); autoTimeout > 0 && autoTimeout < handshakeTimeout {
			handshakeTimeout = autoTimeout
		}
	}
	var timedOut atomic.Bool
	timer := time.AfterFunc(handshakeTimeout, func() {
		timedOut.Store(true)
		cancel()
	})
	go func() {
		resp, err := c.uplinkPool.roundTrip(request)
		timer.Stop()
		if err != nil {
			if timedOut.Load() {
				err = os.ErrDeadlineExceeded
			}
			onHandshakeFailure(timedOut.Load() || reqCtx.Err() == nil)
			_ = pipeInReader.CloseWithError(err)
			conn.Setup(nil, err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			statusErr := E.New("xhttp: unexpected status: ", resp.Status)
			onHandshakeFailure(true)
			_ = pipeInReader.CloseWithError(statusErr)
			conn.Setup(nil, statusErr)
			return
		}
		conn.Setup(resp.Body, nil)
	}()
	return outConn, nil
}

func (c *Client) dialSplit(ctx context.Context, splitMode string, probing bool) (net.Conn, error) {
	sessionID := generateSessionID()
	scCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	handshakeTimeout := C.TCPTimeout
	if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
		handshakeTimeout = time.Until(deadline)
	}

	maxPostBytes := samplePositive(c.cfg.maxEachPostBytes, defaultScMaxEachPostBytes)
	chunkCap := maxPostBytes
	if c.cfg.uplinkChunkSize > 0 && c.cfg.uplinkChunkSize < chunkCap {
		chunkCap = c.cfg.uplinkChunkSize
	}
	chunkCap = c.effectiveChunkCap(chunkCap)
	maxBufferedPosts := samplePositive(c.cfg.maxBufferedPosts, defaultScMaxBufferedPosts)
	maxConcurrency := defaultScMaxConcurrentPosts
	if c.cfg.minPostsIntervalMs.From > 0 || c.cfg.minPostsIntervalMs.To > 0 {
		maxConcurrency = 1
	} else if !c.cfg.maxConcurrentPosts.IsZero() && c.cfg.maxConcurrentPosts.From > 0 {
		maxConcurrency = samplePositive(c.cfg.maxConcurrentPosts, defaultScMaxConcurrentPosts)
	}
	if maxConcurrency > maxBufferedPosts {
		maxConcurrency = maxBufferedPosts
	}
	if maxConcurrency < 1 {
		maxConcurrency = 1
	}
	maxBufferedBytes := maxBufferedPosts * maxPostBytes
	if splitMode == modeStreamUp {
		maxBufferedBytes = defaultStreamBufferBytes
	}

	sc := &splitClientConn{
		client:           c,
		sessionID:        sessionID,
		ctx:              scCtx,
		cancel:           cancel,
		dlFirstReady:     make(chan struct{}),
		dlHost:           randomChoice(c.dlHosts),
		upHost:           randomChoice(c.hosts),
		maxChunkBytes:    chunkCap,
		maxBufferedPosts: maxBufferedPosts,
		maxConcurrency:   maxConcurrency,
		maxBufferedBytes: maxBufferedBytes,
		upDone:           make(chan struct{}),
	}
	sc.upCond = sync.NewCond(&sc.upMu)
	if c.autoMode && splitMode != modePacketUp {
		sc.watchdog = newAutoBufferingWatchdog(c, probing, func() {
			_ = sc.Close()
		})
	}

	// Start resumable GET downlink stream.
	var dlTimedOut atomic.Bool
	dlTimer := time.AfterFunc(handshakeTimeout, func() {
		dlTimedOut.Store(true)
		cancel()
	})
	go sc.startInitialDownlink(dlTimer, &dlTimedOut)

	if splitMode == modeStreamUp {
		go sc.runStreamUpLoop()
	} else {
		go sc.runPacketUpLoop()
	}
	return sc, nil
}

func (c *Client) MultiplexEnabled() bool {
	return true
}

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.closeIdle.Store(!keep)
	c.uplinkPool.setKeepIdleConnections(keep)
	if c.downlinkPool != c.uplinkPool {
		c.downlinkPool.setKeepIdleConnections(keep)
	}
}

func (c *Client) CloseIdleConnections() {
	c.uplinkPool.closeIdleConnections()
	if c.downlinkPool != c.uplinkPool {
		c.downlinkPool.closeIdleConnections()
	}
}

func (c *Client) Close() error {
	c.uplinkPool.closeAll()
	if c.downlinkPool != c.uplinkPool {
		c.downlinkPool.closeAll()
	}
	return nil
}

type splitClientConn struct {
	client           *Client
	sessionID        string
	ctx              context.Context
	cancel           context.CancelFunc
	dlHost           string
	upHost           string
	maxChunkBytes    int
	maxBufferedPosts int
	maxConcurrency   int
	maxBufferedBytes int
	watchdog         *autoBufferingWatchdog

	dlFirstReady chan struct{}
	dlFirstOnce  sync.Once
	dlReadMu     sync.Mutex
	dlBodyMu     sync.Mutex
	dlResp       *http.Response
	dlBody       io.ReadCloser
	dlErr        error
	dlStreamEnd  bool
	dlSeq        uint64
	dlOffset     uint64

	upMu          sync.Mutex
	upCond        *sync.Cond
	upBuf         bytes.Buffer
	upInFlight    int
	upAckedBase   uint64
	upAcked       map[uint64]bool
	upWriteClosed bool
	upClosed      bool
	upErr         error
	upDone        chan struct{}
	closeOnce     sync.Once
}

func (c *splitClientConn) buildDownlinkRequest(seq uint64, offset uint64) *http.Request {
	req := c.client.cfg.buildRequest(c.client.dlURL, http.MethodGet, c.dlHost, c.client.headers, c.sessionID, nil, nil)
	req.Header.Set(headerDownlinkSeq, strconv.FormatUint(seq, 10))
	req.Header.Set(headerDownlinkOffset, strconv.FormatUint(offset, 10))
	return req.WithContext(c.ctx)
}

func (c *splitClientConn) startInitialDownlink(dlTimer *time.Timer, dlTimedOut *atomic.Bool) {
	defer c.dlFirstOnce.Do(func() { close(c.dlFirstReady) })
	defer dlTimer.Stop()
	err := c.reopenDownlink()
	if err == nil {
		return
	}
	if dlTimedOut.Load() {
		err = os.ErrDeadlineExceeded
	}
	c.dlBodyMu.Lock()
	if c.dlErr == nil {
		c.dlErr = err
	}
	c.dlBodyMu.Unlock()
}

func (c *splitClientConn) currentDownlink() (*http.Response, io.ReadCloser, error, bool) {
	c.dlBodyMu.Lock()
	defer c.dlBodyMu.Unlock()
	return c.dlResp, c.dlBody, c.dlErr, c.dlStreamEnd
}

func (c *splitClientConn) clearCurrentDownlink(markEnded bool) {
	c.dlBodyMu.Lock()
	body := c.dlBody
	c.dlBody = nil
	c.dlResp = nil
	if markEnded {
		c.dlStreamEnd = true
	}
	c.dlBodyMu.Unlock()
	if body != nil {
		_ = body.Close()
	}
}

func (c *Client) recordHTTPStatusRetry(resp *http.Response) bool {
	if resp.StatusCode == http.StatusTooManyRequests {
		ra, _ := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
		c.recordRateLimit(ra)
		return true
	}
	return isRetryableXHTTPStatus(resp.StatusCode)
}

func (c *splitClientConn) reopenDownlink() error {
	var lastErr error
	for attempt := 0; attempt < maxDownlinkResumeAttempts; attempt++ {
		waited, ok := c.client.waitRateLimitPace(c.ctx)
		if !ok || (!waited && !waitRetryBackoff(c.ctx, attempt)) {
			return net.ErrClosed
		}
		seq := c.dlSeq
		c.dlSeq++
		dlReq := c.buildDownlinkRequest(seq, c.dlOffset)
		resp, err := c.client.downlinkPool.roundTrip(dlReq)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			statusErr := E.New("xhttp downlink unexpected status: ", resp.Status)
			if c.client.recordHTTPStatusRetry(resp) {
				lastErr = statusErr
				continue
			}
			return statusErr
		}
		ended := resp.Header.Get(headerStreamEnd) == "1"
		c.dlBodyMu.Lock()
		if c.ctx.Err() != nil || c.dlErr != nil {
			c.dlBodyMu.Unlock()
			_ = resp.Body.Close()
			return net.ErrClosed
		}
		c.dlResp = resp
		c.dlBody = resp.Body
		if ended {
			c.dlStreamEnd = true
		}
		c.dlBodyMu.Unlock()
		return nil
	}
	return lastErr
}

func (c *splitClientConn) Read(b []byte) (int, error) {
	<-c.dlFirstReady
	c.dlReadMu.Lock()
	defer c.dlReadMu.Unlock()

	for {
		resp, body, dlErr, ended := c.currentDownlink()
		if body == nil {
			if ended {
				return 0, io.EOF
			}
			if dlErr != nil {
				return 0, baderror.WrapH2(dlErr)
			}
			if c.ctx.Err() != nil {
				return 0, net.ErrClosed
			}
			if err := c.reopenDownlink(); err != nil {
				return 0, baderror.WrapH2(err)
			}
			continue
		}

		n, err := body.Read(b)
		if n > 0 {
			if c.watchdog != nil {
				c.watchdog.onDownlinkRead(n)
			}
			c.dlOffset += uint64(n)
			if err != nil {
				endedByTrailer := err == io.EOF && resp != nil && resp.Trailer.Get(headerStreamEnd) == "1"
				c.clearCurrentDownlink(ended || endedByTrailer)
			}
			return n, nil
		}

		endedByTrailer := err == io.EOF && resp != nil && resp.Trailer.Get(headerStreamEnd) == "1"
		c.clearCurrentDownlink(ended || endedByTrailer)
		if ended || endedByTrailer {
			return 0, io.EOF
		}
		if _, _, dlErr, alreadyEnded := c.currentDownlink(); alreadyEnded {
			return 0, io.EOF
		} else if dlErr != nil {
			return 0, baderror.WrapH2(dlErr)
		}
		if c.ctx.Err() != nil {
			return 0, net.ErrClosed
		}
		if rErr := c.reopenDownlink(); rErr != nil {
			return 0, baderror.WrapH2(rErr)
		}
	}
}

func (c *splitClientConn) Write(b []byte) (int, error) {
	c.upMu.Lock()
	defer c.upMu.Unlock()
	for {
		if c.upErr != nil {
			return 0, baderror.WrapH2(c.upErr)
		}
		if c.upClosed || c.upWriteClosed {
			return 0, net.ErrClosed
		}
		if len(b) == 0 {
			return 0, nil
		}
		if c.upBuf.Len() < c.maxBufferedBytes || c.upBuf.Len() == 0 {
			_, _ = c.upBuf.Write(b)
			c.upCond.Broadcast()
			return len(b), nil
		}
		c.upCond.Wait()
	}
}

func (c *splitClientConn) CloseWrite() error {
	c.upMu.Lock()
	c.upWriteClosed = true
	c.upCond.Broadcast()
	c.upMu.Unlock()
	select {
	case <-c.upDone:
		c.upMu.Lock()
		err := c.upErr
		c.upMu.Unlock()
		if err != nil {
			return baderror.WrapH2(err)
		}
		return nil
	case <-c.ctx.Done():
		c.upMu.Lock()
		err := c.upErr
		c.upMu.Unlock()
		if err != nil {
			return baderror.WrapH2(err)
		}
		return net.ErrClosed
	}
}

func (c *splitClientConn) closeDownlinkWithError(err error, abortIfEnded bool) {
	c.dlBodyMu.Lock()
	if !abortIfEnded && c.dlStreamEnd {
		c.dlBodyMu.Unlock()
		return
	}
	if c.dlErr == nil {
		c.dlErr = err
	}
	body := c.dlBody
	c.dlBody = nil
	c.dlResp = nil
	c.dlBodyMu.Unlock()
	c.cancel()
	if body != nil {
		_ = body.Close()
	}
}

func (c *splitClientConn) Close() error {
	c.closeOnce.Do(func() {
		if c.watchdog != nil {
			c.watchdog.onClose()
		}
		c.upMu.Lock()
		c.upClosed = true
		c.upWriteClosed = true
		c.upCond.Broadcast()
		c.upMu.Unlock()
		c.closeDownlinkWithError(net.ErrClosed, true)
	})
	return nil
}

func (c *splitClientConn) isUpClosed() bool {
	c.upMu.Lock()
	closed := c.upClosed
	c.upMu.Unlock()
	return closed
}

func (c *splitClientConn) failUplink(err error) {
	c.upMu.Lock()
	if c.upErr == nil {
		c.upErr = err
	}
	c.upClosed = true
	c.upCond.Broadcast()
	c.upMu.Unlock()
	// Abort active downlink GET immediately when uplink fails fatally so Read() does not hang.
	c.closeDownlinkWithError(err, false)
}

func (c *splitClientConn) minAdaptiveFloor() int {
	if c.client.cfg.uplinkDataPlacement != placementBody {
		return minAdaptiveNonBodyChunkBytes
	}
	return minAdaptiveChunkBytes
}

func (c *splitClientConn) finishPacketChunk(seqCopy uint64, err error) {
	c.finishPacketChunkRange(seqCopy, seqCopy+1, err)
}

func (c *splitClientConn) finishPacketChunkRange(startSeq uint64, endSeqExclusive uint64, err error) {
	c.upMu.Lock()
	c.upInFlight--
	if err != nil {
		if c.upErr == nil {
			c.upErr = err
		}
		c.upClosed = true
	} else {
		if c.upAcked == nil {
			c.upAcked = make(map[uint64]bool)
		}
		for s := startSeq; s < endSeqExclusive; s++ {
			c.upAcked[s] = true
		}
		for c.upAcked[c.upAckedBase] {
			delete(c.upAcked, c.upAckedBase)
			c.upAckedBase++
		}
	}
	c.upCond.Broadcast()
	c.upMu.Unlock()
	if err != nil {
		c.closeDownlinkWithError(err, false)
	}
}

func (c *splitClientConn) waitPacketWorkersDone() {
	c.upMu.Lock()
	for c.upInFlight > 0 {
		c.upCond.Wait()
	}
	c.upMu.Unlock()
}

func (c *splitClientConn) waitPostInterval(interval time.Duration, lastPost *time.Time) bool {
	if interval > 0 && !lastPost.IsZero() {
		wait := time.Until(lastPost.Add(interval))
		if wait > 0 {
			return waitDurationContext(c.ctx, wait)
		}
	}
	return c.ctx.Err() == nil
}

// sendPacketChunkAdaptive transmits chunk sequentially from startSeq, re-slicing
// in place on HTTP 413/414/431 responses without advancing or breaking seq order.
func (c *splitClientConn) sendPacketChunkAdaptive(startSeq uint64, chunk []byte, eof bool, baseInterval time.Duration, lastPost *time.Time) (uint64, error) {
	minFloor := c.minAdaptiveFloor()
	if len(chunk) == 0 {
		interval := c.client.effectivePostInterval(baseInterval)
		if !c.waitPostInterval(interval, lastPost) {
			return startSeq, net.ErrClosed
		}
		err := c.sendPacketChunk(startSeq, nil, eof)
		if interval > 0 || c.maxConcurrency == 1 {
			*lastPost = time.Now()
		}
		if err != nil {
			return startSeq, err
		}
		return startSeq + 1, nil
	}

	offset := 0
	seq := startSeq
	for offset < len(chunk) {
		capBytes := c.client.effectiveChunkCap(c.maxChunkBytes)
		end := offset + capBytes
		if end > len(chunk) {
			end = len(chunk)
		}
		interval := c.client.effectivePostInterval(baseInterval)
		if !c.waitPostInterval(interval, lastPost) {
			return seq, net.ErrClosed
		}
		part := chunk[offset:end]
		partEOF := eof && end == len(chunk)
		err := c.sendPacketChunk(seq, part, partEOF)
		if interval > 0 || c.maxConcurrency == 1 {
			*lastPost = time.Now()
		}
		if errors.Is(err, errChunkTooLarge) {
			if c.client.effectiveChunkCap(c.maxChunkBytes) < len(part) {
				continue
			}
			return seq, err
		}
		if err != nil {
			return seq, err
		}
		c.client.recordProbedChunkSize(len(part), minFloor)
		offset = end
		seq++
	}
	return seq, nil
}

func (c *splitClientConn) runPacketUpLoop() {
	defer close(c.upDone)
	defer c.waitPacketWorkersDone()

	var seq uint64
	var lastPost time.Time
	minFloor := c.minAdaptiveFloor()
	for {
		baseInterval := time.Duration(samplePaddingLen(c.client.cfg.minPostsIntervalMs)) * time.Millisecond
		postInterval := c.client.effectivePostInterval(baseInterval)
		effConcurrency := c.maxConcurrency
		if postInterval > 0 || c.client.isRateThrottled() {
			effConcurrency = 1
		}

		c.upMu.Lock()
		for !c.upClosed && c.ctx.Err() == nil &&
			((c.upBuf.Len() == 0 && !c.upWriteClosed) ||
				c.upInFlight >= effConcurrency ||
				seq-c.upAckedBase >= uint64(c.maxBufferedPosts)) {
			c.upCond.Wait()
		}
		if c.upClosed || c.ctx.Err() != nil {
			c.upMu.Unlock()
			return
		}
		chunkLen := c.upBuf.Len()
		if chunkLen == 0 && c.upWriteClosed {
			c.upInFlight++
			c.upMu.Unlock()
			nextSeq, err := c.sendPacketChunkAdaptive(seq, nil, true, baseInterval, &lastPost)
			c.finishPacketChunkRange(seq, nextSeq, err)
			return
		}
		chunkCap := c.client.effectiveChunkCap(c.maxChunkBytes)
		if chunkLen > chunkCap {
			chunkLen = chunkCap
		}
		chunk := make([]byte, chunkLen)
		_, _ = c.upBuf.Read(chunk)
		eof := c.upWriteClosed && c.upBuf.Len() == 0
		c.upInFlight++
		c.upCond.Broadcast()
		c.upMu.Unlock()

		serialize := effConcurrency == 1 || c.client.shouldProbeChunkSize(len(chunk), minFloor)
		if serialize {
			nextSeq, err := c.sendPacketChunkAdaptive(seq, chunk, eof, baseInterval, &lastPost)
			c.finishPacketChunkRange(seq, nextSeq, err)
			if err != nil {
				return
			}
			seq = nextSeq
		} else {
			seqCopy := seq
			chunkLenCopy := len(chunk)
			go func() {
				err := c.sendPacketChunk(seqCopy, chunk, eof)
				if err == nil {
					c.client.recordProbedChunkSize(chunkLenCopy, minFloor)
				}
				c.finishPacketChunk(seqCopy, err)
			}()
			seq++
		}
		if eof {
			return
		}
	}
}

func (c *splitClientConn) sendPacketChunk(seq uint64, chunk []byte, eof bool) error {
	var lastErr error
	for attempt := 0; attempt < maxUplinkChunkAttempts; attempt++ {
		waited, ok := c.client.waitRateLimitPace(c.ctx)
		if !ok || (!waited && !waitRetryBackoff(c.ctx, attempt)) {
			return net.ErrClosed
		}
		var getBody func() (io.ReadCloser, error)
		var bodyReader io.ReadCloser
		var nonBody []byte
		var contentLen int64
		if c.client.cfg.uplinkDataPlacement == placementBody && len(chunk) > 0 {
			contentLen = int64(len(chunk))
			getBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(chunk)), nil
			}
			bodyReader, _ = getBody()
		} else {
			if c.client.cfg.uplinkDataPlacement != placementBody {
				nonBody = chunk
			}
			bodyReader = nil
		}
		seqCopy := seq
		req := c.client.cfg.buildRequest(c.client.baseURL, http.MethodPost, c.upHost, c.client.headers, c.sessionID, &seqCopy, nonBody)
		req.Body = bodyReader
		req.GetBody = getBody
		req.ContentLength = contentLen
		if eof {
			req.Header.Set("X-Stream-End", "1")
		}
		req = req.WithContext(c.ctx)
		resp, err := c.client.uplinkPool.roundTrip(req)
		if err != nil {
			if c.ctx.Err() != nil {
				return net.ErrClosed
			}
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			c.client.recordPostSuccess()
			return nil
		}
		statusErr := E.New("xhttp uplink unexpected status: ", resp.Status)
		if isAdaptiveChunkTooLargeStatus(resp.StatusCode) {
			if c.client.shrinkChunkCap(len(chunk), c.minAdaptiveFloor()) {
				return fmt.Errorf("%w: %s", errChunkTooLarge, resp.Status)
			}
			return statusErr
		}
		if c.client.recordHTTPStatusRetry(resp) {
			lastErr = statusErr
			continue
		}
		return statusErr
	}
	return lastErr
}

func (c *splitClientConn) runStreamUpLoop() {
	defer close(c.upDone)
	var seq uint64
	for {
		c.upMu.Lock()
		for c.upBuf.Len() == 0 && !c.upWriteClosed && !c.upClosed {
			c.upCond.Wait()
		}
		if c.upClosed {
			c.upMu.Unlock()
			return
		}
		emptyEOF := c.upWriteClosed && c.upBuf.Len() == 0
		sendingFinal := c.upWriteClosed
		c.upMu.Unlock()

		seqCopy := seq
		req := c.client.cfg.buildRequest(c.client.baseURL, http.MethodPost, c.upHost, c.client.headers, c.sessionID, &seqCopy, nil)
		if !c.client.noGRPCHeader && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/grpc")
		}
		if sendingFinal {
			req.Header.Set("X-Stream-End", "1")
		}

		var reader *streamUpBodyReader
		if emptyEOF {
			req.Body = nil
			req.ContentLength = 0
		} else {
			rotateAfter := time.Duration(samplePaddingLen(c.client.cfg.streamUpServerSecs)) * time.Second
			if rotateAfter <= 0 {
				rotateAfter = c.client.effectiveStreamUpRotatePeriod()
			}
			reader = &streamUpBodyReader{
				conn:      c,
				hasMaxAge: rotateAfter > 0,
				rotateAt:  time.Now().Add(rotateAfter),
			}
			req.Body = reader
			req.ContentLength = -1
		}
		req = req.WithContext(c.ctx)

		triggerAuto := func() {
			if c.client.autoMode && !c.isUpClosed() && c.ctx.Err() == nil {
				if c.watchdog != nil {
					c.watchdog.triggerFallback()
				} else {
					c.client.triggerAutoFallback()
				}
			}
		}

		resp, err := c.client.uplinkPool.roundTrip(req)
		if err != nil {
			triggerAuto()
			c.failUplink(err)
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			triggerAuto()
			c.failUplink(E.New("xhttp stream-up unexpected status: ", resp.Status))
			return
		}
		seq++
		if emptyEOF || (sendingFinal && reader != nil && reader.endedEOF) {
			return
		}
	}
}

type streamUpBodyReader struct {
	conn      *splitClientConn
	hasMaxAge bool
	rotateAt  time.Time
	endedEOF  bool
}

func (r *streamUpBodyReader) Read(p []byte) (int, error) {
	var rotateTimer *time.Timer
	if r.hasMaxAge {
		rem := time.Until(r.rotateAt)
		if rem <= 0 {
			return 0, io.EOF
		}
		rotateTimer = time.AfterFunc(rem, func() {
			r.conn.upMu.Lock()
			r.conn.upCond.Broadcast()
			r.conn.upMu.Unlock()
		})
		defer rotateTimer.Stop()
	}
	r.conn.upMu.Lock()
	defer r.conn.upMu.Unlock()
	for r.conn.upBuf.Len() == 0 {
		if r.conn.upClosed {
			r.endedEOF = true
			return 0, net.ErrClosed
		}
		if r.conn.upWriteClosed {
			r.endedEOF = true
			return 0, io.EOF
		}
		if r.hasMaxAge && !time.Now().Before(r.rotateAt) {
			return 0, io.EOF
		}
		r.conn.upCond.Wait()
	}
	n, _ := r.conn.upBuf.Read(p)
	if n > 0 && r.conn.watchdog != nil {
		r.conn.watchdog.onUplinkSent(n)
	}
	r.conn.upCond.Broadcast()
	return n, nil
}

func (r *streamUpBodyReader) Close() error {
	return nil
}

func (c *splitClientConn) LocalAddr() net.Addr                { return M.Socksaddr{} }
func (c *splitClientConn) RemoteAddr() net.Addr               { return M.Socksaddr{} }
func (c *splitClientConn) SetDeadline(t time.Time) error      { return nil }
func (c *splitClientConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *splitClientConn) SetWriteDeadline(t time.Time) error { return nil }
