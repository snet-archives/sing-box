package v2rayxhttp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-mux"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	modeAuto      = "auto"
	modePacketUp  = "packet-up"
	modeStreamUp  = "stream-up"
	modeStreamOne = "stream-one"

	placementPath          = "path"
	placementQuery         = "query"
	placementHeader        = "header"
	placementCookie        = "cookie"
	placementQueryInHeader = "query_in_header"
	placementBody          = "body"

	querySessionKey      = "x_sess"
	querySeqKey          = "x_seq"
	queryPaddingKey      = "x_padding"
	queryDataKey         = "x_data"
	headerSessionKey     = "X-Session-Id"
	headerSeqKey         = "X-Seq"
	headerPaddingKey     = "X-Padding"
	headerDataKey        = "X-Data"
	headerDownlinkSeq    = "X-Downlink-Seq"
	headerDownlinkOffset = "X-Downlink-Offset"
	headerStreamEnd      = "X-Stream-End"
	cookieSessionKey     = "x_sess"
	cookieSeqKey         = "x_seq"
	cookiePaddingKey     = "x_padding"
	cookieDataKey        = "x_data"

	defaultScMaxEachPostBytes   = 1000000
	defaultScMaxBufferedPosts   = 30
	defaultScMaxConcurrentPosts = 4
	defaultNonBodyChunkSize     = 4096
)

const paddingAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

type placementConfig struct {
	basePath            string
	sessionPlacement    string
	seqPlacement        string
	xPaddingPlacement   string
	uplinkDataPlacement string
	uplinkChunkSize     int
	xPaddingBytes       mux.XmuxRange
	maxEachPostBytes    mux.XmuxRange
	minPostsIntervalMs  mux.XmuxRange
	maxBufferedPosts    mux.XmuxRange
	maxConcurrentPosts  mux.XmuxRange
	streamUpServerSecs  mux.XmuxRange
	downlinkServerSecs  mux.XmuxRange
}

func normalizeBasePath(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" || trimmed == "/" {
		return "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	trimmed = strings.TrimRight(trimmed, "/")
	if trimmed == "" {
		return "/"
	}
	return trimmed
}

func validateOneOf(field, val string, allowed ...string) (string, error) {
	if val == "" {
		return allowed[0], nil
	}
	for _, a := range allowed {
		if val == a {
			return val, nil
		}
	}
	return "", E.New("xhttp: invalid ", field, ": ", val)
}

func parsePlacementConfig(options option.V2RayXHTTPOptions) (placementConfig, error) {
	var cfg placementConfig
	cfg.basePath = normalizeBasePath(options.Path)

	var err error
	if _, err = validateOneOf("mode", options.Mode, modeAuto, modePacketUp, modeStreamUp, modeStreamOne); err != nil {
		return cfg, err
	}
	if cfg.sessionPlacement, err = validateOneOf("session_placement", options.SessionPlacement, placementPath, placementQuery, placementHeader, placementCookie); err != nil {
		return cfg, err
	}
	if cfg.seqPlacement, err = validateOneOf("seq_placement", options.SeqPlacement, placementPath, placementQuery, placementHeader, placementCookie); err != nil {
		return cfg, err
	}
	if cfg.xPaddingPlacement, err = validateOneOf("x_padding_placement", options.XPaddingPlacement, placementHeader, placementQuery, placementCookie, placementQueryInHeader); err != nil {
		return cfg, err
	}
	if cfg.uplinkDataPlacement, err = validateOneOf("uplink_data_placement", options.UplinkDataPlacement, placementBody, placementHeader, placementCookie, placementQuery); err != nil {
		return cfg, err
	}

	ranges := []struct {
		name string
		rng  mux.XmuxRange
	}{
		{"x_padding_bytes", mux.XmuxRange(options.XPaddingBytes)},
		{"sc_max_each_post_bytes", mux.XmuxRange(options.ScMaxEachPostBytes)},
		{"sc_min_posts_interval_ms", mux.XmuxRange(options.ScMinPostsIntervalMs)},
		{"sc_max_buffered_posts", mux.XmuxRange(options.ScMaxBufferedPosts)},
		{"sc_max_concurrent_posts", mux.XmuxRange(options.ScMaxConcurrentPosts)},
		{"sc_stream_up_server_secs", mux.XmuxRange(options.ScStreamUpServerSecs)},
		{"sc_downlink_server_secs", mux.XmuxRange(options.ScDownlinkServerSecs)},
	}
	for _, item := range ranges {
		if err = item.rng.Validate(item.name); err != nil {
			return cfg, err
		}
	}
	cfg.xPaddingBytes = mux.XmuxRange(options.XPaddingBytes)
	cfg.maxEachPostBytes = mux.XmuxRange(options.ScMaxEachPostBytes)
	cfg.minPostsIntervalMs = mux.XmuxRange(options.ScMinPostsIntervalMs)
	cfg.maxBufferedPosts = mux.XmuxRange(options.ScMaxBufferedPosts)
	cfg.maxConcurrentPosts = mux.XmuxRange(options.ScMaxConcurrentPosts)
	cfg.streamUpServerSecs = mux.XmuxRange(options.ScStreamUpServerSecs)
	cfg.downlinkServerSecs = mux.XmuxRange(options.ScDownlinkServerSecs)

	if options.UplinkChunkSize < 0 {
		return cfg, E.New("xhttp: negative uplink_chunk_size")
	}
	cfg.uplinkChunkSize = options.UplinkChunkSize
	if cfg.uplinkDataPlacement != placementBody && cfg.uplinkChunkSize == 0 {
		cfg.uplinkChunkSize = defaultNonBodyChunkSize
	}

	hasDownloadSplit := options.DownloadDialer != nil || options.DownloadTLS != nil || options.DownloadAddress != "" || options.DownloadPort != 0
	if options.Mode == modeStreamOne && hasDownloadSplit {
		return cfg, E.New("xhttp: stream-one mode cannot be combined with download separation")
	}
	if options.Xmux != nil {
		if err = options.Xmux.ToMux().Validate(); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

func generateSessionID() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}

func randomPaddingString(length int) string {
	if length <= 0 {
		return ""
	}
	buf := make([]byte, length)
	_, _ = rand.Read(buf)
	for i, b := range buf {
		buf[i] = paddingAlphabet[int(b)%len(paddingAlphabet)]
	}
	return string(buf)
}

func samplePaddingLen(rng mux.XmuxRange) int {
	if rng.IsZero() {
		return 0
	}
	return rng.Sample()
}

func samplePositive(rng mux.XmuxRange, fallback int) int {
	if rng.IsZero() {
		return fallback
	}
	v := rng.Sample()
	if v <= 0 {
		return fallback
	}
	return v
}

func randomChoice[T any](items []T) T {
	if len(items) == 1 {
		return items[0]
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(items))))
	if err != nil {
		return items[0]
	}
	return items[n.Int64()]
}

func (c placementConfig) buildRequest(baseURL url.URL, method, host string, baseHeaders http.Header, sessionID string, seq *uint64, nonBodyPayload []byte) *http.Request {
	reqURL := baseURL
	query := reqURL.Query()
	headers := baseHeaders.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	var pathSegments []string
	var cookies []*http.Cookie

	if sessionID != "" {
		switch c.sessionPlacement {
		case placementPath:
			pathSegments = append(pathSegments, sessionID)
		case placementQuery:
			query.Set(querySessionKey, sessionID)
		case placementHeader:
			headers.Set(headerSessionKey, sessionID)
		case placementCookie:
			cookies = append(cookies, &http.Cookie{Name: cookieSessionKey, Value: sessionID})
		}
	}

	if seq != nil {
		seqStr := strconv.FormatUint(*seq, 10)
		switch c.seqPlacement {
		case placementPath:
			pathSegments = append(pathSegments, seqStr)
		case placementQuery:
			query.Set(querySeqKey, seqStr)
		case placementHeader:
			headers.Set(headerSeqKey, seqStr)
		case placementCookie:
			cookies = append(cookies, &http.Cookie{Name: cookieSeqKey, Value: seqStr})
		}
	}

	if padLen := samplePaddingLen(c.xPaddingBytes); padLen > 0 {
		padStr := randomPaddingString(padLen)
		switch c.xPaddingPlacement {
		case placementHeader:
			headers.Set(headerPaddingKey, padStr)
		case placementQuery:
			query.Set(queryPaddingKey, padStr)
		case placementCookie:
			cookies = append(cookies, &http.Cookie{Name: cookiePaddingKey, Value: padStr})
		case placementQueryInHeader:
			refURL := url.URL{
				Scheme:   reqURL.Scheme,
				Host:     host,
				Path:     c.basePath,
				RawQuery: url.Values{queryPaddingKey: {padStr}}.Encode(),
			}
			headers.Set("Referer", refURL.String())
		}
	}

	if len(nonBodyPayload) > 0 {
		encoded := base64.RawURLEncoding.EncodeToString(nonBodyPayload)
		switch c.uplinkDataPlacement {
		case placementHeader:
			headers.Set(headerDataKey, encoded)
		case placementCookie:
			cookies = append(cookies, &http.Cookie{Name: cookieDataKey, Value: encoded})
		case placementQuery:
			query.Set(queryDataKey, encoded)
		}
	}

	if len(pathSegments) > 0 {
		prefix := c.basePath
		if prefix == "/" {
			reqURL.Path = "/" + strings.Join(pathSegments, "/")
		} else {
			reqURL.Path = prefix + "/" + strings.Join(pathSegments, "/")
		}
	}
	reqURL.RawQuery = query.Encode()

	req := &http.Request{
		Method: method,
		URL:    &reqURL,
		Header: headers,
		Host:   host,
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	return req
}

type decodedRequestMeta struct {
	sessionID      string
	seq            uint64
	hasSeq         bool
	nonBodyPayload []byte
}

func (c placementConfig) decodeRequest(r *http.Request) (decodedRequestMeta, bool, error) {
	reqPath := normalizeBasePath(r.URL.Path)
	var tail string
	if c.basePath == "/" {
		tail = strings.TrimPrefix(reqPath, "/")
	} else if reqPath == c.basePath {
		tail = ""
	} else if strings.HasPrefix(reqPath, c.basePath+"/") {
		tail = strings.TrimPrefix(reqPath, c.basePath+"/")
	} else {
		return decodedRequestMeta{}, false, nil
	}

	var segs []string
	if tail != "" {
		segs = strings.Split(tail, "/")
	}

	var meta decodedRequestMeta
	query := r.URL.Query()
	readCookie := func(name string) string {
		if ck, err := r.Cookie(name); err == nil {
			return ck.Value
		}
		return ""
	}

	switch c.sessionPlacement {
	case placementPath:
		if len(segs) > 0 {
			meta.sessionID = segs[0]
			segs = segs[1:]
		}
	case placementQuery:
		meta.sessionID = query.Get(querySessionKey)
	case placementHeader:
		meta.sessionID = r.Header.Get(headerSessionKey)
	case placementCookie:
		meta.sessionID = readCookie(cookieSessionKey)
	}

	var seqStr string
	switch c.seqPlacement {
	case placementPath:
		if len(segs) > 0 {
			seqStr = segs[0]
			segs = segs[1:]
		}
	case placementQuery:
		seqStr = query.Get(querySeqKey)
	case placementHeader:
		seqStr = r.Header.Get(headerSeqKey)
	case placementCookie:
		seqStr = readCookie(cookieSeqKey)
	}
	if len(segs) > 0 {
		return meta, false, nil
	}
	if seqStr != "" {
		v, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			return meta, true, E.Cause(err, "invalid seq ", seqStr)
		}
		meta.seq = v
		meta.hasSeq = true
	}

	var encodedData string
	switch c.uplinkDataPlacement {
	case placementHeader:
		encodedData = r.Header.Get(headerDataKey)
	case placementCookie:
		encodedData = readCookie(cookieDataKey)
	case placementQuery:
		encodedData = query.Get(queryDataKey)
	}
	if encodedData != "" {
		raw, err := base64.RawURLEncoding.DecodeString(encodedData)
		if err != nil {
			return meta, true, E.Cause(err, "invalid encoded uplink data")
		}
		meta.nonBodyPayload = raw
	}
	return meta, true, nil
}
