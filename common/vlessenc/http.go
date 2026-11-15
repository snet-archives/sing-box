package vlessenc

import (
	std_bufio "bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/browserhdr"
)

const (
	webSocketGUID          = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	httpAuthBucketSeconds  = 30
	httpAuthMaxSkewBuckets = 4
	httpReplayMaxAge       = 4 * time.Minute
	maxHTTPHeaderBytes     = 16384
)

// HandshakeFallbackError carries the buffered connection (with any already-read bytes replayed)
// when an unauthenticated or non-upgrade request arrives under XorHTTP.
type HandshakeFallbackError struct {
	Conn  net.Conn
	Cause error
}

func (e *HandshakeFallbackError) Error() string {
	return e.Cause.Error()
}

func (e *HandshakeFallbackError) Unwrap() error {
	return e.Cause
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

func newPrefixConn(prefix []byte, conn net.Conn) net.Conn {
	if len(prefix) == 0 {
		return conn
	}
	return &prefixConn{
		Conn:   conn,
		prefix: append([]byte(nil), prefix...),
	}
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *prefixConn) Upstream() any {
	return c.Conn
}

type recordingReader struct {
	r     io.Reader
	buf   bytes.Buffer
	limit int
}

func (r *recordingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		if r.buf.Len()+n > r.limit {
			return 0, ErrInvalidHandshake
		}
		r.buf.Write(p[:n])
	}
	return n, err
}

func wrapBufferedConn(conn net.Conn, br *std_bufio.Reader) (net.Conn, error) {
	buffered := br.Buffered()
	if buffered == 0 {
		return conn, nil
	}
	prefix := make([]byte, buffered)
	if _, err := io.ReadFull(br, prefix); err != nil {
		return nil, err
	}
	return newPrefixConn(prefix, conn), nil
}

func normalizeHTTPPath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func computeHTTPAuthTag(authKey [32]byte, bucket int64, method, path string, salt []byte) []byte {
	mac := hmac.New(sha256.New, authKey[:])
	_, _ = mac.Write([]byte("vlessenc-v1-http-upgrade"))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(bucket))
	_, _ = mac.Write(buf[:])
	_, _ = mac.Write(salt)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(method)))
	_, _ = mac.Write(buf[:2])
	_, _ = mac.Write([]byte(method))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(path)))
	_, _ = mac.Write(buf[:2])
	_, _ = mac.Write([]byte(path))
	return mac.Sum(nil)[:8]
}

func buildWebSocketAuthKey(authKey [32]byte, method, path string, now time.Time) (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(rand.Reader, raw[:8]); err != nil {
		return "", err
	}
	bucket := now.Unix() / httpAuthBucketSeconds
	tag := computeHTTPAuthTag(authKey, bucket, method, path, raw[:8])
	copy(raw[8:], tag)
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

func verifyWebSocketAuthKey(authKey [32]byte, method, path, encoded string, now time.Time, replay *replayCache) bool {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != 16 {
		return false
	}
	salt := raw[:8]
	gotTag := raw[8:]
	curBucket := now.Unix() / httpAuthBucketSeconds
	matched := false
	for delta := -httpAuthMaxSkewBuckets; delta <= httpAuthMaxSkewBuckets; delta++ {
		expected := computeHTTPAuthTag(authKey, curBucket+int64(delta), method, path, salt)
		if hmac.Equal(gotTag, expected) {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	sum := sha256.Sum256(raw)
	var replayID [16]byte
	copy(replayID[:], sum[:16])
	return replay.CheckAndAdd(replayID, now.Add(httpReplayMaxAge), now)
}

func computeWebSocketAccept(encodedKey string) string {
	h := sha1.New()
	_, _ = h.Write([]byte(encodedKey + webSocketGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func hasHeaderToken(values []string, target string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), target) {
				return true
			}
		}
	}
	return false
}

func hasHeaderKey(headers http.Header, name string) bool {
	for k, values := range headers {
		if strings.EqualFold(k, name) && len(values) > 0 {
			return true
		}
	}
	return false
}

func deleteHeaderFold(headers http.Header, name string) {
	for k := range headers {
		if strings.EqualFold(k, name) {
			delete(headers, k)
		}
	}
}

func buildHTTPUpgradeHeaders(userHeaders http.Header, wsKey string) http.Header {
	headers := make(http.Header)
	for key, values := range userHeaders {
		headers[key] = append([]string(nil), values...)
	}
	browserhdr.TryDefaultHeadersWith(headers, "ws")
	// Over plain HTTP (ws://), browsers omit TLS-only Fetch Metadata and Client Hints
	// unless explicitly supplied by the caller. Delete case-insensitively because
	// browserhdr may populate non-canonical Header map keys (e.g. "Sec-CH-UA").
	for _, headerName := range []string{
		"Sec-CH-UA",
		"Sec-CH-UA-Mobile",
		"Sec-CH-UA-Platform",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-Dest",
	} {
		if !hasHeaderKey(userHeaders, headerName) {
			deleteHeaderFold(headers, headerName)
		}
	}
	headers.Set("Connection", "Upgrade")
	headers.Set("Upgrade", "websocket")
	headers.Set("Sec-WebSocket-Version", "13")
	headers.Set("Sec-WebSocket-Key", wsKey)
	return headers
}

func defaultHTTPHost(configured string, conn net.Conn) string {
	if configured != "" {
		return configured
	}
	if addr := conn.RemoteAddr(); addr != nil {
		if hostStr := addr.String(); hostStr != "" {
			return hostStr
		}
	}
	return "www.example.com"
}

func (c *Client) clientHTTPUpgrade(conn net.Conn) (net.Conn, error) {
	path := normalizeHTTPPath(c.httpPath)
	host := defaultHTTPHost(c.httpHost, conn)
	wsKey, err := buildWebSocketAuthKey(c.httpAuthKey, http.MethodGet, path, c.now())
	if err != nil {
		return nil, err
	}
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Scheme: "http", Host: host, Path: path},
		Host:       host,
		Header:     buildHTTPUpgradeHeaders(c.httpHeaders, wsKey),
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if err = req.Write(conn); err != nil {
		return nil, err
	}

	br := std_bufio.NewReaderSize(conn, maxHTTPHeaderBytes)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!hasHeaderToken(resp.Header.Values("Connection"), "upgrade") ||
		!strings.EqualFold(strings.TrimSpace(resp.Header.Get("Upgrade")), "websocket") ||
		resp.Header.Get("Sec-WebSocket-Accept") != computeWebSocketAccept(wsKey) {
		return nil, ErrInvalidHandshake
	}
	wrapped, err := wrapBufferedConn(conn, br)
	if err != nil {
		return nil, err
	}
	return newWSFrameConn(wrapped, true), nil
}

func (s *Server) serverHTTPUpgrade(ctx context.Context, conn net.Conn) (net.Conn, error) {
	rec := &recordingReader{r: conn, limit: maxHTTPHeaderBytes}
	br := std_bufio.NewReaderSize(rec, 4096)
	req, err := http.ReadRequest(br)
	if err == nil {
		_ = req.Body.Close()
	}

	fallback := func() error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if rec.buf.Len() == 0 {
			if err != nil {
				return err
			}
			return ErrInvalidHandshake
		}
		return &HandshakeFallbackError{
			Conn:  newPrefixConn(rec.buf.Bytes(), conn),
			Cause: ErrInvalidHandshake,
		}
	}

	if err != nil {
		return nil, fallback()
	}
	if req.Method != http.MethodGet || req.ContentLength > 0 || len(req.TransferEncoding) > 0 {
		return nil, fallback()
	}
	if s.httpHost != "" && !strings.EqualFold(req.Host, s.httpHost) {
		return nil, fallback()
	}
	if s.httpPath != "" && req.URL.Path != s.httpPath {
		return nil, fallback()
	}
	if !hasHeaderToken(req.Header.Values("Connection"), "upgrade") ||
		!strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket") ||
		strings.TrimSpace(req.Header.Get("Sec-WebSocket-Version")) != "13" {
		return nil, fallback()
	}
	wsKey := strings.TrimSpace(req.Header.Get("Sec-WebSocket-Key"))
	if !verifyWebSocketAuthKey(s.httpAuthKey, req.Method, req.URL.Path, wsKey, s.now(), s.httpReplay) {
		return nil, fallback()
	}

	respHeader := fmt.Sprintf(
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		computeWebSocketAccept(wsKey),
	)
	if _, err = io.WriteString(conn, respHeader); err != nil {
		return nil, err
	}
	wrapped, err := wrapBufferedConn(conn, br)
	if err != nil {
		return nil, err
	}
	return newWSFrameConn(wrapped, false), nil
}

const (
	wsFinBit         = 0x80
	wsMaskBit        = 0x80
	wsOpcodeBinary   = 0x02
	wsOpcodeClose    = 0x08
	wsOpcodePing     = 0x09
	wsOpcodePong     = 0x0a
	wsMaxWriteChunk  = 65535
	wsMaxReadPayload = 16 << 20
)

// wsFrameConn wraps post-101 XorHTTP traffic in valid RFC 6455 binary frames
// (FIN=1, opcode=2; client->server MASK=1, server->client MASK=0) so middleboxes
// inspecting HTTP Upgrade + WebSocket streams see standards-compliant framing.
type wsFrameConn struct {
	net.Conn
	isClient bool

	readMu      sync.Mutex
	readRem     uint64
	readMasked  bool
	readMask    [4]byte
	readMaskOff int
	readEOF     bool

	writeMu  sync.Mutex
	writeBuf []byte
}

func newWSFrameConn(conn net.Conn, isClient bool) net.Conn {
	return &wsFrameConn{
		Conn:     conn,
		isClient: isClient,
	}
}

func (c *wsFrameConn) Upstream() any {
	return c.Conn
}

func (c *wsFrameConn) CloseWrite() error {
	return closeWriteOrClose(c.Conn)
}

func (c *wsFrameConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.readRem == 0 {
		if c.readEOF {
			return 0, io.EOF
		}
		var hdr [2]byte
		if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
			return 0, err
		}
		if hdr[0]&0x70 != 0 {
			return 0, ErrInvalidHandshake
		}
		fin := hdr[0]&wsFinBit != 0
		opcode := hdr[0] & 0x0f
		masked := hdr[1]&wsMaskBit != 0
		if c.isClient && masked {
			return 0, ErrInvalidHandshake
		}
		if !c.isClient && !masked {
			return 0, ErrInvalidHandshake
		}

		var payloadLen uint64
		switch length7 := hdr[1] & 0x7f; length7 {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(c.Conn, ext[:]); err != nil {
				return 0, err
			}
			payloadLen = uint64(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(c.Conn, ext[:]); err != nil {
				return 0, err
			}
			if ext[0]&0x80 != 0 {
				return 0, ErrInvalidHandshake
			}
			payloadLen = binary.BigEndian.Uint64(ext[:])
		default:
			payloadLen = uint64(length7)
		}
		if payloadLen > wsMaxReadPayload {
			return 0, ErrInvalidHandshake
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(c.Conn, maskKey[:]); err != nil {
				return 0, err
			}
		}

		switch opcode {
		case 0x00, 0x01, wsOpcodeBinary:
			if payloadLen == 0 {
				continue
			}
			c.readRem = payloadLen
			c.readMasked = masked
			c.readMask = maskKey
			c.readMaskOff = 0
		case wsOpcodeClose, wsOpcodePing, wsOpcodePong:
			if !fin || payloadLen > 125 {
				return 0, ErrInvalidHandshake
			}
			if payloadLen > 0 {
				var ctrlBuf [125]byte
				if _, err := io.ReadFull(c.Conn, ctrlBuf[:payloadLen]); err != nil {
					return 0, err
				}
			}
			if opcode == wsOpcodeClose {
				c.readEOF = true
				return 0, io.EOF
			}
		default:
			return 0, ErrInvalidHandshake
		}
	}

	toRead := len(p)
	if uint64(toRead) > c.readRem {
		toRead = int(c.readRem)
	}
	n, err := c.Conn.Read(p[:toRead])
	if n > 0 {
		if c.readMasked {
			maskOff := c.readMaskOff
			for i := 0; i < n; i++ {
				p[i] ^= c.readMask[(maskOff+i)&3]
			}
			c.readMaskOff = (maskOff + n) & 3
		}
		c.readRem -= uint64(n)
	}
	return n, err
}

func (c *wsFrameConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	written := 0
	for len(p) > 0 {
		chunkLen := len(p)
		if chunkLen > wsMaxWriteChunk {
			chunkLen = wsMaxWriteChunk
		}
		chunk := p[:chunkLen]

		hdrLen := 2
		if chunkLen >= 126 {
			hdrLen = 4
		}
		if c.isClient {
			hdrLen += 4
		}
		totalLen := hdrLen + chunkLen
		if cap(c.writeBuf) < totalLen {
			c.writeBuf = make([]byte, totalLen)
		} else {
			c.writeBuf = c.writeBuf[:totalLen]
		}

		c.writeBuf[0] = wsFinBit | wsOpcodeBinary
		lengthByte := byte(chunkLen)
		if chunkLen >= 126 {
			lengthByte = 126
			binary.BigEndian.PutUint16(c.writeBuf[2:4], uint16(chunkLen))
		}
		if c.isClient {
			c.writeBuf[1] = wsMaskBit | lengthByte
			maskSlice := c.writeBuf[hdrLen-4 : hdrLen]
			if _, err := io.ReadFull(rand.Reader, maskSlice); err != nil {
				return written, err
			}
			dst := c.writeBuf[hdrLen:]
			m0, m1, m2, m3 := maskSlice[0], maskSlice[1], maskSlice[2], maskSlice[3]
			for i := 0; i < chunkLen; i++ {
				var mk byte
				switch i & 3 {
				case 0:
					mk = m0
				case 1:
					mk = m1
				case 2:
					mk = m2
				default:
					mk = m3
				}
				dst[i] = chunk[i] ^ mk
			}
		} else {
			c.writeBuf[1] = lengthByte
			copy(c.writeBuf[hdrLen:], chunk)
		}

		out := c.writeBuf
		for len(out) > 0 {
			n, err := c.Conn.Write(out)
			out = out[n:]
			if err != nil {
				return written, err
			}
		}
		written += chunkLen
		p = p[chunkLen:]
	}
	return written, nil
}
