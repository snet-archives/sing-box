package vlessenc

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	protocolVersion byte = 0x01

	flagZeroRTT    byte = 1 << 0
	flagHasPadding byte = 1 << 1

	envelopeOverhead   = 16 + 2 // hdrNonce[16] || maskedBodyLen[2]
	x25519KeySize      = 32
	ticketHeaderSize   = 8  // expiryUnixNano
	ticketPSKSize      = 32 // mlkem-bound ticket secret
	ticketPlainSize    = ticketHeaderSize + ticketPSKSize
	ticketNonceSize    = 12
	maxHandshakeBody   = 4096
	minClientBodyBytes = 1 + 1 + x25519KeySize + 2
	minServerBodyBytes = 1 + 1 + 2 + sha256.Size
	maxReplayEntries   = 65536
)

var (
	// ErrInvalidHandshake is returned consistently on malformed, mismatched, or tampered handshakes.
	ErrInvalidHandshake = E.New("vlessenc: invalid handshake")
	// ErrReplayRejected is returned when a 0-RTT ClientHello nonce is replayed.
	ErrReplayRejected = E.New("vlessenc: replay rejected")
	// ErrInvalidRecord is returned when AEAD record length or payload authentication fails.
	ErrInvalidRecord = E.New("vlessenc: invalid record")
)

type sessionKeys struct {
	upKey      []byte
	downKey    []byte
	upIV       [12]byte
	downIV     [12]byte
	confirmKey []byte
	ticketPSK  [32]byte
}

func deriveSessionKeys(ikm []byte, hdrNonce [16]byte) (sessionKeys, error) {
	var out sessionKeys
	prk, err := hkdf.Extract(sha256.New, ikm, hdrNonce[:])
	if err != nil {
		return out, err
	}
	if out.upKey, err = hkdf.Expand(sha256.New, prk, "vlessenc-v1-c2s-key", 32); err != nil {
		return out, err
	}
	if out.downKey, err = hkdf.Expand(sha256.New, prk, "vlessenc-v1-s2c-key", 32); err != nil {
		return out, err
	}
	upIVSlice, err := hkdf.Expand(sha256.New, prk, "vlessenc-v1-c2s-iv", 12)
	if err != nil {
		return out, err
	}
	copy(out.upIV[:], upIVSlice)
	downIVSlice, err := hkdf.Expand(sha256.New, prk, "vlessenc-v1-s2c-iv", 12)
	if err != nil {
		return out, err
	}
	copy(out.downIV[:], downIVSlice)
	if out.confirmKey, err = hkdf.Expand(sha256.New, prk, "vlessenc-v1-confirm", 32); err != nil {
		return out, err
	}
	pskSlice, err := hkdf.Expand(sha256.New, prk, "vlessenc-v1-ticket-psk", 32)
	if err != nil {
		return out, err
	}
	copy(out.ticketPSK[:], pskSlice)
	return out, nil
}

func computeConfirmTag(confirmKey []byte, hdrNonce, srvNonce [16]byte, ticket []byte) []byte {
	mac := hmac.New(sha256.New, confirmKey)
	_, _ = mac.Write([]byte("vlessenc-v1-srv-confirm"))
	_, _ = mac.Write(hdrNonce[:])
	_, _ = mac.Write(srvNonce[:])
	_, _ = mac.Write(ticket)
	return mac.Sum(nil)
}

func sampleRandomPadding(minLen, maxLen int) []byte {
	span := maxLen - minLen + 1
	n := minLen
	if span > 1 {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
		if err == nil {
			n += int(v.Int64())
		}
	}
	pad := make([]byte, n)
	_, _ = io.ReadFull(rand.Reader, pad)
	return pad
}

func writeMaskedEnvelope(w io.Writer, nonce [16]byte, xorMode string, maskKey [32]byte, body []byte) error {
	if len(body) > maxHandshakeBody {
		return ErrInvalidHandshake
	}
	buf := make([]byte, envelopeOverhead+len(body))
	copy(buf[:16], nonce[:])
	binary.BigEndian.PutUint16(buf[16:18], uint16(len(body)))
	copy(buf[18:], body)
	if xorMode != XorNone {
		if err := applyXorStream(maskKey, nonce, buf[16:], buf[16:]); err != nil {
			return err
		}
	}
	_, err := w.Write(buf)
	return err
}

func readMaskedEnvelope(r io.Reader, xorMode string, maskKey [32]byte, minLen int) ([16]byte, []byte, error) {
	var hdr [envelopeOverhead]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return [16]byte{}, nil, err
	}
	var nonce [16]byte
	copy(nonce[:], hdr[:16])

	var lenBytes [2]byte
	if xorMode != XorNone {
		// Unmask length first with first 2 bytes of CTR stream, then unmask body with offset-shifted CTR stream.
		// Using one contiguous scratch slice keeps keystream alignment exact.
		probe := make([]byte, 2+maxHandshakeBody)
		copy(probe[:2], hdr[16:18])
		block, err := aes.NewCipher(maskKey[:])
		if err != nil {
			return [16]byte{}, nil, err
		}
		stream := cipher.NewCTR(block, nonce[:])
		stream.XORKeyStream(lenBytes[:], probe[:2])
		bodyLen := int(binary.BigEndian.Uint16(lenBytes[:]))
		if bodyLen < minLen || bodyLen > maxHandshakeBody {
			return [16]byte{}, nil, ErrInvalidHandshake
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(r, body); err != nil {
			return [16]byte{}, nil, err
		}
		stream.XORKeyStream(body, body)
		return nonce, body, nil
	}

	bodyLen := int(binary.BigEndian.Uint16(hdr[16:18]))
	if bodyLen < minLen || bodyLen > maxHandshakeBody {
		return [16]byte{}, nil, ErrInvalidHandshake
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return [16]byte{}, nil, err
	}
	return nonce, body, nil
}

func watchHandshakeContext(ctx context.Context, conn net.Conn) func() {
	if deadline, has := ctx.Deadline(); has {
		_ = conn.SetDeadline(deadline)
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	return func() {
		stopCancel()
		_ = conn.SetDeadline(time.Time{})
	}
}

func usesRandomPadding(xorMode string) bool {
	return xorMode == XorRandom || xorMode == XorHTTP
}

// Client performs the client side of certificate-less Hybrid X25519 + ML-KEM-768 VLESS encryption.
type Client struct {
	serverX25519 *ecdh.PublicKey
	serverMLKEM  *mlkem.EncapsulationKey768
	pkServer     []byte
	mode         string
	xorMode      string
	maskKey      [32]byte
	httpHost     string
	httpPath     string
	httpHeaders  http.Header
	httpAuthKey  [32]byte
	now          func() time.Time

	ticketMu     sync.Mutex
	cachedTicket []byte
	ticketPSK    [32]byte
	ticketExpiry time.Time
}

// NewClient validates options and constructs a hybrid encryption client handler.
func NewClient(options option.VLESSEncryptionOptions) (*Client, error) {
	mode, err := normalizeClientMode(options.Mode)
	if err != nil {
		return nil, err
	}
	xorMode, err := normalizeXorMode(options.XorMode)
	if err != nil {
		return nil, err
	}
	pubRaw, err := decodeBase64Fixed("public_key", options.PublicKey, x25519KeySize)
	if err != nil {
		return nil, err
	}
	xPub, err := ecdh.X25519().NewPublicKey(pubRaw)
	if err != nil {
		return nil, E.Cause(err, "vlessenc: invalid X25519 public_key")
	}
	ekRaw, err := decodeBase64Fixed("mlkem768_encap_key", options.MLKEM768EncapKey, mlkem.EncapsulationKeySize768)
	if err != nil {
		return nil, err
	}
	kemEK, err := mlkem.NewEncapsulationKey768(ekRaw)
	if err != nil {
		return nil, E.Cause(err, "vlessenc: invalid mlkem768_encap_key")
	}
	psk, err := decodeOptionalPSK(options.XorPSK)
	if err != nil {
		return nil, err
	}

	pkServer := make([]byte, 0, len(pubRaw)+len(ekRaw))
	pkServer = append(pkServer, pubRaw...)
	pkServer = append(pkServer, ekRaw...)

	return &Client{
		serverX25519: xPub,
		serverMLKEM:  kemEK,
		pkServer:     pkServer,
		mode:         mode,
		xorMode:      xorMode,
		maskKey:      deriveMaskKey(pkServer, psk),
		httpHost:     options.HTTPHost,
		httpPath:     normalizeHTTPPath(options.HTTPPath),
		httpHeaders:  options.HTTPHeaders.Build(),
		httpAuthKey:  deriveHTTPAuthKey(pkServer, psk),
		now:          time.Now,
	}, nil
}

func (c *Client) getCachedTicket() ([]byte, [32]byte, bool) {
	if c.mode != ModeZeroRTT {
		return nil, [32]byte{}, false
	}
	c.ticketMu.Lock()
	defer c.ticketMu.Unlock()
	if len(c.cachedTicket) == 0 || !c.now().Before(c.ticketExpiry) {
		c.cachedTicket = nil
		return nil, [32]byte{}, false
	}
	ticket := append([]byte(nil), c.cachedTicket...)
	return ticket, c.ticketPSK, true
}

func (c *Client) setCachedTicket(ticket []byte, psk [32]byte, ttl time.Duration) {
	if c.mode != ModeZeroRTT || len(ticket) == 0 || ttl <= 0 {
		return
	}
	c.ticketMu.Lock()
	c.cachedTicket = append([]byte(nil), ticket...)
	c.ticketPSK = psk
	c.ticketExpiry = c.now().Add(ttl)
	c.ticketMu.Unlock()
}

func (c *Client) invalidateTicket(used []byte) {
	c.ticketMu.Lock()
	if bytes.Equal(c.cachedTicket, used) {
		c.cachedTicket = nil
		c.ticketPSK = [32]byte{}
		c.ticketExpiry = time.Time{}
	}
	c.ticketMu.Unlock()
}

// ClientHandshake upgrades conn using X25519 + ML-KEM-768 (1-RTT) or cached 0-RTT ticket + ephemeral X25519.
func (c *Client) ClientHandshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	doneWatch := watchHandshakeContext(ctx, conn)
	defer doneWatch()

	if c.xorMode == XorHTTP {
		var err error
		conn, err = c.clientHTTPUpgrade(conn)
		if err != nil {
			return nil, err
		}
	}

	ephPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sharedX, err := ephPriv.ECDH(c.serverX25519)
	if err != nil {
		return nil, ErrInvalidHandshake
	}

	ticket, cachedPSK, use0RTT := c.getCachedTicket()
	var (
		flags   byte
		payload []byte
		pqPart  []byte
	)
	if use0RTT {
		flags |= flagZeroRTT
		payload = ticket
		pqPart = cachedPSK[:]
	} else {
		sharedMLKEM, ct := c.serverMLKEM.Encapsulate()
		payload = ct
		pqPart = sharedMLKEM
	}

	var pad []byte
	if usesRandomPadding(c.xorMode) {
		flags |= flagHasPadding
		pad = sampleRandomPadding(16, 191)
	}

	bodyLen := 1 + 1 + x25519KeySize + 2 + len(payload)
	if len(pad) > 0 {
		bodyLen += 1 + len(pad)
	}
	body := make([]byte, 0, bodyLen)
	body = append(body, protocolVersion, flags)
	body = append(body, ephPriv.PublicKey().Bytes()...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	body = append(body, lenBuf[:]...)
	body = append(body, payload...)
	if len(pad) > 0 {
		body = append(body, byte(len(pad)))
		body = append(body, pad...)
	}

	var hdrNonce [16]byte
	if _, err = io.ReadFull(rand.Reader, hdrNonce[:]); err != nil {
		return nil, err
	}
	if err = writeMaskedEnvelope(conn, hdrNonce, c.xorMode, c.maskKey, body); err != nil {
		return nil, err
	}

	ikm := make([]byte, 0, len(sharedX)+len(pqPart)+len(c.pkServer))
	ikm = append(ikm, sharedX...)
	ikm = append(ikm, pqPart...)
	ikm = append(ikm, c.pkServer...)
	keys, err := deriveSessionKeys(ikm, hdrNonce)
	if err != nil {
		return nil, err
	}

	verifyServerHello := func(r io.Reader) error {
		srvNonce, srvBody, rErr := readMaskedEnvelope(r, c.xorMode, c.maskKey, minServerBodyBytes)
		if rErr != nil {
			if use0RTT {
				c.invalidateTicket(ticket)
			}
			return rErr
		}
		newTicket, ttl, pErr := parseAndVerifyServerHello(srvBody, keys.confirmKey, hdrNonce, srvNonce)
		if pErr != nil {
			if use0RTT {
				c.invalidateTicket(ticket)
			}
			return pErr
		}
		c.setCachedTicket(newTicket, keys.ticketPSK, ttl)
		return nil
	}

	if use0RTT {
		// Wait for ServerHello lazily on the client's first Read so 0-RTT application data flows immediately.
		return newAEADConn(conn, keys.upKey, keys.upIV, keys.downKey, keys.downIV, verifyServerHello)
	}
	if err = verifyServerHello(conn); err != nil {
		return nil, err
	}
	return newAEADConn(conn, keys.upKey, keys.upIV, keys.downKey, keys.downIV, nil)
}

func parseAndVerifyServerHello(body, confirmKey []byte, hdrNonce, srvNonce [16]byte) ([]byte, time.Duration, error) {
	if len(body) < minServerBodyBytes || body[0] != protocolVersion {
		return nil, 0, ErrInvalidHandshake
	}
	flags := body[1]
	ticketLen := int(binary.BigEndian.Uint16(body[2:4]))
	pos := 4
	if pos+ticketLen+sha256.Size > len(body) {
		return nil, 0, ErrInvalidHandshake
	}
	ticket := body[pos : pos+ticketLen]
	pos += ticketLen

	var ttl time.Duration
	if pos+8 <= len(body)-sha256.Size {
		ttlMillis := binary.BigEndian.Uint64(body[pos : pos+8])
		ttl = time.Duration(ttlMillis) * time.Millisecond
		pos += 8
	}
	if flags&flagHasPadding != 0 {
		if pos >= len(body)-sha256.Size {
			return nil, 0, ErrInvalidHandshake
		}
		padLen := int(body[pos])
		pos++
		if pos+padLen+sha256.Size != len(body) {
			return nil, 0, ErrInvalidHandshake
		}
		pos += padLen
	} else if pos+sha256.Size != len(body) {
		return nil, 0, ErrInvalidHandshake
	}

	expectedTag := computeConfirmTag(confirmKey, hdrNonce, srvNonce, ticket)
	if !hmac.Equal(expectedTag, body[pos:]) {
		return nil, 0, ErrInvalidHandshake
	}
	return ticket, ttl, nil
}

// Server performs the server side of certificate-less Hybrid X25519 + ML-KEM-768 decryption and 0-RTT ticket validation.
type Server struct {
	x25519Priv    *ecdh.PrivateKey
	mlkemDK       *mlkem.DecapsulationKey768
	pkServer      []byte
	ticketAEAD    cipher.AEAD
	xorMode       string
	maskKey       [32]byte
	httpHost      string
	httpPath      string
	httpAuthKey   [32]byte
	sessionMaxAge time.Duration
	now           func() time.Time
	replay        *replayCache
	httpReplay    *replayCache
}

// NewServer validates options and constructs a hybrid decryption server handler.
func NewServer(options option.VLESSDecryptionOptions) (*Server, error) {
	xorMode, err := normalizeXorMode(options.XorMode)
	if err != nil {
		return nil, err
	}
	privRaw, err := decodeBase64Fixed("private_key", options.PrivateKey, x25519KeySize)
	if err != nil {
		return nil, err
	}
	xPriv, err := ecdh.X25519().NewPrivateKey(privRaw)
	if err != nil {
		return nil, E.Cause(err, "vlessenc: invalid X25519 private_key")
	}
	seedRaw, err := decodeBase64Fixed("mlkem768_seed", options.MLKEM768Seed, mlkem.SeedSize)
	if err != nil {
		return nil, err
	}
	kemDK, err := mlkem.NewDecapsulationKey768(seedRaw)
	if err != nil {
		return nil, E.Cause(err, "vlessenc: invalid mlkem768_seed")
	}
	var ticketSecret []byte
	if options.TicketSecret != "" {
		ticketSecret, err = decodeBase64Fixed("ticket_secret", options.TicketSecret, 32)
		if err != nil {
			return nil, err
		}
	} else {
		ticketSecret = make([]byte, 32)
		if _, err = io.ReadFull(rand.Reader, ticketSecret); err != nil {
			return nil, err
		}
	}
	ticketBlock, err := aes.NewCipher(ticketSecret)
	if err != nil {
		return nil, err
	}
	ticketAEAD, err := cipher.NewGCM(ticketBlock)
	if err != nil {
		return nil, err
	}
	psk, err := decodeOptionalPSK(options.XorPSK)
	if err != nil {
		return nil, err
	}

	xPubBytes := xPriv.PublicKey().Bytes()
	ekBytes := kemDK.EncapsulationKey().Bytes()
	pkServer := make([]byte, 0, len(xPubBytes)+len(ekBytes))
	pkServer = append(pkServer, xPubBytes...)
	pkServer = append(pkServer, ekBytes...)

	maxAge := time.Duration(options.SessionMaxAge)
	if maxAge < 0 {
		return nil, E.New("vlessenc: negative session_max_age")
	}
	if maxAge == 0 {
		maxAge = DefaultSessionMaxAge
	}

	var httpPath string
	if options.HTTPPath != "" {
		httpPath = normalizeHTTPPath(options.HTTPPath)
	}

	return &Server{
		x25519Priv:    xPriv,
		mlkemDK:       kemDK,
		pkServer:      pkServer,
		ticketAEAD:    ticketAEAD,
		xorMode:       xorMode,
		maskKey:       deriveMaskKey(pkServer, psk),
		httpHost:      options.HTTPHost,
		httpPath:      httpPath,
		httpAuthKey:   deriveHTTPAuthKey(pkServer, psk),
		sessionMaxAge: maxAge,
		now:           time.Now,
		replay:        newReplayCache(maxReplayEntries),
		httpReplay:    newReplayCache(maxReplayEntries),
	}, nil
}

// ServerHandshake authenticates ClientHello, guards 0-RTT nonces against replay, and returns an encrypted net.Conn.
func (s *Server) ServerHandshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	doneWatch := watchHandshakeContext(ctx, conn)
	defer doneWatch()

	if s.xorMode == XorHTTP {
		var err error
		conn, err = s.serverHTTPUpgrade(ctx, conn)
		if err != nil {
			return nil, err
		}
	}

	hdrNonce, body, err := readMaskedEnvelope(conn, s.xorMode, s.maskKey, minClientBodyBytes)
	if err != nil {
		return nil, err
	}
	if len(body) < minClientBodyBytes || body[0] != protocolVersion {
		return nil, ErrInvalidHandshake
	}
	flags := body[1]
	pos := 2
	ephPubBytes := body[pos : pos+x25519KeySize]
	pos += x25519KeySize
	payloadLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	if pos+payloadLen > len(body) {
		return nil, ErrInvalidHandshake
	}
	payload := body[pos : pos+payloadLen]
	pos += payloadLen

	if flags&flagHasPadding != 0 {
		if pos >= len(body) {
			return nil, ErrInvalidHandshake
		}
		padLen := int(body[pos])
		pos++
		if pos+padLen != len(body) {
			return nil, ErrInvalidHandshake
		}
	} else if pos != len(body) {
		return nil, ErrInvalidHandshake
	}

	clientEphPub, err := ecdh.X25519().NewPublicKey(ephPubBytes)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	sharedX, err := s.x25519Priv.ECDH(clientEphPub)
	if err != nil {
		return nil, ErrInvalidHandshake
	}

	now := s.now()
	var pqPart []byte
	if flags&flagZeroRTT != 0 {
		ticketPSK, expiry, tErr := s.openTicket(payload, now)
		if tErr != nil {
			return nil, ErrInvalidHandshake
		}
		if !s.replay.CheckAndAdd(hdrNonce, expiry, now) {
			return nil, ErrReplayRejected
		}
		pqPart = ticketPSK[:]
	} else {
		if len(payload) != mlkem.CiphertextSize768 {
			return nil, ErrInvalidHandshake
		}
		sharedMLKEM, dErr := s.mlkemDK.Decapsulate(payload)
		if dErr != nil {
			return nil, ErrInvalidHandshake
		}
		pqPart = sharedMLKEM
	}

	ikm := make([]byte, 0, len(sharedX)+len(pqPart)+len(s.pkServer))
	ikm = append(ikm, sharedX...)
	ikm = append(ikm, pqPart...)
	ikm = append(ikm, s.pkServer...)
	keys, err := deriveSessionKeys(ikm, hdrNonce)
	if err != nil {
		return nil, err
	}

	newTicket, err := s.sealTicket(keys.ticketPSK, now.Add(s.sessionMaxAge))
	if err != nil {
		return nil, err
	}

	var srvNonce [16]byte
	if _, err = io.ReadFull(rand.Reader, srvNonce[:]); err != nil {
		return nil, err
	}

	var srvFlags byte
	var srvPad []byte
	if usesRandomPadding(s.xorMode) {
		srvFlags |= flagHasPadding
		srvPad = sampleRandomPadding(16, 95)
	}
	confirmTag := computeConfirmTag(keys.confirmKey, hdrNonce, srvNonce, newTicket)

	ttlMillis := uint64(s.sessionMaxAge.Milliseconds())
	srvBody := make([]byte, 0, 4+len(newTicket)+8+1+len(srvPad)+len(confirmTag))
	srvBody = append(srvBody, protocolVersion, srvFlags)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(newTicket)))
	srvBody = append(srvBody, lenBuf[:]...)
	srvBody = append(srvBody, newTicket...)
	var ttlBuf [8]byte
	binary.BigEndian.PutUint64(ttlBuf[:], ttlMillis)
	srvBody = append(srvBody, ttlBuf[:]...)
	if len(srvPad) > 0 {
		srvBody = append(srvBody, byte(len(srvPad)))
		srvBody = append(srvBody, srvPad...)
	}
	srvBody = append(srvBody, confirmTag...)

	if err = writeMaskedEnvelope(conn, srvNonce, s.xorMode, s.maskKey, srvBody); err != nil {
		return nil, err
	}
	return newAEADConn(conn, keys.downKey, keys.downIV, keys.upKey, keys.upIV, nil)
}

func (s *Server) sealTicket(psk [32]byte, expiry time.Time) ([]byte, error) {
	var nonce [ticketNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	var plain [ticketPlainSize]byte
	binary.BigEndian.PutUint64(plain[:8], uint64(expiry.UnixNano()))
	copy(plain[8:], psk[:])
	out := make([]byte, ticketNonceSize, ticketNonceSize+ticketPlainSize+aeadTagSize)
	copy(out, nonce[:])
	return s.ticketAEAD.Seal(out, nonce[:], plain[:], []byte("vlessenc-v1-ticket")), nil
}

func (s *Server) openTicket(ticket []byte, now time.Time) ([32]byte, time.Time, error) {
	var psk [32]byte
	if len(ticket) != ticketNonceSize+ticketPlainSize+aeadTagSize {
		return psk, time.Time{}, ErrInvalidHandshake
	}
	plain, err := s.ticketAEAD.Open(nil, ticket[:ticketNonceSize], ticket[ticketNonceSize:], []byte("vlessenc-v1-ticket"))
	if err != nil || len(plain) != ticketPlainSize {
		return psk, time.Time{}, ErrInvalidHandshake
	}
	expiry := time.Unix(0, int64(binary.BigEndian.Uint64(plain[:8])))
	if now.After(expiry) {
		return psk, time.Time{}, ErrInvalidHandshake
	}
	copy(psk[:], plain[8:])
	return psk, expiry, nil
}

type replayCache struct {
	mu      sync.Mutex
	maxSize int
	seen    map[[16]byte]int64
}

func newReplayCache(maxSize int) *replayCache {
	return &replayCache{
		maxSize: maxSize,
		seen:    make(map[[16]byte]int64),
	}
}

func (r *replayCache) CheckAndAdd(nonce [16]byte, expiry, now time.Time) bool {
	nowNano := now.UnixNano()
	expNano := expiry.UnixNano()

	r.mu.Lock()
	defer r.mu.Unlock()

	if prevExp, exists := r.seen[nonce]; exists {
		if prevExp >= nowNano {
			return false
		}
		delete(r.seen, nonce)
	}
	if len(r.seen) >= r.maxSize {
		for k, v := range r.seen {
			if v < nowNano {
				delete(r.seen, k)
			}
		}
		for len(r.seen) >= r.maxSize {
			for k := range r.seen {
				delete(r.seen, k)
				break
			}
		}
	}
	r.seen[nonce] = expNano
	return true
}
