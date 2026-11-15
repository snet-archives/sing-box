package vlessenc

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"math"
	"net"
	"sync"
	"time"

	N "github.com/sagernet/sing/common/network"
)

const (
	maxRecordPayload = 16384
	aeadTagSize      = 16
	encLenSize       = 2 + aeadTagSize
)

type preReadFn func(r io.Reader) error

// aeadConn wraps a net.Conn with length-encrypted, sequence-bound AES-256-GCM framing.
// It intentionally does not expose ReaderReplaceable/WriterReplaceable so sing-bufio
// never bypasses encryption.
type aeadConn struct {
	conn net.Conn

	preReadMu   sync.Mutex
	preReadDone bool
	preReadErr  error
	preRead     preReadFn

	readMu     sync.Mutex
	readAEAD   cipher.AEAD
	readBaseIV [12]byte
	readSeq    uint64
	pending    []byte

	writeMu     sync.Mutex
	writeAEAD   cipher.AEAD
	writeBaseIV [12]byte
	writeSeq    uint64
}

func newAEADConn(conn net.Conn, writeKey []byte, writeIV [12]byte, readKey []byte, readIV [12]byte, preRead preReadFn) (*aeadConn, error) {
	wBlock, err := aes.NewCipher(writeKey)
	if err != nil {
		return nil, err
	}
	wAEAD, err := cipher.NewGCM(wBlock)
	if err != nil {
		return nil, err
	}
	rBlock, err := aes.NewCipher(readKey)
	if err != nil {
		return nil, err
	}
	rAEAD, err := cipher.NewGCM(rBlock)
	if err != nil {
		return nil, err
	}
	return &aeadConn{
		conn:        conn,
		preRead:     preRead,
		readAEAD:    rAEAD,
		readBaseIV:  readIV,
		writeAEAD:   wAEAD,
		writeBaseIV: writeIV,
	}, nil
}

func makeRecordNonce(base [12]byte, seq uint64) [12]byte {
	var nonce [12]byte
	nonce = base
	var seqBytes [8]byte
	binary.BigEndian.PutUint64(seqBytes[:], seq)
	for i := range 8 {
		nonce[4+i] ^= seqBytes[i]
	}
	return nonce
}

func (c *aeadConn) ensurePreRead() error {
	if c.preRead == nil {
		return nil
	}
	c.preReadMu.Lock()
	defer c.preReadMu.Unlock()
	if !c.preReadDone {
		c.preReadErr = c.preRead(c.conn)
		c.preReadDone = true
	}
	return c.preReadErr
}

func (c *aeadConn) Read(p []byte) (int, error) {
	if err := c.ensurePreRead(); err != nil {
		return 0, err
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.readSeq > math.MaxUint64-2 {
		return 0, ErrInvalidRecord
	}

	var encLen [encLenSize]byte
	if _, err := io.ReadFull(c.conn, encLen[:]); err != nil {
		return 0, err
	}
	lenNonce := makeRecordNonce(c.readBaseIV, c.readSeq)
	var plainLen [2]byte
	if _, err := c.readAEAD.Open(plainLen[:0], lenNonce[:], encLen[:], nil); err != nil {
		return 0, ErrInvalidRecord
	}
	payloadLen := int(binary.BigEndian.Uint16(plainLen[:]))
	if payloadLen == 0 || payloadLen > maxRecordPayload {
		return 0, ErrInvalidRecord
	}

	encPayload := make([]byte, payloadLen+aeadTagSize)
	if _, err := io.ReadFull(c.conn, encPayload); err != nil {
		return 0, err
	}
	payloadNonce := makeRecordNonce(c.readBaseIV, c.readSeq+1)
	plaintext, err := c.readAEAD.Open(encPayload[:0], payloadNonce[:], encPayload, encLen[:])
	if err != nil {
		return 0, ErrInvalidRecord
	}
	c.readSeq += 2

	n := copy(p, plaintext)
	if n < len(plaintext) {
		c.pending = append(c.pending[:0], plaintext[n:]...)
	}
	return n, nil
}

func (c *aeadConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	written := 0
	for len(p) > 0 {
		if c.writeSeq > math.MaxUint64-2 {
			return written, ErrInvalidRecord
		}
		chunkLen := len(p)
		if chunkLen > maxRecordPayload {
			chunkLen = maxRecordPayload
		}
		chunk := p[:chunkLen]

		var plainLen [2]byte
		binary.BigEndian.PutUint16(plainLen[:], uint16(chunkLen))

		frame := make([]byte, encLenSize+chunkLen+aeadTagSize)
		lenNonce := makeRecordNonce(c.writeBaseIV, c.writeSeq)
		c.writeAEAD.Seal(frame[:0], lenNonce[:], plainLen[:], nil)

		payloadNonce := makeRecordNonce(c.writeBaseIV, c.writeSeq+1)
		c.writeAEAD.Seal(frame[encLenSize:encLenSize], payloadNonce[:], chunk, frame[:encLenSize])
		c.writeSeq += 2

		if _, err := c.conn.Write(frame); err != nil {
			return written, err
		}
		written += chunkLen
		p = p[chunkLen:]
	}
	return written, nil
}

func (c *aeadConn) Close() error {
	return c.conn.Close()
}

func (c *aeadConn) CloseWrite() error {
	return N.CloseWrite(c.conn)
}

func (c *aeadConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *aeadConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *aeadConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *aeadConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *aeadConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
func (c *aeadConn) Upstream() any                      { return c.conn }
