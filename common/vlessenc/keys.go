package vlessenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// ModeNative performs a full 1-RTT X25519 + ML-KEM-768 handshake on every connection.
	ModeNative = "native"
	// ModeZeroRTT caches a server-issued encrypted ticket after 1-RTT for 0-RTT fast open.
	ModeZeroRTT = "zero_rtt"

	// XorNone disables handshake envelope masking.
	XorNone = "none"
	// XorMask masks handshake headers with an AES-256-CTR keystream derived from server keys and optional XorPSK.
	XorMask = "xor"
	// XorRandom applies XorMask plus randomized variable-length padding to defeat packet-size fingerprinting.
	XorRandom = "random"
	// XorHTTP wraps the handshake in an authenticated HTTP/1.1 Upgrade request/response
	// (defeating Ex1-Ex5 heuristics and allowing fallback masquerading) before XorRandom framing.
	XorHTTP = "http"

	// DefaultSessionMaxAge bounds 0-RTT session ticket validity and replay-nonce retention.
	DefaultSessionMaxAge = 5 * time.Minute
)

// KeyPair holds a generated hybrid X25519 + ML-KEM-768 keypair plus optional 0-RTT and mask secrets.
type KeyPair struct {
	PrivateKey       string `json:"private_key"`
	PublicKey        string `json:"public_key"`
	MLKEM768Seed     string `json:"mlkem768_seed"`
	MLKEM768EncapKey string `json:"mlkem768_encap_key"`
	TicketSecret     string `json:"ticket_secret"`
	XorPSK           string `json:"xor_psk"`
}

// GenerateKeyPair creates fresh certificate-less X25519 + ML-KEM-768 credentials
// alongside random 0-RTT ticket and XorPSK secrets.
func GenerateKeyPair() (KeyPair, error) {
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, E.Cause(err, "vlessenc: generate X25519 key")
	}
	kemDK, err := mlkem.GenerateKey768()
	if err != nil {
		return KeyPair{}, E.Cause(err, "vlessenc: generate ML-KEM-768 key")
	}
	var ticketSecret, xorPSK [32]byte
	if _, err = io.ReadFull(rand.Reader, ticketSecret[:]); err != nil {
		return KeyPair{}, err
	}
	if _, err = io.ReadFull(rand.Reader, xorPSK[:]); err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		PrivateKey:       base64.RawURLEncoding.EncodeToString(xPriv.Bytes()),
		PublicKey:        base64.RawURLEncoding.EncodeToString(xPriv.PublicKey().Bytes()),
		MLKEM768Seed:     base64.RawURLEncoding.EncodeToString(kemDK.Bytes()),
		MLKEM768EncapKey: base64.RawURLEncoding.EncodeToString(kemDK.EncapsulationKey().Bytes()),
		TicketSecret:     base64.RawURLEncoding.EncodeToString(ticketSecret[:]),
		XorPSK:           base64.RawURLEncoding.EncodeToString(xorPSK[:]),
	}, nil
}

func decodeBase64Fixed(field, encoded string, wantLen int) ([]byte, error) {
	if encoded == "" {
		return nil, E.New("vlessenc: missing ", field)
	}
	raw, err := decodeBase64Flex(encoded)
	if err != nil {
		return nil, E.Cause(err, "vlessenc: decode ", field)
	}
	if wantLen > 0 && len(raw) != wantLen {
		return nil, E.New("vlessenc: invalid ", field, " length ", len(raw), ", want ", wantLen)
	}
	return raw, nil
}

func decodeBase64Flex(encoded string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		raw, err := enc.DecodeString(encoded)
		if err == nil {
			return raw, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func normalizeXorMode(mode string) (string, error) {
	switch mode {
	case "", XorNone:
		return XorNone, nil
	case XorMask, XorRandom, XorHTTP:
		return mode, nil
	default:
		return "", E.New("vlessenc: unknown xor_mode: ", mode)
	}
}

func normalizeClientMode(mode string) (string, error) {
	switch mode {
	case "", ModeZeroRTT:
		return ModeZeroRTT, nil
	case ModeNative:
		return ModeNative, nil
	default:
		return "", E.New("vlessenc: unknown mode: ", mode)
	}
}

func decodeOptionalPSK(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	raw, err := decodeBase64Flex(encoded)
	if err != nil {
		return nil, E.Cause(err, "vlessenc: decode xor_psk")
	}
	if len(raw) == 0 {
		return nil, E.New("vlessenc: empty xor_psk")
	}
	return raw, nil
}

func deriveScopedKey(domain string, pkServer, psk []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(pkServer)
	if len(psk) > 0 {
		_, _ = h.Write(psk)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func deriveMaskKey(pkServer, psk []byte) [32]byte {
	return deriveScopedKey("vlessenc-v1-mask", pkServer, psk)
}

func deriveHTTPAuthKey(pkServer, psk []byte) [32]byte {
	return deriveScopedKey("vlessenc-v1-http-auth", pkServer, psk)
}

func applyXorStream(key [32]byte, nonce [16]byte, dst, src []byte) error {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, nonce[:])
	stream.XORKeyStream(dst, src)
	return nil
}
