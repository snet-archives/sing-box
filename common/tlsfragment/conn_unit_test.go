package tf_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	tf "github.com/sagernet/sing-box/common/tlsfragment"
)

type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	c.mu.Unlock()
	return len(p), nil
}

func (c *recordingConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (c *recordingConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443} }
func (c *recordingConn) SetDeadline(t time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *recordingConn) Close() error                       { return nil }

func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	var captured []byte
	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		n, _ := c2.Read(buf)
		captured = append(captured, buf[:n]...)
		_ = c2.Close()
	}()
	client := tls.Client(c1, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: serverName == "",
		NextProtos:         []string{"h2"},
	})
	_ = client.Handshake()
	_ = c1.Close()
	<-done
	if len(captured) < 5 || captured[0] != 22 {
		t.Fatalf("expected TLS handshake record, got %d bytes", len(captured))
	}
	return captured
}

func TestParseRange(t *testing.T) {
	minV, maxV, err := tf.ParseRange("10-20")
	if err != nil || minV != 10 || maxV != 20 {
		t.Fatalf("unexpected ParseRange(10-20): %d, %d, %v", minV, maxV, err)
	}
	minV, maxV, err = tf.ParseRange("15")
	if err != nil || minV != 15 || maxV != 15 {
		t.Fatalf("unexpected ParseRange(15): %d, %d, %v", minV, maxV, err)
	}
	for _, invalid := range []string{"0", "20-10", "-5", "abc", "5-0"} {
		if _, _, err := tf.ParseRange(invalid); err == nil {
			t.Fatalf("expected error for ParseRange(%q)", invalid)
		}
	}
}

func TestFragmentPublicSuffixCountingAndSingleLabel(t *testing.T) {
	raw := captureClientHello(t, "api.sub.example.co.uk")
	suffixIdx := bytes.Index(raw, []byte(".co.uk"))
	if suffixIdx < 0 {
		t.Fatal("failed to locate .co.uk in ClientHello")
	}
	// Verify all splits happen strictly inside "api.sub.example" and never inside ".co.uk".
	for i := 0; i < 20; i++ {
		rec := &recordingConn{}
		conn := tf.NewConnWithOptions(rec, tf.Options{
			Context:       context.Background(),
			SplitPacket:   true,
			FallbackDelay: time.Millisecond,
		})
		n, err := conn.Write(raw)
		if err != nil || n != len(raw) {
			t.Fatalf("Write failed: n=%d len=%d err=%v", n, len(raw), err)
		}
		if len(rec.writes) != 4 {
			t.Fatalf("expected 4 chunks for 3 prefix labels before .co.uk, got %d", len(rec.writes))
		}
		lastSplit := len(rec.writes[0]) + len(rec.writes[1]) + len(rec.writes[2])
		if lastSplit > suffixIdx {
			t.Fatalf("split occurred inside public suffix: lastSplit=%d suffixIdx=%d", lastSplit, suffixIdx)
		}
		if !bytes.Equal(bytes.Join(rec.writes, nil), raw) {
			t.Fatalf("reassembled payload mismatch")
		}
	}

	rawLocal := captureClientHello(t, "localhost")
	recLocal := &recordingConn{}
	connLocal := tf.NewConnWithOptions(recLocal, tf.Options{
		Context:       context.Background(),
		SplitPacket:   true,
		FallbackDelay: time.Millisecond,
	})
	if n, err := connLocal.Write(rawLocal); err != nil || n != len(rawLocal) {
		t.Fatalf("Write failed for single-label host: n=%d err=%v", n, err)
	}
	if !bytes.Equal(bytes.Join(recLocal.writes, nil), rawLocal) {
		t.Fatalf("reassembled single-label payload mismatch")
	}
}

func TestFragmentEmptyOrMaliciousSNILabelsDoNotPanic(t *testing.T) {
	// Construct a ClientHello-like payload containing a trailing empty label "a."
	base := captureClientHello(t, "edge.example.com")
	malformed := bytes.Replace(base, []byte("edge.example.com"), []byte("edge...........a"), 1)
	rec := &recordingConn{}
	conn := tf.NewConnWithOptions(rec, tf.Options{
		Context:       context.Background(),
		SplitPacket:   true,
		FallbackDelay: time.Millisecond,
	})
	if n, err := conn.Write(malformed); err != nil || n != len(malformed) {
		t.Fatalf("Write failed on empty-label host: n=%d err=%v", n, err)
	}
}

func TestFragmentNonSNIClientHelloFallbackAndRangeSplit(t *testing.T) {
	raw := captureClientHello(t, "")
	if tf.IndexTLSServerName(raw) != nil {
		t.Fatalf("expected no SNI extension in ClientHello without ServerName")
	}

	// Default non-SNI generalized fallback split
	rec := &recordingConn{}
	conn := tf.NewConnWithOptions(rec, tf.Options{
		Context:       context.Background(),
		SplitPacket:   true,
		FallbackDelay: time.Millisecond,
	})
	n, err := conn.Write(raw)
	if err != nil || n != len(raw) {
		t.Fatalf("Write failed: n=%d err=%v", n, err)
	}
	if len(rec.writes) < 2 || len(rec.writes) > 6 {
		t.Fatalf("expected 2..6 chunks for generalized handshake fallback, got %d", len(rec.writes))
	}
	if !bytes.Equal(bytes.Join(rec.writes, nil), raw) {
		t.Fatalf("reassembled non-SNI payload mismatch")
	}

	// Custom fragment length range
	recRange := &recordingConn{}
	connRange := tf.NewConnWithOptions(recRange, tf.Options{
		Context:        context.Background(),
		SplitPacket:    true,
		FallbackDelay:  time.Millisecond,
		FragmentMinLen: 16,
		FragmentMaxLen: 32,
	})
	n, err = connRange.Write(raw)
	if err != nil || n != len(raw) {
		t.Fatalf("Write failed: n=%d err=%v", n, err)
	}
	if len(recRange.writes) < 3 {
		t.Fatalf("expected multiple chunks with 16-32 range, got %d", len(recRange.writes))
	}
	for i, w := range recRange.writes {
		maxAllowed := 32
		if i == 0 {
			maxAllowed += 5 // chunk 0 includes the 5-byte TLS record header
		}
		if len(w) == 0 || (i < len(recRange.writes)-1 && len(w) > maxAllowed) {
			t.Fatalf("chunk %d length out of expected bounds: %d (max %d)", i, len(w), maxAllowed)
		}
	}
	if !bytes.Equal(bytes.Join(recRange.writes, nil), raw) {
		t.Fatalf("reassembled range payload mismatch")
	}
}
