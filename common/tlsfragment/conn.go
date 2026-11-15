package tf

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/net/publicsuffix"
)

const (
	defaultFallbackChunkMin = 32
	defaultFallbackChunkMax = 96
	defaultPacketMaxSplits  = 5
	maxTLSRecordPayloadLen  = 16384
)

type Options struct {
	Context         context.Context
	SplitPacket     bool
	SplitRecord     bool
	FallbackDelay   time.Duration
	FragmentMinLen  int
	FragmentMaxLen  int
	FragmentMinWait time.Duration
	FragmentMaxWait time.Duration
}

type Conn struct {
	net.Conn
	tcpConn            *net.TCPConn
	ctx                context.Context
	firstPacketWritten bool
	splitPacket        bool
	splitRecord        bool
	fallbackDelay      time.Duration
	fragmentMinLen     int
	fragmentMaxLen     int
	fragmentMinWait    time.Duration
	fragmentMaxWait    time.Duration
}

func NewConn(conn net.Conn, ctx context.Context, splitPacket bool, splitRecord bool, fallbackDelay time.Duration) *Conn {
	return NewConnWithOptions(conn, Options{
		Context:       ctx,
		SplitPacket:   splitPacket,
		SplitRecord:   splitRecord,
		FallbackDelay: fallbackDelay,
	})
}

func NewConnWithOptions(conn net.Conn, options Options) *Conn {
	fallbackDelay := options.FallbackDelay
	if fallbackDelay == 0 {
		fallbackDelay = C.TLSFragmentFallbackDelay
	}
	var tcpConn *net.TCPConn
	if unwrapped := N.UnwrapReader(conn); unwrapped != nil {
		tcpConn, _ = unwrapped.(*net.TCPConn)
	}
	return &Conn{
		Conn:            conn,
		tcpConn:         tcpConn,
		ctx:             options.Context,
		splitPacket:     options.SplitPacket,
		splitRecord:     options.SplitRecord,
		fallbackDelay:   fallbackDelay,
		fragmentMinLen:  options.FragmentMinLen,
		fragmentMaxLen:  options.FragmentMaxLen,
		fragmentMinWait: options.FragmentMinWait,
		fragmentMaxWait: options.FragmentMaxWait,
	}
}

// ParseRange parses a "min-max" or single integer/value range into inclusive bounds.
func ParseRange(spec string) (int, int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, nil
	}
	if left, right, ok := strings.Cut(spec, "-"); ok {
		minVal, err := strconv.Atoi(strings.TrimSpace(left))
		if err != nil {
			return 0, 0, E.Cause(err, "invalid range lower bound: ", spec)
		}
		maxVal, err := strconv.Atoi(strings.TrimSpace(right))
		if err != nil {
			return 0, 0, E.Cause(err, "invalid range upper bound: ", spec)
		}
		if minVal <= 0 || maxVal < minVal {
			return 0, 0, E.New("invalid range bounds: ", spec)
		}
		return minVal, maxVal, nil
	}
	val, err := strconv.Atoi(spec)
	if err != nil || val <= 0 {
		return 0, 0, E.New("invalid range value: ", spec)
	}
	return val, val, nil
}

// ParseDurationOrMillisRange parses a "min-max" or single duration/millisecond
// value into inclusive time.Duration bounds. Plain integers default to ms.
func ParseDurationOrMillisRange(spec string) (time.Duration, time.Duration, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, nil
	}
	parseOne := func(part string) (time.Duration, error) {
		part = strings.TrimSpace(part)
		if d, err := time.ParseDuration(part); err == nil {
			if d < 0 {
				return 0, E.New("negative duration: ", part)
			}
			return d, nil
		}
		ms, err := strconv.Atoi(part)
		if err != nil || ms < 0 {
			return 0, E.New("invalid interval: ", part)
		}
		return time.Duration(ms) * time.Millisecond, nil
	}
	if left, right, ok := strings.Cut(spec, "-"); ok {
		minWait, err := parseOne(left)
		if err != nil {
			return 0, 0, err
		}
		maxWait, err := parseOne(right)
		if err != nil {
			return 0, 0, err
		}
		if maxWait < minWait {
			return 0, 0, E.New("invalid interval bounds: ", spec)
		}
		return minWait, maxWait, nil
	}
	val, err := parseOne(spec)
	if err != nil {
		return 0, 0, err
	}
	return val, val, nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if !c.firstPacketWritten && len(b) > 0 && (c.splitPacket || c.splitRecord) {
		defer func() {
			c.firstPacketWritten = true
		}()
		isTLSRecord := len(b) > recordLayerHeaderLen+1 && b[0] == contentType
		splitTLSRecord := c.splitRecord && isTLSRecord
		splitStart := 0
		var splitIndexes []int
		if isTLSRecord {
			splitStart = recordLayerHeaderLen
			if c.fragmentMaxLen > 0 {
				splitIndexes = computeFallbackSplitIndexes(b, splitStart, c.fragmentMinLen, c.fragmentMaxLen, 0)
			} else if serverName := IndexTLSServerName(b); serverName != nil {
				splitIndexes = computeSNISplitIndexes(b, serverName)
			} else {
				// Generalized fallback when cleartext SNI cannot be indexed (e.g. ECH / non-SNI ClientHello).
				maxSplits := 0
				minLen, maxLen := defaultFallbackChunkMin, defaultFallbackChunkMax
				if c.splitPacket {
					maxSplits = defaultPacketMaxSplits
					payloadLen := len(b) - recordLayerHeaderLen
					targetChunk := payloadLen / (maxSplits + 1)
					if targetChunk > minLen {
						minLen = targetChunk / 2
						if minLen < 16 {
							minLen = 16
						}
						maxLen = targetChunk + targetChunk/2
						if maxLen < minLen {
							maxLen = minLen
						}
					}
				}
				splitIndexes = computeFallbackSplitIndexes(b, splitStart, minLen, maxLen, maxSplits)
			}
		} else if c.splitPacket && c.fragmentMaxLen > 0 && len(b) > 1 {
			// Orthogonal DialerOptions.Masks fragment also splits non-TLS first writes.
			splitIndexes = computeFallbackSplitIndexes(b, 0, c.fragmentMinLen, c.fragmentMaxLen, 0)
		}
		if splitTLSRecord && len(splitIndexes) > 0 {
			splitIndexes = enforceMaxChunkSplits(splitIndexes, recordLayerHeaderLen, len(b), maxTLSRecordPayloadLen)
		}
		if len(splitIndexes) > 0 {
			if c.splitPacket && c.tcpConn != nil {
				if err = c.tcpConn.SetNoDelay(true); err != nil {
					return
				}
			}
			var buffer bytes.Buffer
			for i := 0; i <= len(splitIndexes); i++ {
				var payload []byte
				switch i {
				case 0:
					payload = b[:splitIndexes[0]]
					if splitTLSRecord {
						payload = payload[recordLayerHeaderLen:]
					}
				case len(splitIndexes):
					payload = b[splitIndexes[len(splitIndexes)-1]:]
				default:
					payload = b[splitIndexes[i-1]:splitIndexes[i]]
				}
				if splitTLSRecord {
					if c.splitPacket {
						buffer.Reset()
					}
					payloadLen := uint16(len(payload))
					buffer.Write(b[:3])
					binary.Write(&buffer, binary.BigEndian, payloadLen)
					buffer.Write(payload)
					if c.splitPacket {
						payload = buffer.Bytes()
					}
				}
				if c.splitPacket {
					waitDelay := c.pickIntervalDelay()
					if c.tcpConn != nil && i != len(splitIndexes) && c.fragmentMaxWait == 0 {
						err = writeAndWaitAck(c.ctx, c.tcpConn, payload, waitDelay)
						if err != nil {
							return
						}
					} else {
						_, err = c.Conn.Write(payload)
						if err != nil {
							return
						}
						if i != len(splitIndexes) && waitDelay > 0 {
							time.Sleep(waitDelay)
						}
					}
				}
			}
			if splitTLSRecord && !c.splitPacket {
				_, err = c.Conn.Write(buffer.Bytes())
				if err != nil {
					return
				}
			}
			if c.splitPacket && c.tcpConn != nil {
				if err = c.tcpConn.SetNoDelay(false); err != nil {
					return
				}
			}
			return len(b), nil
		}
	}
	return c.Conn.Write(b)
}

func (c *Conn) pickIntervalDelay() time.Duration {
	if c.fragmentMaxWait > 0 {
		if c.fragmentMinWait >= c.fragmentMaxWait {
			return c.fragmentMinWait
		}
		diff := int64(c.fragmentMaxWait - c.fragmentMinWait)
		return c.fragmentMinWait + time.Duration(rand.Int63n(diff+1))
	}
	return c.fallbackDelay
}

func computeSNISplitIndexes(b []byte, serverName *MyServerName) []int {
	splits := strings.Split(serverName.ServerName, ".")
	currentIndex := serverName.Index
	if publicSuffix := publicsuffix.List.PublicSuffix(serverName.ServerName); publicSuffix != "" {
		suffixCount := strings.Count(publicSuffix, ".") + 1
		if len(splits) > suffixCount {
			splits = splits[:len(splits)-suffixCount]
		} else if len(splits) > 1 {
			splits = splits[:len(splits)-1]
		}
	}
	if len(splits) > 1 && splits[0] == "..." {
		currentIndex += len(splits[0]) + 1
		splits = splits[1:]
	}
	var splitIndexes []int
	for i, split := range splits {
		if len(split) > 1 {
			splitAt := 1 + rand.Intn(len(split)-1)
			idx := currentIndex + splitAt
			if idx > recordLayerHeaderLen && idx < len(b) {
				splitIndexes = append(splitIndexes, idx)
			}
		} else if len(split) == 1 && i > 0 {
			if currentIndex > recordLayerHeaderLen && currentIndex < len(b) {
				splitIndexes = append(splitIndexes, currentIndex)
			}
		}
		currentIndex += len(split)
		if i != len(splits)-1 {
			currentIndex++
		}
	}
	if len(splitIndexes) == 0 && serverName.Length > 1 {
		mid := serverName.Index + serverName.Length/2
		if mid > recordLayerHeaderLen && mid < len(b) {
			splitIndexes = append(splitIndexes, mid)
		}
	}
	return normalizeSplitIndexes(splitIndexes, len(b))
}

func computeFallbackSplitIndexes(b []byte, startOffset, minLen, maxLen, maxSplits int) []int {
	if len(b) <= startOffset+1 {
		return nil
	}
	if minLen <= 0 {
		minLen = 1
	}
	if maxLen < minLen {
		maxLen = minLen
	}
	var splitIndexes []int
	pos := startOffset
	for pos < len(b)-1 {
		if maxSplits > 0 && len(splitIndexes) >= maxSplits {
			break
		}
		step := minLen
		if maxLen > minLen {
			step += rand.Intn(maxLen - minLen + 1)
		}
		next := pos + step
		if next >= len(b) {
			break
		}
		splitIndexes = append(splitIndexes, next)
		pos = next
	}
	return normalizeSplitIndexesFrom(splitIndexes, startOffset, len(b))
}

func enforceMaxChunkSplits(indexes []int, startOffset, totalLen, maxChunk int) []int {
	if maxChunk <= 0 || len(indexes) == 0 {
		return indexes
	}
	var result []int
	prev := startOffset
	for _, idx := range indexes {
		for idx-prev > maxChunk {
			prev += maxChunk
			result = append(result, prev)
		}
		result = append(result, idx)
		prev = idx
	}
	for totalLen-prev > maxChunk {
		prev += maxChunk
		result = append(result, prev)
	}
	return normalizeSplitIndexesFrom(result, startOffset, totalLen)
}

func normalizeSplitIndexes(indexes []int, totalLen int) []int {
	return normalizeSplitIndexesFrom(indexes, recordLayerHeaderLen, totalLen)
}

func normalizeSplitIndexesFrom(indexes []int, minOffset, totalLen int) []int {
	if len(indexes) == 0 {
		return nil
	}
	sort.Ints(indexes)
	out := indexes[:0]
	prev := minOffset
	for _, idx := range indexes {
		if idx > prev && idx < totalLen {
			out = append(out, idx)
			prev = idx
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (c *Conn) ReaderReplaceable() bool {
	return true
}

func (c *Conn) WriterReplaceable() bool {
	return c.firstPacketWritten
}

func (c *Conn) Upstream() any {
	return c.Conn
}
