//go:build go1.24

package tls

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
)

type mockDNSRouter struct {
	adapter.DNSRouter
	calls          atomic.Int32
	lastPaddingLen atomic.Int32
	handler        func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error)
}

func (m *mockDNSRouter) Exchange(ctx context.Context, message *mDNS.Msg, _ adapter.DNSQueryOptions) (*mDNS.Msg, error) {
	m.calls.Add(1)
	if opt := message.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if pad, ok := o.(*mDNS.EDNS0_PADDING); ok {
				m.lastPaddingLen.Store(int32(len(pad.Padding)))
			}
		}
	}
	return m.handler(ctx, message)
}

func makeECHDNSResponse(qname string, ttl uint32, echPayload []byte) *mDNS.Msg {
	resp := &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			Response: true,
			Rcode:    mDNS.RcodeSuccess,
		},
	}
	if echPayload != nil {
		resp.Answer = []mDNS.RR{
			&mDNS.HTTPS{
				SVCB: mDNS.SVCB{
					Hdr: mDNS.RR_Header{
						Name:   mDNS.Fqdn(qname),
						Rrtype: mDNS.TypeHTTPS,
						Class:  mDNS.ClassINET,
						Ttl:    ttl,
					},
					Priority: 1,
					Target:   ".",
					Value: []mDNS.SVCBKeyValue{
						&mDNS.SVCBECHConfig{ECH: echPayload},
					},
				},
			},
		}
	}
	return resp
}

func newTestECHClientConfig(t *testing.T, router adapter.DNSRouter) *ECHClientConfig {
	t.Helper()
	base, err := NewSTDClient(context.Background(), logger.NOP(), "example.com", option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &ECHClientConfig{
		ECHCapableConfig: base.(ECHCapableConfig),
		dnsRouter:        router,
		queryServerName:  "example.com",
		cache:            &echConfigCache{},
	}
}

func TestECHEDNS0PaddingAndStaleWhileRevalidateRace(t *testing.T) {
	refreshStarted := make(chan struct{})
	refreshRelease := make(chan struct{})
	var phase atomic.Int32

	dnsMock := &mockDNSRouter{}
	dnsMock.handler = func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
		p := phase.Load()
		if p == 0 {
			// TTL = 0s so it immediately enters stale-while-revalidate grace window
			return makeECHDNSResponse("example.com", 0, []byte("ech-v1")), nil
		}
		select {
		case <-refreshStarted:
		default:
			close(refreshStarted)
		}
		<-refreshRelease
		return makeECHDNSResponse("example.com", 60, []byte("ech-v2")), nil
	}

	cfg := newTestECHClientConfig(t, dnsMock)

	// 1. Initial sync fetch populates v1 and validates EDNS0_PADDING 100..300
	got, err := cfg.resolveConfigList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ech-v1" {
		t.Fatalf("expected ech-v1, got %q", got)
	}
	padLen := dnsMock.lastPaddingLen.Load()
	if padLen < 100 || padLen > 300 {
		t.Fatalf("expected EDNS0_PADDING in [100, 300], got %d", padLen)
	}
	if calls := dnsMock.calls.Load(); calls != 1 {
		t.Fatalf("expected 1 DNS call, got %d", calls)
	}

	// 2. Concurrent resolve calls during 4h grace window must NOT block and must trigger only 1 background refresh
	phase.Store(1)
	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			cloned := cfg.Clone().(*ECHClientConfig)
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()
			if idx%2 == 0 {
				_, err := cloned.fetchAndHandshake(context.Background(), c1)
				if err != nil {
					t.Errorf("worker %d fetchAndHandshake error: %v", idx, err)
				}
			} else {
				val, err := cloned.resolveConfigList(context.Background())
				if err != nil || string(val) != "ech-v1" {
					t.Errorf("worker %d unexpected resolve result: %q %v", idx, val, err)
				}
			}
		}(i)
	}
	wg.Wait()

	select {
	case <-refreshStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("background refresh did not start")
	}
	if calls := dnsMock.calls.Load(); calls != 2 {
		t.Fatalf("expected exactly 2 total DNS calls (single background TryLock), got %d", calls)
	}

	close(refreshRelease)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		val, err := cfg.resolveConfigList(context.Background())
		if err == nil && string(val) == "ech-v2" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("cache did not update to ech-v2 after background refresh")
}

func TestECHFailClosedWhenNoRecordReturned(t *testing.T) {
	dnsMock := &mockDNSRouter{}
	dnsMock.handler = func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
		return makeECHDNSResponse("example.com", 60, nil), nil
	}
	cfg := newTestECHClientConfig(t, dnsMock)
	if _, err := cfg.resolveConfigList(context.Background()); err == nil {
		t.Fatal("expected fail-closed error when HTTPS record has no ECH param")
	}
}

func TestECHSTDConfigForQUICContextResolvesAndCachesDNS(t *testing.T) {
	t.Parallel()

	payload := []byte("quic-ech-dns-config-v1")
	dnsMock := &mockDNSRouter{}
	dnsMock.handler = func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
		return makeECHDNSResponse("example.com", 60, payload), nil
	}

	cfg := newTestECHClientConfig(t, dnsMock)
	stdCfg, err := STDConfigForQUICContext(context.Background(), cfg)
	if err != nil {
		t.Fatalf("STDConfigForQUICContext failed: %v", err)
	}
	if string(stdCfg.EncryptedClientHelloConfigList) != string(payload) {
		t.Fatalf("expected QUIC STDConfig ECH list %q, got %q", payload, stdCfg.EncryptedClientHelloConfigList)
	}
	// Base config must remain untouched so concurrent QUIC/TLS dials never alias c.config.
	if len(cfg.ECHCapableConfig.ECHConfigList()) != 0 {
		t.Fatalf("expected underlying ECHCapableConfig list untouched, got %x", cfg.ECHCapableConfig.ECHConfigList())
	}
	if calls := dnsMock.calls.Load(); calls != 1 {
		t.Fatalf("expected 1 DNS ECH query, got %d", calls)
	}

	// Second resolution and kTLS wrapper must hit cache without extra DNS queries.
	wrapped := &KTLSClientConfig{Config: cfg}
	stdCfg2, err := STDConfigForQUICContext(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("wrapped STDConfigForQUICContext failed: %v", err)
	}
	if string(stdCfg2.EncryptedClientHelloConfigList) != string(payload) {
		t.Fatalf("expected cached ECH list %q, got %q", payload, stdCfg2.EncryptedClientHelloConfigList)
	}
	if calls := dnsMock.calls.Load(); calls != 1 {
		t.Fatalf("expected cached DNS hit without extra query, got %d calls", calls)
	}
}

func TestECHRefreshECHConfigListBypassesCacheAndUpdatesKTLS(t *testing.T) {
	t.Parallel()

	var phase atomic.Int32
	v1 := []byte("quic-ech-v1")
	v2 := []byte("quic-ech-rotated-v2")
	dnsMock := &mockDNSRouter{}
	dnsMock.handler = func(ctx context.Context, msg *mDNS.Msg) (*mDNS.Msg, error) {
		if phase.Load() == 0 {
			return makeECHDNSResponse("example.com", 300, v1), nil
		}
		return makeECHDNSResponse("example.com", 300, v2), nil
	}

	cfg := newTestECHClientConfig(t, dnsMock)
	wrapped := &KTLSClientConfig{Config: cfg}

	stdCfg1, err := STDConfigForQUICContext(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("initial STDConfigForQUICContext failed: %v", err)
	}
	if string(stdCfg1.EncryptedClientHelloConfigList) != string(v1) {
		t.Fatalf("expected initial ECH list %q, got %q", v1, stdCfg1.EncryptedClientHelloConfigList)
	}

	// Simulate key rotation while v1 still has ~300s TTL remaining in cache.
	phase.Store(1)
	refreshed, supported, err := RefreshECHConfigList(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("RefreshECHConfigList failed: %v", err)
	}
	if !supported {
		t.Fatal("expected KTLSClientConfig wrapping ECHClientConfig to support RefreshECHConfigList")
	}
	if string(refreshed) != string(v2) {
		t.Fatalf("expected refreshed ECH list %q, got %q", v2, refreshed)
	}
	if calls := dnsMock.calls.Load(); calls != 2 {
		t.Fatalf("expected forced refresh DNS query, got %d calls", calls)
	}

	// Subsequent STDConfigForQUICContext calls must immediately observe rotated v2 from cache.
	stdCfg2, err := STDConfigForQUICContext(context.Background(), wrapped)
	if err != nil {
		t.Fatalf("post-refresh STDConfigForQUICContext failed: %v", err)
	}
	if string(stdCfg2.EncryptedClientHelloConfigList) != string(v2) {
		t.Fatalf("expected cached rotated ECH list %q, got %q", v2, stdCfg2.EncryptedClientHelloConfigList)
	}
	if calls := dnsMock.calls.Load(); calls != 2 {
		t.Fatalf("expected cache hit after refresh, got %d calls", calls)
	}
}
