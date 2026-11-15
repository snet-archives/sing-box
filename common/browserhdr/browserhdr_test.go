package browserhdr

import (
	"net/http"
	"strings"
	"testing"
)

func TestApplyForUTLS(t *testing.T) {
	hdr := make(http.Header)
	ApplyForUTLS(hdr, "Chrome", "133", "nav")
	if got := hdr.Get("User-Agent"); !strings.Contains(got, "Chrome/133.0.0.0") {
		t.Fatalf("unexpected Chrome UA: %q", got)
	}
	chUA := hdr["Sec-CH-UA"]
	if len(chUA) == 0 || !strings.Contains(chUA[0], `"Google Chrome";v="133"`) {
		t.Fatalf("unexpected Sec-CH-UA: %v", hdr)
	}
	if mob := hdr["Sec-CH-UA-Mobile"]; len(mob) == 0 || mob[0] != "?0" {
		t.Fatalf("unexpected Sec-CH-UA-Mobile: %v", mob)
	}
	if got := hdr.Get("Sec-Fetch-Mode"); got != "navigate" {
		t.Fatalf("expected navigate, got %q", got)
	}

	ffHdr := make(http.Header)
	ApplyForUTLS(ffHdr, "Firefox", "148", "fetch")
	if got := ffHdr.Get("User-Agent"); !strings.Contains(got, "Firefox/148.0") {
		t.Fatalf("unexpected Firefox UA: %q", got)
	}
	if _, ok := ffHdr["Sec-CH-UA"]; ok {
		t.Fatal("Firefox must not send Sec-CH-UA")
	}
	if got := ffHdr.Get("Priority"); got != "u=4" {
		t.Fatalf("expected Firefox fetch priority u=4, got %q", got)
	}

	sfHdr := make(http.Header)
	ApplyForUTLS(sfHdr, "Safari", "26.3", "ws")
	if got := sfHdr.Get("User-Agent"); !strings.Contains(got, "Version/26.3 Safari/605.1.15") {
		t.Fatalf("unexpected Safari UA: %q", got)
	}
	if got := sfHdr.Get("Sec-Fetch-Dest"); got != "websocket" {
		t.Fatalf("expected Safari ws Sec-Fetch-Dest=websocket, got %q", got)
	}
}

func TestTryDefaultHeadersWithCustomUA(t *testing.T) {
	hdr := make(http.Header)
	hdr.Set("User-Agent", "MyCustomClient/1.0")
	TryDefaultHeadersWith(hdr, "fetch")
	if got := hdr.Get("User-Agent"); got != "MyCustomClient/1.0" {
		t.Fatalf("custom UA overwritten: %q", got)
	}
	if got := hdr.Get("Sec-Fetch-Mode"); got != "cors" {
		t.Fatalf("expected cors, got %q", got)
	}

	goHdr := make(http.Header)
	goHdr.Set("User-Agent", "golang")
	TryDefaultHeadersWith(goHdr, "fetch")
	if _, exists := goHdr["User-Agent"]; exists {
		t.Fatal("golang token should delete explicit User-Agent")
	}
}
