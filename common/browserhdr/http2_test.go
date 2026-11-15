package browserhdr

import (
	"net/http"
	"testing"
)

func TestResolveProfileNameAndHTTP2Fingerprint(t *testing.T) {
	hdr := make(http.Header)
	ApplyForUTLS(hdr, "Firefox", "120", "fetch")
	fp := HTTP2Fingerprint(hdr, "Firefox", "120", "fetch")
	if fp == nil || fp.Name != "firefox_120" {
		t.Fatalf("expected firefox_120 profile, got %#v", fp)
	}
	if len(fp.PseudoHeaderOrder) != 4 || fp.PseudoHeaderOrder[1] != ":path" {
		t.Fatalf("unexpected firefox pseudo order: %v", fp.PseudoHeaderOrder)
	}
	if len(fp.HeaderOrder) == 0 || fp.HeaderOrder[0] != "user-agent" {
		t.Fatalf("unexpected firefox fetch header order: %v", fp.HeaderOrder)
	}

	uaOnly := http.Header{"User-Agent": {safariUA(SafariVersion())}}
	fpUA := HTTP2Fingerprint(uaOnly, "", "", "document")
	if fpUA == nil || fpUA.Name != "safari" {
		t.Fatalf("expected safari profile from UA, got %#v", fpUA)
	}
	if fpUA.PseudoHeaderOrder[1] != ":scheme" {
		t.Fatalf("unexpected safari pseudo order: %v", fpUA.PseudoHeaderOrder)
	}

	goHdr := http.Header{"User-Agent": {"Go-http-client/2.0"}}
	if fpGo := HTTP2Fingerprint(goHdr, "", "", "fetch"); fpGo != nil {
		t.Fatalf("expected nil profile for Go-http-client without uTLS, got %#v", fpGo)
	}
}
