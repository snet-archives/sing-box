package tls

import (
	"net/http"

	"github.com/sagernet/sing-box/common/browserhdr"

	"golang.org/x/net/http2"
)

// HTTP2Fingerprint returns an http2.FingerprintProfile matching config's uTLS
// browser fingerprint, or nil when config does not use uTLS.
func HTTP2Fingerprint(config Config) *http2.FingerprintProfile {
	return HTTP2FingerprintForHeaders(config, nil, "")
}

// HTTP2FingerprintForHeaders returns an http2.FingerprintProfile matching
// config's uTLS fingerprint (or User-Agent in header if config does not use uTLS)
// with regular header ordering aligned to variant ("fetch" or "document").
func HTTP2FingerprintForHeaders(config Config, header http.Header, variant string) *http2.FingerprintProfile {
	return HTTP2FingerprintForSources(header, variant, config)
}

// HTTP2FingerprintForSources resolves the first UTLSFingerprintProvider among
// sources (e.g. tls.Config or tls.Dialer) and returns a matching HTTP/2 profile,
// falling back to User-Agent inspection on header when no uTLS provider exists.
func HTTP2FingerprintForSources(header http.Header, variant string, sources ...any) *http2.FingerprintProfile {
	for _, src := range sources {
		if src == nil {
			continue
		}
		if provider, isProvider := src.(UTLSFingerprintProvider); isProvider {
			if client, version, ok := provider.UTLSFingerprint(); ok {
				return browserhdr.HTTP2Fingerprint(header, client, version, variant)
			}
		}
	}
	return browserhdr.HTTP2Fingerprint(header, "", "", variant)
}
