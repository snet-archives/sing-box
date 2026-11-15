package browserhdr

import (
	"net/http"
	"slices"
	"strings"

	"golang.org/x/net/http2"
)

var (
	chromeDocHeaderOrder = []string{
		"cache-control",
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"upgrade-insecure-requests",
		"user-agent",
		"accept",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-user",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"accept-language",
		"cookie",
		"priority",
	}

	chromeFetchHeaderOrder = []string{
		"content-length",
		"sec-ch-ua-platform",
		"user-agent",
		"sec-ch-ua",
		"content-type",
		"sec-ch-ua-mobile",
		"accept",
		"origin",
		"sec-fetch-site",
		"sec-fetch-mode",
		"sec-fetch-dest",
		"referer",
		"accept-encoding",
		"accept-language",
		"cookie",
		"priority",
	}

	firefoxDocHeaderOrder = []string{
		"user-agent",
		"accept",
		"accept-language",
		"accept-encoding",
		"referer",
		"upgrade-insecure-requests",
		"sec-fetch-dest",
		"sec-fetch-mode",
		"sec-fetch-site",
		"sec-fetch-user",
		"priority",
		"cookie",
		"te",
	}

	firefoxFetchHeaderOrder = []string{
		"user-agent",
		"accept",
		"accept-language",
		"accept-encoding",
		"referer",
		"content-type",
		"content-length",
		"origin",
		"sec-fetch-dest",
		"sec-fetch-mode",
		"sec-fetch-site",
		"priority",
		"cookie",
		"te",
	}

	safariDocHeaderOrder = []string{
		"sec-fetch-dest",
		"user-agent",
		"accept",
		"referer",
		"sec-fetch-site",
		"sec-fetch-mode",
		"accept-language",
		"priority",
		"accept-encoding",
		"cookie",
	}

	safariFetchHeaderOrder = []string{
		"content-type",
		"accept",
		"sec-fetch-site",
		"origin",
		"sec-fetch-mode",
		"user-agent",
		"referer",
		"accept-language",
		"accept-encoding",
		"sec-fetch-dest",
		"priority",
		"cookie",
	}
)

// ResolveProfileName resolves a browser profile name ("chrome", "edge",
// "firefox", "safari", "ios", "android") from utlsClient or the request's
// User-Agent header. Returns empty string if neither identifies a browser.
func ResolveProfileName(header http.Header, utlsClient string) string {
	client := strings.ToLower(strings.TrimSpace(utlsClient))
	if client != "" && client != "golang" {
		switch {
		case strings.Contains(client, "firefox"):
			return "firefox"
		case strings.Contains(client, "ios"):
			return "ios"
		case strings.Contains(client, "safari"):
			return "safari"
		case strings.Contains(client, "edge"):
			return "edge"
		case strings.Contains(client, "android"):
			return "android"
		default:
			return "chrome"
		}
	}
	if header == nil {
		return ""
	}
	ua := strings.ToLower(header.Get("User-Agent"))
	switch {
	case ua == "", strings.Contains(ua, "go-http-client"):
		return ""
	case strings.Contains(ua, "firefox/"):
		return "firefox"
	case strings.Contains(ua, "edg/"):
		return "edge"
	case strings.Contains(ua, "iphone"), strings.Contains(ua, "ipad"):
		return "ios"
	case strings.Contains(ua, "android") && strings.Contains(ua, "chrome/"):
		return "android"
	case strings.Contains(ua, "chrome/"), strings.Contains(ua, "crios/"):
		return "chrome"
	case strings.Contains(ua, "safari/"):
		return "safari"
	default:
		return ""
	}
}

// HTTP2HeaderOrder returns the browser-aligned lowercase regular HTTP/2 header
// wire order for the given client and request variant ("fetch" or "document").
func HTTP2HeaderOrder(client, variant string) []string {
	c := strings.ToLower(strings.TrimSpace(client))
	isFetch := strings.EqualFold(strings.TrimSpace(variant), "fetch")
	switch {
	case strings.Contains(c, "firefox"):
		if isFetch {
			return slices.Clone(firefoxFetchHeaderOrder)
		}
		return slices.Clone(firefoxDocHeaderOrder)
	case strings.Contains(c, "safari") || strings.Contains(c, "ios"):
		if isFetch {
			return slices.Clone(safariFetchHeaderOrder)
		}
		return slices.Clone(safariDocHeaderOrder)
	case c == "":
		return nil
	default:
		if isFetch {
			return slices.Clone(chromeFetchHeaderOrder)
		}
		return slices.Clone(chromeDocHeaderOrder)
	}
}

// HTTP2Fingerprint constructs a complete http2.FingerprintProfile aligned to
// the uTLS fingerprint (if present) or User-Agent header, applying variant-specific
// regular header ordering ("fetch" or "document"). Returns nil when neither identifies a browser.
func HTTP2Fingerprint(header http.Header, utlsClient, utlsVersion, variant string) *http2.FingerprintProfile {
	var fp *http2.FingerprintProfile
	if c := strings.TrimSpace(utlsClient); c != "" && !strings.EqualFold(c, "golang") {
		fp = http2.FingerprintForUTLS(c, utlsVersion)
	} else if resolved := ResolveProfileName(header, ""); resolved != "" {
		fp = http2.FingerprintForName(resolved)
	}
	if fp == nil {
		return nil
	}
	if order := HTTP2HeaderOrder(fp.Name, variant); len(order) > 0 {
		fp.HeaderOrder = order
	}
	return fp
}
