package tls

import (
	"context"
	"crypto/tls"

	E "github.com/sagernet/sing/common/exceptions"
	aTLS "github.com/sagernet/sing/common/tls"
)

type (
	Config                 = aTLS.Config
	ConfigCompat           = aTLS.ConfigCompat
	ServerConfig           = aTLS.ServerConfig
	ServerConfigCompat     = aTLS.ServerConfigCompat
	WithSessionIDGenerator = aTLS.WithSessionIDGenerator
	Conn                   = aTLS.Conn

	STDConfig       = tls.Config
	STDConn         = tls.Conn
	ConnectionState = tls.ConnectionState
	CurveID         = tls.CurveID
)

// UTLSFingerprintProvider reports the browser client and version configured on a
// TLS config when uTLS fingerprint imitation is enabled.
type UTLSFingerprintProvider interface {
	UTLSFingerprint() (client string, version string, ok bool)
}

// UTLSFingerprint resolves the uTLS client and version name from config, or
// returns ok=false when config does not use uTLS.
func UTLSFingerprint(config Config) (client string, version string, ok bool) {
	if provider, isProvider := config.(UTLSFingerprintProvider); isProvider {
		return provider.UTLSFingerprint()
	}
	return "", "", false
}

// QUICSTDConfigProvider returns a *STDConfig usable by QUIC engines (without
// requiring callers to invoke STDConfig() directly on uTLS client configs).
type QUICSTDConfigProvider interface {
	STDConfigForQUIC() (*STDConfig, error)
}

// QUICSTDConfigContextProvider resolves a *STDConfig usable by QUIC engines
// using caller context (for example, dynamic DNS ECH resolution).
type QUICSTDConfigContextProvider interface {
	STDConfigForQUICContext(ctx context.Context) (*STDConfig, error)
}

// STDConfigForQUIC extracts a standard *tls.Config compatible with QUIC from
// config, converting uTLS client configs cleanly when supported.
func STDConfigForQUIC(config Config) (*STDConfig, error) {
	return STDConfigForQUICContext(context.Background(), config)
}

// STDConfigForQUICContext extracts a standard *tls.Config compatible with QUIC
// from config using ctx for dynamic resolution (such as DNS ECH records).
func STDConfigForQUICContext(ctx context.Context, config Config) (*STDConfig, error) {
	if config == nil {
		return nil, E.New("missing TLS config")
	}
	if provider, isProvider := config.(QUICSTDConfigContextProvider); isProvider {
		return provider.STDConfigForQUICContext(ctx)
	}
	if provider, isProvider := config.(QUICSTDConfigProvider); isProvider {
		return provider.STDConfigForQUIC()
	}
	return config.STDConfig()
}

// ECHRefreshProvider refreshes dynamic ECH configuration (for example,
// bypassing cached DNS TTL after a server ECH rejection).
type ECHRefreshProvider interface {
	RefreshECHConfigList(ctx context.Context) ([]byte, error)
}

// RefreshECHConfigList forces a fresh lookup of dynamic ECH configuration when
// supported by config.
func RefreshECHConfigList(ctx context.Context, config Config) ([]byte, bool, error) {
	if provider, isProvider := config.(ECHRefreshProvider); isProvider {
		list, err := provider.RefreshECHConfigList(ctx)
		return list, true, err
	}
	return nil, false, nil
}

// QUICCapabilityProvider reports whether a TLS config (for example, REALITY or
// a system TLS engine) supports QUIC / HTTP/3 handshakes.
type QUICCapabilityProvider interface {
	SupportsQUIC() bool
}

// SupportsQUIC reports whether config supports QUIC / HTTP/3 handshakes.
func SupportsQUIC(config Config) bool {
	if config == nil {
		return false
	}
	if provider, isProvider := config.(QUICCapabilityProvider); isProvider {
		return provider.SupportsQUIC()
	}
	return true
}

func ParseTLSVersion(version string) (uint16, error) {
	switch version {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, E.New("unknown tls version:", version)
	}
}
