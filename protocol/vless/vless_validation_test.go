package vless

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestVLESSVisionValidationFailFast(t *testing.T) {
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()

	// Case 1: Vision with Multiplex enabled
	_, err := NewOutbound(ctx, nil, logger, "test-out", option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Flow:          "xtls-rprx-vision",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "example.com",
			},
		},
		Multiplex: &option.OutboundMultiplexOptions{
			Enabled: true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "flow is incompatible with multiplex") {
		t.Fatalf("expected multiplex rejection, got: %v", err)
	}

	// Case 2: Vision with custom transport
	_, err = NewOutbound(ctx, nil, logger, "test-out", option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Flow:          "xtls-rprx-vision",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "example.com",
			},
		},
		Transport: &option.V2RayTransportOptions{
			Type: "ws",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "flow is incompatible with custom transport") {
		t.Fatalf("expected custom transport rejection, got: %v", err)
	}

	// Case 3: Vision without TLS
	_, err = NewOutbound(ctx, nil, logger, "test-out", option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Flow:          "xtls-rprx-vision",
	})
	if err == nil || !strings.Contains(err.Error(), "flow requires TLS to be enabled") {
		t.Fatalf("expected missing TLS rejection, got: %v", err)
	}
}
