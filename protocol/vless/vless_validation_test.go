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

func TestVLESSVisionOutboundPositive(t *testing.T) {
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()

	out, err := NewOutbound(ctx, nil, logger, "test-out", option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 443},
		Flow:          "xtls-rprx-vision",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: "example.com",
			},
		},
	})
	if err != nil {
		t.Fatalf("expected valid vision outbound to succeed, got: %v", err)
	}
	if out == nil {
		t.Fatalf("expected non-nil outbound")
	}
}

func TestVLESSVisionInboundValidationFailFast(t *testing.T) {
	ctx := context.Background()
	logger := log.NewNOPFactory().Logger()

	// Case 1: Inbound Vision with Multiplex enabled
	_, err := NewInbound(ctx, nil, logger, "test-in", option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: 443},
		Users: []option.VLESSUser{
			{Name: "user1", UUID: "a8098c1a-f86e-11da-bd1a-00112444be1e", Flow: "xtls-rprx-vision"},
		},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled: true,
			},
		},
		Multiplex: &option.InboundMultiplexOptions{
			Enabled: true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "flow is incompatible with multiplex") {
		t.Fatalf("expected multiplex rejection, got: %v", err)
	}

	// Case 2: Inbound Vision with custom transport
	_, err = NewInbound(ctx, nil, logger, "test-in", option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: 443},
		Users: []option.VLESSUser{
			{Name: "user1", UUID: "a8098c1a-f86e-11da-bd1a-00112444be1e", Flow: "xtls-rprx-vision"},
		},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
			TLS: &option.InboundTLSOptions{
				Enabled: true,
			},
		},
		Transport: &option.V2RayTransportOptions{
			Type: "ws",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "flow is incompatible with custom transport") {
		t.Fatalf("expected custom transport rejection, got: %v", err)
	}

	// Case 3: Inbound Vision without TLS
	_, err = NewInbound(ctx, nil, logger, "test-in", option.VLESSInboundOptions{
		ListenOptions: option.ListenOptions{ListenPort: 443},
		Users: []option.VLESSUser{
			{Name: "user1", UUID: "a8098c1a-f86e-11da-bd1a-00112444be1e", Flow: "xtls-rprx-vision"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "flow requires TLS to be enabled") {
		t.Fatalf("expected missing TLS rejection, got: %v", err)
	}
}
