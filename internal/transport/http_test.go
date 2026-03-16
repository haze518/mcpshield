package transport_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/haze518/mcpshield/internal/transport"
)

func TestNewHTTPServerAppliesConfiguredTimeouts(t *testing.T) {
	srv, err := transport.NewHTTPServer(":8080", http.NewServeMux(), transport.HTTPServerConfig{
		ReadTimeout:  11 * time.Second,
		WriteTimeout: 17 * time.Second,
		IdleTimeout:  29 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewHTTPServer: %v", err)
	}

	if srv.ReadTimeout != 11*time.Second {
		t.Fatalf("ReadTimeout: want 11s, got %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout != 17*time.Second {
		t.Fatalf("WriteTimeout: want 17s, got %v", srv.WriteTimeout)
	}
	if srv.IdleTimeout != 29*time.Second {
		t.Fatalf("IdleTimeout: want 29s, got %v", srv.IdleTimeout)
	}
}

func TestNewHTTPServerRejectsInvalidConfig(t *testing.T) {
	_, err := transport.NewHTTPServer(":8080", http.NewServeMux(), transport.HTTPServerConfig{})
	if err == nil {
		t.Fatal("expected invalid HTTP server config to be rejected")
	}
}
