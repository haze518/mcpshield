package transport_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/haze518/mcpshield/internal/transport"
)

// decodeRPCID extracts the JSON-RPC id from an incoming request body.
func decodeRPCID(r *http.Request) json.RawMessage {
	var req struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	return req.ID
}

// ---------------------------------------------------------------------------
// E2: HTTP status validation
// ---------------------------------------------------------------------------

func TestNon2xxResponseReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := transport.NewMCPHTTPClient("test", srv.URL, nil)
	_, err := client.ToolsList(context.Background())
	if err == nil {
		t.Fatal("expected error for non-2xx response, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected 'HTTP 500' in error, got: %v", err)
	}
}

func TestNon2xxIncrementsProtocolErrorMetric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	rec := &metricsRecorder{}
	client := transport.NewMCPHTTPClient("test", srv.URL, nil)
	client.SetMetrics(rec)

	_, err := client.ToolsList(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if rec.protocolErrors != 1 {
		t.Errorf("expected 1 protocol error metric, got %d", rec.protocolErrors)
	}
}

// ---------------------------------------------------------------------------
// E2: JSON-RPC protocol validation
// ---------------------------------------------------------------------------

func TestWrongJSONRPCVersionReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := decodeRPCID(r)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "1.0", // wrong version
			"id":      id,
			"result":  map[string]any{"tools": []any{}},
		})
	}))
	defer srv.Close()

	client := transport.NewMCPHTTPClient("test", srv.URL, nil)
	_, err := client.ToolsList(context.Background())
	if err == nil {
		t.Fatal("expected error for wrong jsonrpc version, got nil")
	}
	if !strings.Contains(err.Error(), "jsonrpc") {
		t.Errorf("expected 'jsonrpc' in error, got: %v", err)
	}
}

func TestIDMismatchReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      9999, // wrong ID
			"result":  map[string]any{"tools": []any{}},
		})
	}))
	defer srv.Close()

	client := transport.NewMCPHTTPClient("test", srv.URL, nil)
	_, err := client.ToolsList(context.Background())
	if err == nil {
		t.Fatal("expected error for ID mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "ID mismatch") {
		t.Errorf("expected 'ID mismatch' in error, got: %v", err)
	}
}

func TestMissingResultAndErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := decodeRPCID(r)
		w.Header().Set("Content-Type", "application/json")
		// Valid jsonrpc + id but neither result nor error.
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
		})
	}))
	defer srv.Close()

	client := transport.NewMCPHTTPClient("test", srv.URL, nil)
	_, err := client.ToolsList(context.Background())
	if err == nil {
		t.Fatal("expected error for response with neither result nor error, got nil")
	}
	if !strings.Contains(err.Error(), "neither result nor error") {
		t.Errorf("expected 'neither result nor error' in error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// E3: Response size limit
// ---------------------------------------------------------------------------

func TestResponseTooLargeReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := decodeRPCID(r)
		w.Header().Set("Content-Type", "application/json")
		// Write a response that exceeds the default 4 MiB limit.
		w.Write([]byte(`{"jsonrpc":"2.0","id":`))
		w.Write(id)
		w.Write([]byte(`,"result":{"tools":[`))
		// Each tool entry is ~1051 bytes; 5000 of them ≈ 5.25 MiB.
		toolJSON := []byte(`{"name":"` + strings.Repeat("x", 1024) + `","description":""}`)
		for i := 0; i < 5000; i++ {
			if i > 0 {
				w.Write([]byte(","))
			}
			w.Write(toolJSON)
		}
		w.Write([]byte(`]}}`))
	}))
	defer srv.Close()

	client := transport.NewMCPHTTPClient("test", srv.URL, nil)
	_, err := client.ToolsList(context.Background())
	if err == nil {
		t.Fatal("expected error for oversized response, got nil")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("expected 'exceeded' in error, got: %v", err)
	}
}

func TestResponseTooLargeIncrementsMetric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := decodeRPCID(r)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":`))
		w.Write(id)
		w.Write([]byte(`,"result":{"tools":[`))
		toolJSON := []byte(`{"name":"` + strings.Repeat("x", 1024) + `","description":""}`)
		for i := 0; i < 5000; i++ {
			if i > 0 {
				w.Write([]byte(","))
			}
			w.Write(toolJSON)
		}
		w.Write([]byte(`]}}`))
	}))
	defer srv.Close()

	rec := &metricsRecorder{}
	client := transport.NewMCPHTTPClient("test", srv.URL, nil)
	client.SetMetrics(rec)

	_, err := client.ToolsList(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if rec.responseTooLarge != 1 {
		t.Errorf("expected 1 response-too-large metric, got %d", rec.responseTooLarge)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type metricsRecorder struct {
	protocolErrors  int
	responseTooLarge int
}

func (m *metricsRecorder) IncUpstreamProtocolError(_ string)  { m.protocolErrors++ }
func (m *metricsRecorder) IncUpstreamResponseTooLarge(_ string) { m.responseTooLarge++ }
