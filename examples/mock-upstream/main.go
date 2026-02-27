// Package main implements a minimal MCP-compatible HTTP server for local
// development and demo purposes. It exposes two deterministic tools:
//   - echo: returns its text argument unchanged
//   - time.now: returns the current UTC time as RFC3339
//
// Usage: go run ./examples/mock-upstream   (listens on :9090)
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// ---- JSON-RPC types -----------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ---- tool definitions ---------------------------------------------------

var toolList = []map[string]any{
	{
		"name":        "echo",
		"description": "Echoes the input text back unchanged",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"text": map[string]any{
					"type":        "string",
					"description": "Text to echo",
				},
			},
			"required": []string{"text"},
		},
	},
	{
		"name":        "time.now",
		"description": "Returns the current UTC time in RFC3339 format",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	},
}

// ---- handlers -----------------------------------------------------------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func errResp(id json.RawMessage, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func mcpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, errResp(json.RawMessage("null"), -32700, "parse error"))
		return
	}

	// Notifications have no id — acknowledge silently.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		writeJSON(w, rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "mock-upstream", "version": "0.1.0"},
			},
		})

	case "tools/list":
		writeJSON(w, rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{"tools": toolList},
		})

	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			writeJSON(w, errResp(req.ID, -32602, "invalid params"))
			return
		}

		var text string
		switch params.Name {
		case "echo":
			if v, ok := params.Arguments["text"]; ok {
				text = fmt.Sprintf("%v", v)
			} else {
				text = "(no text provided)"
			}
		case "time.now":
			text = time.Now().UTC().Format(time.RFC3339)
		default:
			writeJSON(w, errResp(req.ID, -32601, "tool not found: "+params.Name))
			return
		}

		writeJSON(w, rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": text},
				},
			},
		})

	default:
		writeJSON(w, errResp(req.ID, -32601, "method not found: "+req.Method))
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", mcpHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	addr := ":9090"
	log.Printf("mock-upstream listening on %s (tools: echo, time.now)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
