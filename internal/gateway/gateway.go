package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/haze518/mcpshield/internal/audit"
	"github.com/haze518/mcpshield/internal/auth"
	"github.com/haze518/mcpshield/internal/mcp"
	"github.com/haze518/mcpshield/internal/observability"
	"github.com/haze518/mcpshield/internal/policy"
	"github.com/haze518/mcpshield/internal/upstream"
)

const (
	requestTimeout  = 60 * time.Second
	protocolVersion = "2024-11-05"
	gatewayName     = "mcpshield"
	gatewayVersion  = "0.1.0"
	defaultMaxBody  = 1 << 20 // 1 MiB
)

type contextKey string

const clientIDKey contextKey = "clientID"

type Gateway struct {
	auth            auth.Authenticator
	policy          policy.Engine
	upstream        upstream.Manager
	audit           audit.Logger
	metrics         *observability.Registry
	maxRequestBytes int64
}

func New(a auth.Authenticator, p policy.Engine, u upstream.Manager, al audit.Logger) *Gateway {
	return &Gateway{
		auth:            a,
		policy:          p,
		upstream:        u,
		audit:           al,
		maxRequestBytes: defaultMaxBody,
	}
}

// SetMetrics wires an optional Prometheus metrics registry into the gateway.
func (g *Gateway) SetMetrics(r *observability.Registry) {
	g.metrics = r
}

// SetMaxRequestBytes overrides the default 1 MiB inbound body limit.
func (g *Gateway) SetMaxRequestBytes(n int64) {
	if n > 0 {
		g.maxRequestBytes = n
	}
}

// httpStatusForCode maps JSON-RPC error codes to HTTP status codes.
func httpStatusForCode(code int) int {
	switch code {
	case mcp.CodeParseError, mcp.CodeInvalidRequest, mcp.CodeInvalidParams:
		return http.StatusBadRequest
	case mcp.CodeMethodNotFound:
		return http.StatusNotFound
	case mcp.CodeUnauthorized:
		return http.StatusUnauthorized
	case mcp.CodeRateLimited:
		return http.StatusTooManyRequests
	case mcp.CodeServerError:
		return http.StatusInternalServerError
	default:
		// CodePolicyDenied and others → 200.
		return http.StatusOK
	}
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Serve Prometheus metrics without the JSON-RPC machinery.
	if r.Method == http.MethodGet && r.URL.Path == "/metrics" {
		if g.metrics != nil {
			g.metrics.Handler().ServeHTTP(w, r)
		} else {
			http.NotFound(w, r)
		}
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()

	// Enforce body size limit.
	r.Body = http.MaxBytesReader(w, r.Body, g.maxRequestBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// MaxBytesError means payload too large.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_ = json.NewEncoder(w).Encode(mcp.Response{
				JSONRPC: "2.0",
				ID:      mcp.NullID,
				Error:   &mcp.Error{Code: mcp.CodeInvalidRequest, Message: "request body too large"},
			})
			return
		}
		writeError(w, mcp.NullID, mcp.CodeParseError, "read error")
		return
	}

	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		writeError(w, mcp.NullID, mcp.CodeParseError, "empty body")
		return
	}

	// Phase 1: validate JSON syntax and detect trailing data.
	dec := json.NewDecoder(bytes.NewReader(body))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		writeError(w, mcp.NullID, mcp.CodeParseError, "parse error")
		return
	}
	if tok, err := dec.Token(); err != io.EOF || tok != nil {
		writeError(w, mcp.NullID, mcp.CodeParseError, "trailing data after JSON object")
		return
	}

	// Phase 2: check top-level JSON type.
	// Arrays (batch) and primitives (number/string/bool/null) are not valid MCP
	// requests. Both return CodeInvalidRequest (-32600) because the input is
	// well-formed JSON — just the wrong type.
	switch raw[0] {
	case '[':
		writeError(w, mcp.NullID, mcp.CodeInvalidRequest, "batch not supported")
		return
	case '{':
		// valid MCP request object — continue
	default:
		// Valid JSON primitive: not a request object.
		writeError(w, mcp.NullID, mcp.CodeInvalidRequest, "invalid request")
		return
	}

	// Phase 3: decode the object as an MCP request.
	var req mcp.Request
	if err := json.Unmarshal(raw, &req); err != nil {
		writeError(w, mcp.NullID, mcp.CodeParseError, "parse error")
		return
	}

	if req.JSONRPC != "2.0" || req.Method == "" {
		writeError(w, req.ID, mcp.CodeInvalidRequest, "invalid request")
		return
	}

	// Validate id type: only string, number, or null are valid.
	if req.ID != nil {
		first := firstNonSpace(req.ID)
		switch {
		case first == '"': // string — ok
		case first == 'n': // null — ok
		case first == '-' || (first >= '0' && first <= '9'): // number — ok
		default:
			// object, array, bool — invalid
			writeError(w, mcp.NullID, mcp.CodeInvalidRequest, "invalid id type")
			return
		}
	}

	// Determine notification status BEFORE auth so that auth failures on
	// notifications return 401 with no JSON-RPC body (MCP spec requirement).
	isNotification := req.ID == nil

	clientID, err := g.auth.Authenticate(r)
	if err != nil {
		if isNotification {
			// Notifications must never carry a JSON-RPC error body.
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeError(w, req.ID, mcp.CodeUnauthorized, "unauthorized")
		return
	}
	ctx = context.WithValue(ctx, clientIDKey, clientID)

	// Notifications (id absent) are acknowledged silently.
	if isNotification {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch req.Method {
	case "initialize":
		g.handleInitialize(w, &req)
	case "tools/list":
		g.handleToolsList(ctx, w, &req)
	case "tools/call":
		g.handleToolsCall(ctx, w, &req, clientID)
	default:
		writeError(w, req.ID, mcp.CodeMethodNotFound, "method not found")
	}
}

// handleInitialize responds to the MCP initialize handshake.
func (g *Gateway) handleInitialize(w http.ResponseWriter, req *mcp.Request) {
	writeResult(w, req.ID, mcp.InitializeResult{
		ProtocolVersion: protocolVersion,
		Capabilities: mcp.ServerCapabilities{
			Tools: &mcp.ToolsCapability{},
		},
		ServerInfo: mcp.ServerInfo{
			Name:    gatewayName,
			Version: gatewayVersion,
		},
	})
}

func (g *Gateway) handleToolsList(ctx context.Context, w http.ResponseWriter, req *mcp.Request) {
	tools, err := g.upstream.ToolsList(ctx)
	if err != nil {
		writeError(w, req.ID, mcp.CodeServerError, "upstream error")
		return
	}

	allowed := make([]mcp.Tool, 0, len(tools))
	for _, t := range tools {
		if g.policy.IsToolAllowed(t.Name) {
			allowed = append(allowed, t)
		}
	}

	if g.metrics != nil {
		g.metrics.IncRequest(req.Method, "", "allow")
	}
	writeResult(w, req.ID, mcp.ToolsListResult{Tools: allowed})
}

func (g *Gateway) handleToolsCall(ctx context.Context, w http.ResponseWriter, req *mcp.Request, clientID string) {
	start := time.Now()

	var callReq mcp.ToolsCallRequest
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &callReq); err != nil {
			writeError(w, req.ID, mcp.CodeInvalidParams, "invalid params")
			return
		}
	}
	if callReq.Name == "" {
		writeError(w, req.ID, mcp.CodeInvalidParams, "invalid params: name required")
		return
	}

	ctx = policy.ContextWithClientID(ctx, clientID)
	decision := g.policy.Evaluate(ctx, &callReq)

	event := &audit.Event{
		Timestamp:  time.Now(),
		Action:     "tools/call",
		Tool:       callReq.Name,
		Decision:   decision.Action,
		Reason:     decision.Reason,
		PolicyRule: decision.Rule,
		ClientID:   clientID,
		RequestID:  string(req.ID),
		Arguments:  callReq.Arguments,
	}

	if decision.Action == "deny" {
		event.Duration = time.Since(start)

		if logErr := g.audit.Log(ctx, event); logErr != nil {
			writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
			return
		}

		if decision.RateLimited {
			if g.metrics != nil {
				g.metrics.IncRateLimitHit(callReq.Name, clientID)
				g.metrics.IncRequest(req.Method, callReq.Name, "deny")
			}
			writeErrorWithData(w, req.ID, mcp.CodeRateLimited, "rate limited", map[string]any{
				"rule":           decision.Rule,
				"reason":         decision.Reason,
				"retry_after_ms": decision.RetryAfterMs,
			})
			return
		}

		if g.metrics != nil {
			g.metrics.IncPolicyDeny(decision.Rule)
			g.metrics.IncRequest(req.Method, callReq.Name, "deny")
		}
		writeErrorWithData(w, req.ID, mcp.CodePolicyDenied, "policy denied", map[string]string{
			"rule":   decision.Rule,
			"reason": decision.Reason,
		})
		return
	}

	result, err := g.upstream.ToolsCall(ctx, &callReq)
	event.Duration = time.Since(start)
	if err != nil {
		event.Error = err.Error()
		if logErr := g.audit.Log(ctx, event); logErr != nil {
			writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
			return
		}
		writeError(w, req.ID, mcp.CodeServerError, "upstream error")
		return
	}

	if logErr := g.audit.Log(ctx, event); logErr != nil {
		writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
		return
	}

	if g.metrics != nil {
		g.metrics.IncRequest(req.Method, callReq.Name, "allow")
	}
	writeResult(w, req.ID, result)
}

func writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mcp.Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusForCode(code))
	_ = json.NewEncoder(w).Encode(mcp.Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &mcp.Error{Code: code, Message: msg},
	})
}

func writeErrorWithData(w http.ResponseWriter, id json.RawMessage, code int, msg string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusForCode(code))
	_ = json.NewEncoder(w).Encode(mcp.Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &mcp.Error{Code: code, Message: msg, Data: data},
	})
}

// firstNonSpace returns the first non-whitespace byte in b, or 0 if b is empty/all spaces.
func firstNonSpace(b []byte) byte {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return c
		}
	}
	return 0
}
