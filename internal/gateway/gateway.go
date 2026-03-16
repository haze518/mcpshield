package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
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
	defaultSessionTTL      = 30 * time.Minute
	defaultSessionMaxEntries = 10_000
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
	sessionMu       sync.RWMutex
	sessionClients  map[string]sessionBinding
	sessionTTL      time.Duration
	sessionMaxEntries int
	timeNow         func() time.Time
}

type sessionBinding struct {
	clientID  string
	expiresAt time.Time
}

func New(a auth.Authenticator, p policy.Engine, u upstream.Manager, al audit.Logger) *Gateway {
	return &Gateway{
		auth:            a,
		policy:          p,
		upstream:        u,
		audit:           al,
		maxRequestBytes: defaultMaxBody,
		sessionClients:  make(map[string]sessionBinding),
		sessionTTL:      defaultSessionTTL,
		sessionMaxEntries: defaultSessionMaxEntries,
		timeNow:         time.Now,
	}
}

// SetMetrics wires an optional Prometheus metrics registry into the gateway.
func (g *Gateway) SetMetrics(r *observability.Registry) {
	g.metrics = r
	if r != nil {
		g.sessionMu.RLock()
		defer g.sessionMu.RUnlock()
		r.SetActiveSessions(len(g.sessionClients))
	}
}

// SetMaxRequestBytes overrides the default 1 MiB inbound body limit.
func (g *Gateway) SetMaxRequestBytes(n int64) {
	if n > 0 {
		g.maxRequestBytes = n
	}
}

// SetSessionConfig overrides the default in-memory session TTL and cap.
func (g *Gateway) SetSessionConfig(ttl time.Duration, maxEntries int) {
	if ttl > 0 {
		g.sessionTTL = ttl
	}
	if maxEntries > 0 {
		g.sessionMaxEntries = maxEntries
	}
}

// SetTimeNow overrides the clock used by session lifecycle logic.
func (g *Gateway) SetTimeNow(now func() time.Time) {
	if now != nil {
		g.timeNow = now
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
		if req.Method == "notifications/initialized" {
			requestedSessionID := r.Header.Get(mcp.SessionHeader)
			if requestedSessionID != "" {
				sessionID, sessionErr := g.resolveSession(requestedSessionID, clientID)
				if sessionErr != nil {
					if logErr := g.logSessionReject(ctx, &req, clientID, requestedSessionID, sessionErr); logErr != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(httpStatusForCode(sessionErr.code))
					return
				}
				if logErr := g.audit.Log(ctx, &audit.Event{
						Timestamp:  g.timeNow(),
						Action:     req.Method,
						Decision:   "allow",
						ClientID:   clientID,
						SessionID:  sessionID,
						UpstreamID: "gateway",
					}); logErr != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch req.Method {
	case "initialize":
		g.handleInitialize(ctx, w, &req, clientID, uuid.NewString())
	case "tools/list":
		requestedSessionID := r.Header.Get(mcp.SessionHeader)
		sessionID, sessionErr := g.resolveSession(requestedSessionID, clientID)
		if sessionErr != nil {
			if logErr := g.logSessionReject(ctx, &req, clientID, requestedSessionID, sessionErr); logErr != nil {
				writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
				return
			}
			writeError(w, req.ID, sessionErr.code, sessionErr.message)
			return
		}
		w.Header().Set(mcp.SessionHeader, sessionID)
		g.handleToolsList(ctx, w, &req, clientID, sessionID)
	case "tools/call":
		requestedSessionID := r.Header.Get(mcp.SessionHeader)
		sessionID, sessionErr := g.resolveSession(requestedSessionID, clientID)
		if sessionErr != nil {
			if logErr := g.logSessionReject(ctx, &req, clientID, requestedSessionID, sessionErr); logErr != nil {
				writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
				return
			}
			writeError(w, req.ID, sessionErr.code, sessionErr.message)
			return
		}
		w.Header().Set(mcp.SessionHeader, sessionID)
		g.handleToolsCall(ctx, w, &req, clientID, sessionID)
	default:
		writeError(w, req.ID, mcp.CodeMethodNotFound, "method not found")
	}
}

// handleInitialize responds to the MCP initialize handshake.
func (g *Gateway) handleInitialize(ctx context.Context, w http.ResponseWriter, req *mcp.Request, clientID, sessionID string) {
	result := mcp.InitializeResult{
		ProtocolVersion: protocolVersion,
		Capabilities: mcp.ServerCapabilities{
			Tools: &mcp.ToolsCapability{},
		},
		ServerInfo: mcp.ServerInfo{
			Name:    gatewayName,
			Version: gatewayVersion,
		},
	}
	event := &audit.Event{
		Timestamp: g.timeNow(),
		Action:    "initialize",
		Decision:  "allow",
		ClientID:  clientID,
		RequestID: string(req.ID),
		SessionID: sessionID,
		UpstreamID: "gateway",
		Response:  result,
	}
	if logErr := g.audit.Log(ctx, event); logErr != nil {
		writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
		return
	}
	g.bindSession(sessionID, clientID)
	w.Header().Set(mcp.SessionHeader, sessionID)
	writeResult(w, req.ID, result)
}

func (g *Gateway) handleToolsList(ctx context.Context, w http.ResponseWriter, req *mcp.Request, clientID, sessionID string) {
	start := time.Now()
	tools, err := g.upstream.ToolsList(ctx)
	event := &audit.Event{
		Timestamp:  g.timeNow(),
		Action:     "tools/list",
		Decision:   "allow",
		ClientID:   clientID,
		RequestID:  string(req.ID),
		SessionID:  sessionID,
		UpstreamID: "gateway",
	}
	if err != nil {
		event.Duration = time.Since(start)
		event.Error = normalizedError(mcp.CodeServerError, "upstream error", map[string]any{
			"cause": err.Error(),
		})
		if logErr := g.audit.Log(ctx, event); logErr != nil {
			writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
			return
		}
		writeError(w, req.ID, mcp.CodeServerError, "upstream error")
		return
	}

	allowed := make([]mcp.Tool, 0, len(tools))
	for _, t := range tools {
		if g.policy.IsToolAllowed(t.Name) {
			allowed = append(allowed, t)
		}
	}
	event.Duration = time.Since(start)
	event.Response = mcp.ToolsListResult{Tools: allowed}
	if logErr := g.audit.Log(ctx, event); logErr != nil {
		writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
		return
	}

	if g.metrics != nil {
		g.metrics.IncRequest(req.Method, "", "allow")
	}
	writeResult(w, req.ID, mcp.ToolsListResult{Tools: allowed})
}

func (g *Gateway) handleToolsCall(ctx context.Context, w http.ResponseWriter, req *mcp.Request, clientID, sessionID string) {
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
		Timestamp:  g.timeNow(),
		Action:     "tools/call",
		Tool:       callReq.Name,
		Decision:   decision.Action,
		Reason:     decision.Reason,
		PolicyRule: decision.Rule,
		ClientID:   clientID,
		RequestID:  string(req.ID),
		SessionID:  sessionID,
		UpstreamID: "gateway",
		Arguments:  callReq.Arguments,
	}

	if decision.Action == "deny" {
		event.Duration = time.Since(start)

		if decision.RateLimited {
			event.Error = normalizedError(mcp.CodeRateLimited, "rate limited", map[string]any{
				"rule":           decision.Rule,
				"reason":         decision.Reason,
				"retry_after_ms": decision.RetryAfterMs,
			})
			if logErr := g.audit.Log(ctx, event); logErr != nil {
				writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
				return
			}
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

		event.Error = normalizedError(mcp.CodePolicyDenied, "policy denied", map[string]string{
			"rule":   decision.Rule,
			"reason": decision.Reason,
		})
		if logErr := g.audit.Log(ctx, event); logErr != nil {
			writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
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

	callResult, err := g.upstream.ToolsCall(ctx, &callReq)
	event.Duration = time.Since(start)
	if err != nil {
		if callResult != nil && callResult.UpstreamID != "" {
			event.UpstreamID = callResult.UpstreamID
		}
		event.Error = normalizedError(mcp.CodeServerError, "upstream error", map[string]any{
			"cause": err.Error(),
		})
		if logErr := g.audit.Log(ctx, event); logErr != nil {
			writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
			return
		}
		writeError(w, req.ID, mcp.CodeServerError, "upstream error")
		return
	}
	event.UpstreamID = callResult.UpstreamID
	event.Response = callResult.Result

	if logErr := g.audit.Log(ctx, event); logErr != nil {
		writeError(w, req.ID, mcp.CodeServerError, "audit logging failed")
		return
	}

	if g.metrics != nil {
		g.metrics.IncRequest(req.Method, callReq.Name, "allow")
	}
	writeResult(w, req.ID, callResult.Result)
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

func normalizedError(code int, msg string, data any) *audit.AuditError {
	return &audit.AuditError{
		Code:    code,
		Message: msg,
		Data:    data,
	}
}

type sessionError struct {
	code    int
	message string
}

func (g *Gateway) resolveSession(requestedSessionID, clientID string) (string, *sessionError) {
	if requestedSessionID == "" {
		g.recordSessionReject("missing")
		return "", &sessionError{code: mcp.CodeInvalidRequest, message: "missing session header"}
	}
	boundClientID, ok := g.lookupSessionClient(requestedSessionID)
	if !ok {
		g.recordSessionReject("unknown")
		return "", &sessionError{code: mcp.CodeInvalidRequest, message: "unknown session"}
	}
	if boundClientID != clientID {
		g.recordSessionReject("cross_client")
		return "", &sessionError{code: mcp.CodeUnauthorized, message: "session does not belong to client"}
	}
	return requestedSessionID, nil
}

func (g *Gateway) bindSession(sessionID, clientID string) {
	g.sessionMu.Lock()
	defer g.sessionMu.Unlock()
	g.evictExpiredLocked(g.timeNow())
	if len(g.sessionClients) >= g.sessionMaxEntries {
		g.evictOldestLocked(len(g.sessionClients)-g.sessionMaxEntries+1, "capacity")
	}
	g.sessionClients[sessionID] = sessionBinding{
		clientID:  clientID,
		expiresAt: g.timeNow().Add(g.sessionTTL),
	}
	g.updateActiveSessionsMetricLocked()
}

func (g *Gateway) lookupSessionClient(sessionID string) (string, bool) {
	now := g.timeNow()
	g.sessionMu.Lock()
	defer g.sessionMu.Unlock()
	binding, ok := g.sessionClients[sessionID]
	if !ok {
		return "", false
	}
	if !binding.expiresAt.After(now) {
		delete(g.sessionClients, sessionID)
		g.recordSessionEvictionLocked("expired")
		g.updateActiveSessionsMetricLocked()
		return "", false
	}
	binding.expiresAt = now.Add(g.sessionTTL)
	g.sessionClients[sessionID] = binding
	return binding.clientID, true
}

func (g *Gateway) evictExpiredLocked(now time.Time) {
	for sessionID, binding := range g.sessionClients {
		if !binding.expiresAt.After(now) {
			delete(g.sessionClients, sessionID)
			g.recordSessionEvictionLocked("expired")
		}
	}
	g.updateActiveSessionsMetricLocked()
}

func (g *Gateway) evictOldestLocked(n int, reason string) {
	for range n {
		var oldestID string
		var oldest time.Time
		first := true
		for sessionID, binding := range g.sessionClients {
			if first || binding.expiresAt.Before(oldest) {
				oldestID = sessionID
				oldest = binding.expiresAt
				first = false
			}
		}
		if oldestID == "" {
			return
		}
		delete(g.sessionClients, oldestID)
		g.recordSessionEvictionLocked(reason)
	}
	g.updateActiveSessionsMetricLocked()
}

func (g *Gateway) logSessionReject(ctx context.Context, req *mcp.Request, clientID, requestedSessionID string, sessionErr *sessionError) error {
	return g.audit.Log(ctx, &audit.Event{
		Timestamp:  g.timeNow(),
		Action:     req.Method,
		Decision:   "deny",
		ClientID:   clientID,
		RequestID:  string(req.ID),
		SessionID:  requestedSessionID,
		UpstreamID: "gateway",
		Error: normalizedError(sessionErr.code, sessionErr.message, map[string]any{
			"requested_session_id": requestedSessionID,
		}),
	})
}

func (g *Gateway) recordSessionReject(reason string) {
	if g.metrics != nil {
		g.metrics.IncSessionReject(reason)
	}
}

func (g *Gateway) recordSessionEvictionLocked(reason string) {
	if g.metrics != nil {
		g.metrics.IncSessionEviction(reason)
	}
}

func (g *Gateway) updateActiveSessionsMetricLocked() {
	if g.metrics != nil {
		g.metrics.SetActiveSessions(len(g.sessionClients))
	}
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
