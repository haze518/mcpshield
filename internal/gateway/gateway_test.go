package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/haze518/mcpshield/internal/audit"
	"github.com/haze518/mcpshield/internal/auth"
	"github.com/haze518/mcpshield/internal/gateway"
	"github.com/haze518/mcpshield/internal/mcp"
	"github.com/haze518/mcpshield/internal/observability"
	"github.com/haze518/mcpshield/internal/policy"
	"github.com/haze518/mcpshield/internal/upstream"
)

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

type testAuditLogger struct {
	mu     sync.Mutex
	events []*audit.Event
}

type failingAuditLogger struct{}

func (failingAuditLogger) Log(context.Context, *audit.Event) error { return errors.New("audit failed") }
func (failingAuditLogger) Close() error                            { return nil }

type failAfterNAuditLogger struct {
	mu    sync.Mutex
	count int
	failAt int
}

func (l *failAfterNAuditLogger) Log(_ context.Context, _ *audit.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.count++
	if l.count >= l.failAt {
		return errors.New("audit failed")
	}
	return nil
}

func (l *failAfterNAuditLogger) Close() error { return nil }

type readyManager struct {
	ready atomic.Bool
}

func (m *readyManager) Warmup(context.Context) error { m.ready.Store(true); return nil }
func (m *readyManager) Ready() bool                  { return m.ready.Load() }
func (m *readyManager) ToolsList(context.Context) ([]mcp.Tool, error) {
	return []mcp.Tool{}, nil
}
func (m *readyManager) ToolsCall(context.Context, *mcp.ToolsCallRequest) (*upstream.CallResult, error) {
	return &upstream.CallResult{UpstreamID: "test", Result: &mcp.ToolsCallResult{}}, nil
}

type notReadyManager struct{}

func (m *notReadyManager) Warmup(context.Context) error { return upstream.ErrNotReady }
func (m *notReadyManager) Ready() bool                  { return false }
func (m *notReadyManager) ToolsList(context.Context) ([]mcp.Tool, error) {
	return nil, upstream.ErrNotReady
}
func (m *notReadyManager) ToolsCall(context.Context, *mcp.ToolsCallRequest) (*upstream.CallResult, error) {
	return nil, upstream.ErrNotReady
}

func (l *testAuditLogger) Log(_ context.Context, event *audit.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
	return nil
}

func (l *testAuditLogger) Close() error { return nil }

func (l *testAuditLogger) captured() []*audit.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := make([]*audit.Event, len(l.events))
	copy(cp, l.events)
	return cp
}

// rpcResponse is a test-local decode target that keeps fields as raw JSON.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

// httpResult bundles the HTTP status, decoded RPC response, and raw body.
type httpResult struct {
	status  int
	cookies []*http.Cookie
	headers http.Header
	rpc     rpcResponse
	rawBody string
}

func newTestServer(al audit.Logger, eng policy.Engine) *httptest.Server {
	return newTestServerWithUpstream(al, eng, upstream.NewStubManager())
}

func newTestServerWithUpstream(al audit.Logger, eng policy.Engine, up upstream.Manager) *httptest.Server {
	gw := gateway.New(
		auth.NewAllowAll(),
		eng,
		up,
		al,
	)
	return httptest.NewServer(gw)
}

func newTestServerWithMaxBytes(al audit.Logger, eng policy.Engine, maxBytes int64) *httptest.Server {
	gw := gateway.New(
		auth.NewAllowAll(),
		eng,
		upstream.NewStubManager(),
		al,
	)
	gw.SetMaxRequestBytes(maxBytes)
	return httptest.NewServer(gw)
}

func allowAllStubToolsEngine(t *testing.T) policy.Engine {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(`
version: "1"
rules:
  - name: allow-stubs
    action: allow
    tools:
      - filesystem.read_file
      - github.search_repositories
`))
	if err != nil {
		t.Fatalf("build allow-all engine: %v", err)
	}
	return policy.NewYAMLPolicyEngine(p)
}

// doPost sends a POST and returns HTTP status, cookies, and decoded JSON-RPC.
func doPost(t *testing.T, url, body string, cookies ...*http.Cookie) httpResult {
	return doPostHeaders(t, url, body, nil, cookies...)
}

func doPostHeaders(t *testing.T, url, body string, headers map[string]string, cookies ...*http.Cookie) httpResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var rpc rpcResponse
	_ = json.Unmarshal(raw, &rpc) // may fail for 204/413 — callers check status first

	return httpResult{
		status:  resp.StatusCode,
		cookies: resp.Cookies(),
		headers: resp.Header.Clone(),
		rpc:     rpc,
		rawBody: string(raw),
	}
}

// doPostAuth is like doPost but with Bearer token.
func doPostAuth(t *testing.T, url, body, token string, cookies ...*http.Cookie) httpResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var rpc rpcResponse
	_ = json.Unmarshal(raw, &rpc)

	return httpResult{
		status:  resp.StatusCode,
		cookies: resp.Cookies(),
		headers: resp.Header.Clone(),
		rpc:     rpc,
		rawBody: string(raw),
	}
}

func bootstrapSession(t *testing.T, url string) string {
	t.Helper()
	res := doPost(t, url, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`)
	if res.rpc.Error != nil {
		t.Fatalf("initialize failed: %+v", res.rpc.Error)
	}
	sessionID := res.headers.Get(mcp.SessionHeader)
	if sessionID == "" {
		t.Fatal("initialize did not return session header")
	}
	return sessionID
}

func bootstrapSessionAuth(t *testing.T, url, token string) string {
	t.Helper()
	res := doPostAuth(t, url, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`, token)
	if res.rpc.Error != nil {
		t.Fatalf("initialize failed: %+v", res.rpc.Error)
	}
	sessionID := res.headers.Get(mcp.SessionHeader)
	if sessionID == "" {
		t.Fatal("initialize did not return session header")
	}
	return sessionID
}

// ---------------------------------------------------------------------------
// A) JSON-RPC parsing tests
// ---------------------------------------------------------------------------

func TestInvalidJSONReturnsParseError(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, policy.NewDenyAllEngine())
	defer srv.Close()

	res := doPost(t, srv.URL, `not valid json`)
	if res.status != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", res.status)
	}
	if res.rpc.Error == nil || res.rpc.Error.Code != mcp.CodeParseError {
		t.Errorf("error code: want %d, got %v", mcp.CodeParseError, res.rpc.Error)
	}
}

func TestEmptyBodyReturnsParseError(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, policy.NewDenyAllEngine())
	defer srv.Close()

	res := doPost(t, srv.URL, ``)
	if res.status != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", res.status)
	}
	if res.rpc.Error == nil || res.rpc.Error.Code != mcp.CodeParseError {
		t.Errorf("error code: want %d, got %v", mcp.CodeParseError, res.rpc.Error)
	}
}

func TestBatchJSONReturnsInvalidRequest(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, policy.NewDenyAllEngine())
	defer srv.Close()

	res := doPost(t, srv.URL, `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`)
	if res.status != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", res.status)
	}
	if res.rpc.Error == nil || res.rpc.Error.Code != mcp.CodeInvalidRequest {
		t.Errorf("error code: want %d, got %v", mcp.CodeInvalidRequest, res.rpc.Error)
	}
}

func TestTrailingGarbageRejected(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, policy.NewDenyAllEngine())
	defer srv.Close()

	res := doPost(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize"}{"extra":true}`)
	if res.status != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", res.status)
	}
	if res.rpc.Error == nil || res.rpc.Error.Code != mcp.CodeParseError {
		t.Errorf("error code: want %d, got %v", mcp.CodeParseError, res.rpc.Error)
	}
}

// TestNonObjectJSONReturnsInvalidRequest verifies that valid JSON primitives
// (number, string, bool, null) return CodeInvalidRequest (-32600), not
// CodeParseError (-32700), because the input is well-formed JSON — just the
// wrong type for an MCP request.
func TestNonObjectJSONReturnsInvalidRequest(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, policy.NewDenyAllEngine())
	defer srv.Close()

	for _, body := range []string{`42`, `"hello"`, `true`, `null`} {
		res := doPost(t, srv.URL, body)
		if res.status != http.StatusBadRequest {
			t.Errorf("body=%q status: want 400, got %d", body, res.status)
		}
		if res.rpc.Error == nil || res.rpc.Error.Code != mcp.CodeInvalidRequest {
			t.Errorf("body=%q error code: want %d (CodeInvalidRequest), got %v",
				body, mcp.CodeInvalidRequest, res.rpc.Error)
		}
	}
}

func TestInvalidIDTypeRejected(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, policy.NewDenyAllEngine())
	defer srv.Close()

	for _, body := range []string{
		`{"jsonrpc":"2.0","id":true,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":{},"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":[],"method":"initialize"}`,
	} {
		res := doPost(t, srv.URL, body)
		if res.status != http.StatusBadRequest {
			t.Errorf("body=%q status: want 400, got %d", body, res.status)
		}
		if res.rpc.Error == nil || res.rpc.Error.Code != mcp.CodeInvalidRequest {
			t.Errorf("body=%q error code: want %d, got %v", body, mcp.CodeInvalidRequest, res.rpc.Error)
		}
	}
}

func TestNullIDIsValidRequest(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, policy.NewDenyAllEngine())
	defer srv.Close()

	// id:null is a valid request (NOT a notification). Initialize should return a result.
	res := doPost(t, srv.URL, `{"jsonrpc":"2.0","id":null,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`)
	if res.status != http.StatusOK {
		t.Errorf("status: want 200, got %d", res.status)
	}
	if res.rpc.Error != nil {
		t.Errorf("unexpected error: code=%d msg=%s", res.rpc.Error.Code, res.rpc.Error.Message)
	}
	if string(res.rpc.ID) != "null" {
		t.Errorf("id: want null, got %s", res.rpc.ID)
	}
}

// ---------------------------------------------------------------------------
// B) HTTP status code tests
// ---------------------------------------------------------------------------

func TestUnknownMethodReturns404(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, policy.NewDenyAllEngine())
	defer srv.Close()

	res := doPost(t, srv.URL, `{"jsonrpc":"2.0","id":3,"method":"unknown/method"}`)
	if res.status != http.StatusNotFound {
		t.Errorf("status: want 404, got %d", res.status)
	}
	if res.rpc.Error == nil || res.rpc.Error.Code != mcp.CodeMethodNotFound {
		t.Errorf("error code: want %d, got %v", mcp.CodeMethodNotFound, res.rpc.Error)
	}
}

func TestReadyzReturns503BeforeWarmup(t *testing.T) {
	up := &readyManager{}
	srv := newTestServerWithUpstream(&testAuditLogger{}, policy.NewDenyAllEngine(), up)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status: want 503, got %d", res.StatusCode)
	}
}

func TestReadyzReturns200AfterWarmup(t *testing.T) {
	up := &readyManager{}
	if err := up.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}
	srv := newTestServerWithUpstream(&testAuditLogger{}, policy.NewDenyAllEngine(), up)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status: want 200, got %d", res.StatusCode)
	}
}

func TestMetricsStillWorksIndependentlyOfReadyz(t *testing.T) {
	up := &readyManager{}
	gw := gateway.New(auth.NewAllowAll(), policy.NewDenyAllEngine(), up, &testAuditLogger{})
	gw.SetMetrics(observability.NewRegistry(false))
	srv := httptest.NewServer(gw)
	defer srv.Close()

	metricsRes, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer metricsRes.Body.Close()
	if metricsRes.StatusCode != http.StatusOK {
		t.Fatalf("/metrics status: want 200, got %d", metricsRes.StatusCode)
	}

	readyRes, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer readyRes.Body.Close()
	if readyRes.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/readyz status: want 503, got %d", readyRes.StatusCode)
	}
}

func TestToolsListReturns503WhenUpstreamNotReady(t *testing.T) {
	al := &testAuditLogger{}
	srv := newTestServerWithUpstream(al, allowAllStubToolsEngine(t), &notReadyManager{})
	defer srv.Close()

	sessionID := bootstrapSession(t, srv.URL)
	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":42,"method":"tools/list"}`, map[string]string{mcp.SessionHeader: sessionID})
	if res.status != http.StatusServiceUnavailable {
		t.Fatalf("status: want 503, got %d", res.status)
	}
	if res.rpc.Error == nil || res.rpc.Error.Message != "gateway not ready" {
		t.Fatalf("expected gateway not ready error, got %+v", res.rpc.Error)
	}
	events := al.captured()
	if len(events) != 2 {
		t.Fatalf("audit events: want 2, got %d", len(events))
	}
	if events[1].Error == nil || events[1].Error.Message != "gateway not ready" {
		t.Fatalf("expected distinct audit error for not-ready path, got %+v", events[1].Error)
	}
}

func TestToolsCallReturns503WhenUpstreamNotReady(t *testing.T) {
	al := &testAuditLogger{}
	srv := newTestServerWithUpstream(al, allowAllStubToolsEngine(t), &notReadyManager{})
	defer srv.Close()

	sessionID := bootstrapSession(t, srv.URL)
	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"filesystem.read_file","arguments":{}}}`, map[string]string{mcp.SessionHeader: sessionID})
	if res.status != http.StatusServiceUnavailable {
		t.Fatalf("status: want 503, got %d", res.status)
	}
	if res.rpc.Error == nil || res.rpc.Error.Message != "gateway not ready" {
		t.Fatalf("expected gateway not ready error, got %+v", res.rpc.Error)
	}
	events := al.captured()
	if len(events) != 2 {
		t.Fatalf("audit events: want 2, got %d", len(events))
	}
	if events[1].Error == nil || events[1].Error.Message != "gateway not ready" {
		t.Fatalf("expected distinct audit error for not-ready path, got %+v", events[1].Error)
	}
}

func TestAuthFailureReturns401(t *testing.T) {
	gw := gateway.New(
		auth.NewAPIKeyAuthenticator(map[string]string{
			auth.NewKeyHash("secret-token"): "dev-team",
		}),
		policy.NewDenyAllEngine(),
		upstream.NewStubManager(),
		&testAuditLogger{},
	)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	res := doPost(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if res.status != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", res.status)
	}
	if res.rpc.Error == nil || res.rpc.Error.Code != mcp.CodeUnauthorized {
		t.Errorf("error code: want %d, got %v", mcp.CodeUnauthorized, res.rpc.Error)
	}
}

func TestRateLimitedReturns429(t *testing.T) {
	p, err := policy.LoadFromBytes([]byte(`
version: "1"
rules:
  - name: allow-fs-limited
    action: allow
    tools:
      - filesystem.read_file
    rate_limit:
      max: 1
      window: "60s"
      per: global
`))
	if err != nil {
		t.Fatal(err)
	}

	fixedNow := time.Now()
	eng := policy.NewYAMLPolicyEngineWithOptions(
		p,
		policy.NewFixedWindowLimiter(),
		func() time.Time { return fixedNow },
	)

	al := &testAuditLogger{}
	srv := newTestServer(al, eng)
	defer srv.Close()
	sessionID := bootstrapSession(t, srv.URL)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read_file","arguments":{}}}`

	// First call: allowed.
	r1 := doPostHeaders(t, srv.URL, body, map[string]string{mcp.SessionHeader: sessionID})
	if r1.rpc.Error != nil {
		t.Fatalf("first call should succeed, got error code=%d", r1.rpc.Error.Code)
	}

	// Second call: rate limited → 429.
	r2 := doPostHeaders(t, srv.URL, body, map[string]string{mcp.SessionHeader: sessionID})
	if r2.status != http.StatusTooManyRequests {
		t.Errorf("status: want 429, got %d", r2.status)
	}
	if r2.rpc.Error == nil || r2.rpc.Error.Code != mcp.CodeRateLimited {
		t.Errorf("error code: want %d, got %v", mcp.CodeRateLimited, r2.rpc.Error)
	}
}

// ---------------------------------------------------------------------------
// C) Initialize and session bootstrap
// ---------------------------------------------------------------------------

func TestInitializeReturnsServerInfo(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, policy.NewDenyAllEngine())
	defer srv.Close()

	res := doPost(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`)

	if res.status != http.StatusOK {
		t.Errorf("status: want 200, got %d", res.status)
	}
	if res.rpc.Error != nil {
		t.Fatalf("unexpected error: code=%d msg=%s", res.rpc.Error.Code, res.rpc.Error.Message)
	}

	var result mcp.InitializeResult
	if err := json.Unmarshal(res.rpc.Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if result.ProtocolVersion == "" {
		t.Error("protocolVersion must not be empty")
	}
	if result.ServerInfo.Name == "" {
		t.Error("serverInfo.name must not be empty")
	}
	if result.Capabilities.Tools == nil {
		t.Error("capabilities.tools must be present")
	}
}

func TestSessionPropagationAcrossInitializeToolsListAndToolsCall(t *testing.T) {
	al := &testAuditLogger{}
	srv := newTestServer(al, allowAllStubToolsEngine(t))
	defer srv.Close()

	initRes := doPost(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`)
	if initRes.rpc.Error != nil {
		t.Fatalf("initialize failed: %+v", initRes.rpc.Error)
	}

	sessionID := initRes.headers.Get(mcp.SessionHeader)
	if sessionID == "" {
		t.Fatal("expected initialize to return session header")
	}

	listRes := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, map[string]string{
		mcp.SessionHeader: sessionID,
	})
	if listRes.rpc.Error != nil {
		t.Fatalf("tools/list failed: %+v", listRes.rpc.Error)
	}
	if got := listRes.headers.Get(mcp.SessionHeader); got != sessionID {
		t.Fatalf("tools/list session header: want %q, got %q", sessionID, got)
	}

	callRes := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"filesystem.read_file","arguments":{"path":"/tmp/x"}}}`, map[string]string{
		mcp.SessionHeader: sessionID,
	})
	if callRes.rpc.Error != nil {
		t.Fatalf("tools/call failed: %+v", callRes.rpc.Error)
	}
	if got := callRes.headers.Get(mcp.SessionHeader); got != sessionID {
		t.Fatalf("tools/call session header: want %q, got %q", sessionID, got)
	}

	events := al.captured()
	if len(events) != 3 {
		t.Fatalf("audit events: want 3, got %d", len(events))
	}
	for i, evt := range events {
		if evt.SessionID != sessionID {
			t.Fatalf("event[%d] session_id: want %q, got %q", i, sessionID, evt.SessionID)
		}
		if evt.UpstreamID == "" {
			t.Fatalf("event[%d] upstream_id must not be empty", i)
		}
	}
	if events[0].Action != "initialize" {
		t.Fatalf("event[0] action: want initialize, got %s", events[0].Action)
	}
	if events[1].Action != "tools/list" {
		t.Fatalf("event[1] action: want tools/list, got %s", events[1].Action)
	}
	if events[2].Action != "tools/call" {
		t.Fatalf("event[2] action: want tools/call, got %s", events[2].Action)
	}
	if events[2].UpstreamID != "stub" {
		t.Fatalf("tools/call upstream_id: want stub, got %q", events[2].UpstreamID)
	}
	if events[2].Response == nil {
		t.Fatal("tools/call response must be captured in audit event")
	}
}

func TestInitializeIgnoresClientProvidedSessionID(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, allowAllStubToolsEngine(t))
	defer srv.Close()

	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, map[string]string{
		mcp.SessionHeader: "client-forged-session",
	})
	if res.rpc.Error != nil {
		t.Fatalf("initialize failed: %+v", res.rpc.Error)
	}
	got := res.headers.Get(mcp.SessionHeader)
	if got == "" {
		t.Fatal("expected server-minted session id")
	}
	if got == "client-forged-session" {
		t.Fatal("initialize must not echo client-provided session id")
	}
}

func TestInitializeAuditFailureDoesNotPublishSession(t *testing.T) {
	gw := gateway.New(
		auth.NewAllowAll(),
		allowAllStubToolsEngine(t),
		upstream.NewStubManager(),
		failingAuditLogger{},
	)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	res := doPost(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if res.status != http.StatusInternalServerError {
		t.Fatalf("status: want 500, got %d", res.status)
	}
	if got := res.headers.Get(mcp.SessionHeader); got != "" {
		t.Fatalf("failed initialize must not publish session header, got %q", got)
	}
}

func TestToolsListRejectsUnknownSession(t *testing.T) {
	al := &testAuditLogger{}
	srv := newTestServer(al, allowAllStubToolsEngine(t))
	defer srv.Close()

	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, map[string]string{
		mcp.SessionHeader: "forged-session",
	})
	if res.status != http.StatusBadRequest {
		t.Fatalf("status: want 400, got %d", res.status)
	}
	if res.rpc.Error == nil || res.rpc.Error.Code != mcp.CodeInvalidRequest {
		t.Fatalf("error: want invalid request, got %+v", res.rpc.Error)
	}
	events := al.captured()
	if len(events) != 1 {
		t.Fatalf("audit events: want 1, got %d", len(events))
	}
	if events[0].Decision != "deny" || events[0].Action != "tools/list" {
		t.Fatalf("unexpected audit event: %+v", events[0])
	}
}

func TestToolsListRejectsMissingSessionAndAudits(t *testing.T) {
	al := &testAuditLogger{}
	srv := newTestServer(al, allowAllStubToolsEngine(t))
	defer srv.Close()

	res := doPost(t, srv.URL, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if res.status != http.StatusBadRequest {
		t.Fatalf("status: want 400, got %d", res.status)
	}
	if res.rpc.Error == nil || res.rpc.Error.Code != mcp.CodeInvalidRequest {
		t.Fatalf("error: want invalid request, got %+v", res.rpc.Error)
	}
	events := al.captured()
	if len(events) != 1 {
		t.Fatalf("audit events: want 1, got %d", len(events))
	}
	if events[0].SessionID != "" {
		t.Fatalf("missing-session reject must audit empty session id, got %q", events[0].SessionID)
	}
	if events[0].Error == nil || events[0].Error.Message != "missing session header" {
		t.Fatalf("unexpected audit error: %+v", events[0].Error)
	}
}

func TestSessionCannotBeReusedByDifferentClient(t *testing.T) {
	gw := gateway.New(
		auth.NewAPIKeyAuthenticator(map[string]string{
			auth.NewKeyHash("token-a"): "client-a",
			auth.NewKeyHash("token-b"): "client-b",
		}),
		allowAllStubToolsEngine(t),
		upstream.NewStubManager(),
		&testAuditLogger{},
	)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	initRes := doPostAuth(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "token-a")
	if initRes.rpc.Error != nil {
		t.Fatalf("initialize failed: %+v", initRes.rpc.Error)
	}
	sessionID := initRes.headers.Get(mcp.SessionHeader)
	if sessionID == "" {
		t.Fatal("expected session id from initialize")
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer token-b")
	req.Header.Set(mcp.SessionHeader, sessionID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var rpc rpcResponse
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &rpc)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: want 401, got %d", resp.StatusCode)
	}
	if rpc.Error == nil || rpc.Error.Code != mcp.CodeUnauthorized {
		t.Fatalf("error: want unauthorized, got %+v", rpc.Error)
	}
}

func TestInitializedNotificationWithSessionIsAudited(t *testing.T) {
	al := &testAuditLogger{}
	srv := newTestServer(al, allowAllStubToolsEngine(t))
	defer srv.Close()

	sessionID := bootstrapSession(t, srv.URL)
	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, map[string]string{
		mcp.SessionHeader: sessionID,
	})
	if res.status != http.StatusNoContent {
		t.Fatalf("status: want 204, got %d", res.status)
	}
	events := al.captured()
	if len(events) != 2 {
		t.Fatalf("audit events: want 2, got %d", len(events))
	}
	if events[1].Action != "notifications/initialized" {
		t.Fatalf("expected initialized notification audit, got %s", events[1].Action)
	}
}

func TestInitializedNotificationWithInvalidSessionReturnsNon2xxAndAudits(t *testing.T) {
	al := &testAuditLogger{}
	srv := newTestServer(al, allowAllStubToolsEngine(t))
	defer srv.Close()

	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, map[string]string{
		mcp.SessionHeader: "forged-session",
	})
	if res.status != http.StatusBadRequest {
		t.Fatalf("status: want 400, got %d", res.status)
	}
	if res.rawBody != "" {
		t.Fatalf("notification reject must not return JSON-RPC body, got %q", res.rawBody)
	}
	events := al.captured()
	if len(events) != 1 {
		t.Fatalf("audit events: want 1, got %d", len(events))
	}
	if events[0].Action != "notifications/initialized" || events[0].Decision != "deny" {
		t.Fatalf("unexpected audit event: %+v", events[0])
	}
}

func TestInitializedNotificationAuditFailureReturnsNon2xxNoBody(t *testing.T) {
	al := &failAfterNAuditLogger{failAt: 2}
	gw := gateway.New(auth.NewAllowAll(), allowAllStubToolsEngine(t), upstream.NewStubManager(), al)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	sessionID := bootstrapSession(t, srv.URL)
	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, map[string]string{
		mcp.SessionHeader: sessionID,
	})
	if res.status != http.StatusInternalServerError {
		t.Fatalf("status: want 500, got %d", res.status)
	}
	if res.rawBody != "" {
		t.Fatalf("notification audit failure must not return body, got %q", res.rawBody)
	}
}

func TestSessionExpiresWithoutUse(t *testing.T) {
	al := &testAuditLogger{}
	gw := gateway.New(auth.NewAllowAll(), allowAllStubToolsEngine(t), upstream.NewStubManager(), al)
	now := time.Now()
	gw.SetTimeNow(func() time.Time { return now })
	gw.SetSessionConfig(time.Minute, 4)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	sessionID := bootstrapSession(t, srv.URL)
	now = now.Add(61 * time.Second)

	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, map[string]string{mcp.SessionHeader: sessionID})
	if res.status != http.StatusBadRequest {
		t.Fatalf("status: want 400, got %d", res.status)
	}
}

func TestSessionUseRenewsTTL(t *testing.T) {
	gw := gateway.New(auth.NewAllowAll(), allowAllStubToolsEngine(t), upstream.NewStubManager(), &testAuditLogger{})
	now := time.Now()
	gw.SetTimeNow(func() time.Time { return now })
	gw.SetSessionConfig(time.Minute, 4)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	sessionID := bootstrapSession(t, srv.URL)
	now = now.Add(30 * time.Second)
	res1 := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, map[string]string{mcp.SessionHeader: sessionID})
	if res1.rpc.Error != nil {
		t.Fatalf("first tools/list failed: %+v", res1.rpc.Error)
	}
	now = now.Add(59 * time.Second)
	res2 := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, map[string]string{mcp.SessionHeader: sessionID})
	if res2.rpc.Error != nil {
		t.Fatalf("renewed session should still be valid: %+v", res2.rpc.Error)
	}
}

func TestSessionCapacityEvictsOldest(t *testing.T) {
	gw := gateway.New(auth.NewAllowAll(), allowAllStubToolsEngine(t), upstream.NewStubManager(), &testAuditLogger{})
	now := time.Now()
	gw.SetTimeNow(func() time.Time { return now })
	gw.SetSessionConfig(time.Hour, 2)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	s1 := bootstrapSession(t, srv.URL)
	now = now.Add(time.Second)
	s2 := bootstrapSession(t, srv.URL)
	now = now.Add(time.Second)
	s3 := bootstrapSession(t, srv.URL)

	resOld := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, map[string]string{mcp.SessionHeader: s1})
	if resOld.status != http.StatusBadRequest {
		t.Fatalf("oldest session should be evicted, got status %d", resOld.status)
	}
	res2 := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, map[string]string{mcp.SessionHeader: s2})
	if res2.rpc.Error != nil {
		t.Fatalf("second session should remain valid: %+v", res2.rpc.Error)
	}
	res3 := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":4,"method":"tools/list"}`, map[string]string{mcp.SessionHeader: s3})
	if res3.rpc.Error != nil {
		t.Fatalf("newest session should remain valid: %+v", res3.rpc.Error)
	}
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

func TestNotificationReturns204(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, policy.NewDenyAllEngine())
	defer srv.Close()

	// Notification = id absent from JSON.
	res := doPost(t, srv.URL, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if res.status != http.StatusNoContent {
		t.Errorf("status: want 204, got %d", res.status)
	}
}

// TestNotificationAuthFailureReturns401WithNoBody verifies that when a
// notification (no id field) fails auth, the gateway returns 401 with an
// empty body — never a JSON-RPC error object.
func TestNotificationAuthFailureReturns401WithNoBody(t *testing.T) {
	gw := gateway.New(
		auth.NewAPIKeyAuthenticator(map[string]string{
			auth.NewKeyHash("secret-token"): "dev-team",
		}),
		policy.NewDenyAllEngine(),
		upstream.NewStubManager(),
		&testAuditLogger{},
	)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	// Notification (no id) sent without a valid Bearer token.
	res := doPost(t, srv.URL, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if res.status != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", res.status)
	}
	if res.rawBody != "" {
		t.Errorf("body: want empty for notification auth failure, got %q", res.rawBody)
	}
}

// ---------------------------------------------------------------------------
// D) Body size limit
// ---------------------------------------------------------------------------

func TestRequestBodyTooLarge(t *testing.T) {
	srv := newTestServerWithMaxBytes(&testAuditLogger{}, policy.NewDenyAllEngine(), 64)
	defer srv.Close()

	// Build a body larger than 64 bytes.
	bigBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`
	if len(bigBody) <= 64 {
		t.Fatal("test body should exceed the limit")
	}

	res := doPost(t, srv.URL, bigBody)
	if res.status != http.StatusRequestEntityTooLarge {
		t.Errorf("status: want 413, got %d", res.status)
	}
}

// ---------------------------------------------------------------------------
// E) Functional tests (tools/list, tools/call, policy, auth)
// ---------------------------------------------------------------------------

func TestToolsListReturnsTwoTools(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, allowAllStubToolsEngine(t))
	defer srv.Close()
	sessionID := bootstrapSession(t, srv.URL)

	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":42,"method":"tools/list"}`, map[string]string{mcp.SessionHeader: sessionID})

	if res.rpc.Error != nil {
		t.Fatalf("unexpected error: code=%d msg=%s", res.rpc.Error.Code, res.rpc.Error.Message)
	}
	if string(res.rpc.ID) != "42" {
		t.Errorf("id: want 42, got %s", res.rpc.ID)
	}

	var result mcp.ToolsListResult
	if err := json.Unmarshal(res.rpc.Result, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Tools) != 2 {
		t.Errorf("tools: want 2, got %d", len(result.Tools))
	}
}

func TestToolsCallDeniedByPolicy(t *testing.T) {
	al := &testAuditLogger{}
	srv := newTestServer(al, policy.NewDenyAllEngine())
	defer srv.Close()
	sessionID := bootstrapSession(t, srv.URL)

	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"filesystem.read_file","arguments":{}}}`, map[string]string{mcp.SessionHeader: sessionID})

	if res.rpc.Error == nil {
		t.Fatal("expected error response, got nil")
	}
	if res.rpc.Error.Code != mcp.CodePolicyDenied {
		t.Errorf("error code: want %d, got %d", mcp.CodePolicyDenied, res.rpc.Error.Code)
	}

	events := al.captured()
	if len(events) != 2 {
		t.Fatalf("audit events: want 2, got %d", len(events))
	}
	if events[1].Decision != "deny" {
		t.Errorf("audit decision: want deny, got %s", events[1].Decision)
	}
}

func TestToolsListFilteredByPolicy(t *testing.T) {
	p, err := policy.LoadFromBytes([]byte(`
version: "1"
rules:
  - name: allow-fs-only
    action: allow
    tools:
      - filesystem.read_file
`))
	if err != nil {
		t.Fatal(err)
	}

	srv := newTestServer(&testAuditLogger{}, policy.NewYAMLPolicyEngine(p))
	defer srv.Close()
	sessionID := bootstrapSession(t, srv.URL)

	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, map[string]string{mcp.SessionHeader: sessionID})
	if res.rpc.Error != nil {
		t.Fatalf("unexpected error: code=%d msg=%s", res.rpc.Error.Code, res.rpc.Error.Message)
	}

	var result mcp.ToolsListResult
	if err := json.Unmarshal(res.rpc.Result, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Tools) != 1 {
		t.Errorf("tools: want 1 after filtering, got %d", len(result.Tools))
	}
	if len(result.Tools) > 0 && result.Tools[0].Name != "filesystem.read_file" {
		t.Errorf("tool name: want filesystem.read_file, got %s", result.Tools[0].Name)
	}
}

func TestToolsListWithDenyAllReturnsNoTools(t *testing.T) {
	srv := newTestServer(&testAuditLogger{}, policy.NewDenyAllEngine())
	defer srv.Close()
	sessionID := bootstrapSession(t, srv.URL)

	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, map[string]string{mcp.SessionHeader: sessionID})
	if res.rpc.Error != nil {
		t.Fatalf("unexpected error: code=%d msg=%s", res.rpc.Error.Code, res.rpc.Error.Message)
	}

	var result mcp.ToolsListResult
	if err := json.Unmarshal(res.rpc.Result, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Tools) != 0 {
		t.Errorf("tools: want 0 with deny-all policy, got %d", len(result.Tools))
	}
}

func TestToolsCallArgDenyGuard(t *testing.T) {
	p, err := policy.LoadFromBytes([]byte(`
version: "1"
toolsets:
  fs_tools:
    tools:
      - filesystem.read_file
rules:
  - name: allow-fs
    action: allow
    toolset: fs_tools
  - name: block-sensitive-paths
    action: deny
    tools:
      - filesystem.read_file
    args:
      path:
        not_match: "^/etc/"
    reason: "sensitive path"
`))
	if err != nil {
		t.Fatal(err)
	}

	al := &testAuditLogger{}
	srv := newTestServer(al, policy.NewYAMLPolicyEngine(p))
	defer srv.Close()
	sessionID := bootstrapSession(t, srv.URL)

	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"filesystem.read_file","arguments":{"path":"/etc/passwd"}}}`, map[string]string{mcp.SessionHeader: sessionID})

	if res.rpc.Error == nil {
		t.Fatal("expected policy denied error, got nil")
	}
	if res.rpc.Error.Code != mcp.CodePolicyDenied {
		t.Errorf("code: want %d, got %d", mcp.CodePolicyDenied, res.rpc.Error.Code)
	}

	var data struct {
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(res.rpc.Error.Data, &data); err != nil {
		t.Fatalf("decode error data: %v", err)
	}
	if data.Rule != "block-sensitive-paths" {
		t.Errorf("rule: want block-sensitive-paths, got %q", data.Rule)
	}
	if data.Reason != "sensitive path" {
		t.Errorf("reason: want 'sensitive path', got %q", data.Reason)
	}

	events := al.captured()
	if len(events) != 2 {
		t.Fatalf("audit events: want 2, got %d", len(events))
	}
	if events[1].Decision != "deny" {
		t.Errorf("audit decision: want deny, got %s", events[1].Decision)
	}
}

func TestToolsCallRateLimited(t *testing.T) {
	p, err := policy.LoadFromBytes([]byte(`
version: "1"
rules:
  - name: allow-fs-limited
    action: allow
    tools:
      - filesystem.read_file
    rate_limit:
      max: 1
      window: "60s"
      per: global
`))
	if err != nil {
		t.Fatal(err)
	}

	fixedNow := time.Now()
	eng := policy.NewYAMLPolicyEngineWithOptions(
		p,
		policy.NewFixedWindowLimiter(),
		func() time.Time { return fixedNow },
	)

	al := &testAuditLogger{}
	srv := newTestServer(al, eng)
	defer srv.Close()
	sessionID := bootstrapSession(t, srv.URL)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read_file","arguments":{}}}`

	// First call: allowed.
	r1 := doPostHeaders(t, srv.URL, body, map[string]string{mcp.SessionHeader: sessionID})
	if r1.rpc.Error != nil {
		t.Fatalf("first call should succeed, got error code=%d msg=%s", r1.rpc.Error.Code, r1.rpc.Error.Message)
	}

	// Second call: rate limited.
	r2 := doPostHeaders(t, srv.URL, body, map[string]string{mcp.SessionHeader: sessionID})
	if r2.rpc.Error == nil {
		t.Fatal("expected rate-limit error, got nil")
	}
	if r2.rpc.Error.Code != mcp.CodeRateLimited {
		t.Errorf("error code: want %d (CodeRateLimited), got %d", mcp.CodeRateLimited, r2.rpc.Error.Code)
	}

	var data struct {
		Rule         string `json:"rule"`
		Reason       string `json:"reason"`
		RetryAfterMs int64  `json:"retry_after_ms"`
	}
	if err := json.Unmarshal(r2.rpc.Error.Data, &data); err != nil {
		t.Fatalf("decode error data: %v", err)
	}
	if data.Rule != "allow-fs-limited" {
		t.Errorf("rule: want allow-fs-limited, got %q", data.Rule)
	}
	if data.RetryAfterMs != 60_000 {
		t.Errorf("retry_after_ms: want 60000, got %d", data.RetryAfterMs)
	}
}

func TestToolsCallArgDenyGuardAllowsSafePath(t *testing.T) {
	p, err := policy.LoadFromBytes([]byte(`
version: "1"
rules:
  - name: allow-fs
    action: allow
    tools:
      - filesystem.read_file
  - name: block-sensitive-paths
    action: deny
    tools:
      - filesystem.read_file
    args:
      path:
        not_match: "^/etc/"
    reason: "sensitive path"
`))
	if err != nil {
		t.Fatal(err)
	}

	srv := newTestServer(&testAuditLogger{}, policy.NewYAMLPolicyEngine(p))
	defer srv.Close()
	sessionID := bootstrapSession(t, srv.URL)

	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"filesystem.read_file","arguments":{"path":"/home/user/doc.txt"}}}`, map[string]string{mcp.SessionHeader: sessionID})

	if res.rpc.Error != nil {
		t.Errorf("expected success for safe path, got error code=%d msg=%s", res.rpc.Error.Code, res.rpc.Error.Message)
	}
}

// ---------------------------------------------------------------------------
// API key auth
// ---------------------------------------------------------------------------

func TestAPIKeyAuthRejectsUnauthorized(t *testing.T) {
	gw := gateway.New(
		auth.NewAPIKeyAuthenticator(map[string]string{
			auth.NewKeyHash("secret-token"): "dev-team",
		}),
		policy.NewDenyAllEngine(),
		upstream.NewStubManager(),
		&testAuditLogger{},
	)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	res := doPost(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	if res.status != http.StatusUnauthorized {
		t.Errorf("status: want 401, got %d", res.status)
	}
	if res.rpc.Error == nil || res.rpc.Error.Code != mcp.CodeUnauthorized {
		t.Errorf("error code: want %d, got %v", mcp.CodeUnauthorized, res.rpc.Error)
	}
}

func TestAPIKeyAuthAcceptsValidToken(t *testing.T) {
	const rawToken = "secret-token"
	gw := gateway.New(
		auth.NewAPIKeyAuthenticator(map[string]string{
			auth.NewKeyHash(rawToken): "dev-team",
		}),
		allowAllStubToolsEngine(t),
		upstream.NewStubManager(),
		&testAuditLogger{},
	)
	srv := httptest.NewServer(gw)
	defer srv.Close()

	sessionID := bootstrapSessionAuth(t, srv.URL, rawToken)
	res := doPostHeaders(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, map[string]string{
		"Authorization":   "Bearer " + rawToken,
		mcp.SessionHeader: sessionID,
	})

	if res.rpc.Error != nil {
		t.Fatalf("unexpected error: code=%d msg=%s", res.rpc.Error.Code, res.rpc.Error.Message)
	}
}
