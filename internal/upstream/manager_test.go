package upstream_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/haze518/mcpshield/internal/mcp"
	"github.com/haze518/mcpshield/internal/transport"
	"github.com/haze518/mcpshield/internal/upstream"
)

func newFakeMCPServer(t *testing.T, tools []mcp.Tool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		switch req.Method {
		case "tools/list":
			_ = enc.Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{"tools": tools},
			})
		case "tools/call":
			var params mcp.ToolsCallRequest
			_ = json.Unmarshal(req.Params, &params)
			_ = enc.Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": "ok:" + params.Name},
					},
				},
			})
		default:
			_ = enc.Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"error":   map[string]any{"code": -32601, "message": "method not found"},
			})
		}
	}))
}

func TestToolsListReturnsPrefixedNames(t *testing.T) {
	srv := newFakeMCPServer(t, []mcp.Tool{
		{Name: "read_file", Description: "Read a file"},
		{Name: "write_file", Description: "Write a file"},
	})
	defer srv.Close()

	client := transport.NewMCPHTTPClient("fs", srv.URL, nil)
	mgr := upstream.NewManager(context.Background(), []upstream.Entry{
		{ID: "fs", Prefix: "fs", Client: client},
	})

	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}
	tools, err := mgr.ToolsList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(tools))
	}
	for _, tool := range tools {
		if !strings.HasPrefix(tool.Name, "fs.") {
			t.Errorf("expected prefix 'fs.', got %q", tool.Name)
		}
	}
	if tools[0].Name != "fs.read_file" {
		t.Errorf("want fs.read_file, got %s", tools[0].Name)
	}
	if tools[1].Name != "fs.write_file" {
		t.Errorf("want fs.write_file, got %s", tools[1].Name)
	}
}

func TestToolsCallRoutesAndStripsPrefix(t *testing.T) {
	srv := newFakeMCPServer(t, []mcp.Tool{
		{Name: "read_file", Description: "Read a file"},
	})
	defer srv.Close()

	client := transport.NewMCPHTTPClient("fs", srv.URL, nil)
	mgr := upstream.NewManager(context.Background(), []upstream.Entry{
		{ID: "fs", Prefix: "fs", Client: client},
	})

	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}
	result, err := mgr.ToolsCall(context.Background(), &mcp.ToolsCallRequest{
		Name:      "fs.read_file",
		Arguments: map[string]any{"path": "/tmp/test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.UpstreamID != "fs" {
		t.Fatalf("want upstream id fs, got %q", result.UpstreamID)
	}
	if len(result.Result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}
	// Fake server echoes the name it received; must be stripped of prefix.
	if result.Result.Content[0].Text != "ok:read_file" {
		t.Errorf("want ok:read_file (prefix stripped), got %q", result.Result.Content[0].Text)
	}
}

func TestToolsCallUnknownToolReturnsError(t *testing.T) {
	srv := newFakeMCPServer(t, []mcp.Tool{
		{Name: "read_file", Description: "Read a file"},
	})
	defer srv.Close()

	client := transport.NewMCPHTTPClient("fs", srv.URL, nil)
	mgr := upstream.NewManager(context.Background(), []upstream.Entry{
		{ID: "fs", Prefix: "fs", Client: client},
	})

	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}
	_, err := mgr.ToolsCall(context.Background(), &mcp.ToolsCallRequest{
		Name: "fs.nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for unknown tool, got nil")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("expected 'unknown tool' in error message, got: %s", err.Error())
	}
}

func TestToolsListMultipleUpstreams(t *testing.T) {
	srv1 := newFakeMCPServer(t, []mcp.Tool{
		{Name: "read_file", Description: "Read a file"},
	})
	defer srv1.Close()

	srv2 := newFakeMCPServer(t, []mcp.Tool{
		{Name: "search_repos", Description: "Search repositories"},
	})
	defer srv2.Close()

	mgr := upstream.NewManager(context.Background(), []upstream.Entry{
		{ID: "fs", Prefix: "fs", Client: transport.NewMCPHTTPClient("fs", srv1.URL, nil)},
		{ID: "gh", Prefix: "gh", Client: transport.NewMCPHTTPClient("gh", srv2.URL, nil)},
	})

	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}
	tools, err := mgr.ToolsList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 {
		t.Fatalf("want 2 tools from 2 upstreams, got %d", len(tools))
	}

	names := make(map[string]bool, len(tools))
	for _, tool := range tools {
		names[tool.Name] = true
	}
	if !names["fs.read_file"] {
		t.Error("expected fs.read_file in merged list")
	}
	if !names["gh.search_repos"] {
		t.Error("expected gh.search_repos in merged list")
	}
}

// ---------------------------------------------------------------------------
// E1: stale-while-revalidate — global lock never held during network I/O
// ---------------------------------------------------------------------------

// blockingClient implements upstream.Client and allows the test to control
// when ToolsList calls complete.
type blockingClient struct {
	tools    []mcp.Tool
	mu       sync.Mutex
	n        int
	blockAt  int           // block starting at this call number (1-based)
	releaseC chan struct{}  // close to unblock all waiting calls
}

func (c *blockingClient) ToolsList(ctx context.Context) ([]mcp.Tool, error) {
	c.mu.Lock()
	c.n++
	callN := c.n
	c.mu.Unlock()

	if callN >= c.blockAt {
		select {
		case <-c.releaseC:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return c.tools, nil
}

func (c *blockingClient) ToolsCall(_ context.Context, _ *mcp.ToolsCallRequest) (*mcp.ToolsCallResult, error) {
	return &mcp.ToolsCallResult{
		Content: []mcp.Content{{Type: "text", Text: "ok"}},
	}, nil
}

func (c *blockingClient) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func TestWarmupTransitionsManagerToReady(t *testing.T) {
	client := &blockingClient{
		tools:    []mcp.Tool{{Name: "tool1", Description: "desc"}},
		blockAt:  100,
		releaseC: make(chan struct{}),
	}
	close(client.releaseC)

	mgr := upstream.NewManager(context.Background(), []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	})
	if mgr.Ready() {
		t.Fatal("manager must start unready")
	}
	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}
	if !mgr.Ready() {
		t.Fatal("manager must be ready after successful warmup")
	}
}

func TestWarmupFailureLeavesManagerUnready(t *testing.T) {
	client := &fakeCountClient{tools: []mcp.Tool{{Name: "tool1"}}, failAfter: 0}
	mgr := upstream.NewManager(context.Background(), []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	})
	if err := mgr.Warmup(context.Background()); err == nil {
		t.Fatal("expected Warmup to fail")
	}
	if mgr.Ready() {
		t.Fatal("manager must remain unready after failed warmup")
	}
}

func TestErrNotReadyReturnedBeforeSuccessfulWarmup(t *testing.T) {
	client := &fakeCountClient{tools: []mcp.Tool{{Name: "tool1"}}, failAfter: 1}
	mgr := upstream.NewManager(context.Background(), []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	})
	_, err := mgr.ToolsList(context.Background())
	if !errors.Is(err, upstream.ErrNotReady) {
		t.Fatalf("expected ErrNotReady, got %v", err)
	}
}

type flakyWarmupClient struct {
	mu       sync.Mutex
	calls    int
	failures int
	tools    []mcp.Tool
}

func (c *flakyWarmupClient) ToolsList(_ context.Context) ([]mcp.Tool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.failures > 0 {
		c.failures--
		return nil, fmt.Errorf("temporary failure")
	}
	return c.tools, nil
}

func (c *flakyWarmupClient) ToolsCall(_ context.Context, _ *mcp.ToolsCallRequest) (*mcp.ToolsCallResult, error) {
	return &mcp.ToolsCallResult{Content: []mcp.Content{{Type: "text", Text: "ok"}}}, nil
}

func TestWarmupRetryAfterFailureEventuallyReady(t *testing.T) {
	client := &flakyWarmupClient{
		failures: 1,
		tools:    []mcp.Tool{{Name: "tool1", Description: "desc"}},
	}
	mgr := upstream.NewManager(context.Background(), []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	})
	if err := mgr.Warmup(context.Background()); err == nil {
		t.Fatal("first Warmup should fail")
	}
	if mgr.Ready() {
		t.Fatal("manager must remain unready after failed warmup")
	}
	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("second Warmup: %v", err)
	}
	if !mgr.Ready() {
		t.Fatal("manager must become ready after successful retry")
	}
}

func TestConcurrentWarmupDoesNotDuplicateInitialLoad(t *testing.T) {
	releaseC := make(chan struct{})
	client := &blockingClient{
		tools:    []mcp.Tool{{Name: "tool1", Description: "desc"}},
		blockAt:  1,
		releaseC: releaseC,
	}
	mgr := upstream.NewManagerWithTTL(context.Background(), []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	}, time.Minute)

	errCh := make(chan error, 3)
	for range 3 {
		go func() {
			errCh <- mgr.Warmup(context.Background())
		}()
	}

	for i := 0; i < 50; i++ {
		if mgr.LoadingInProgress() {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(releaseC)

	for range 3 {
		if err := <-errCh; err != nil {
			t.Fatalf("Warmup returned error: %v", err)
		}
	}
	if calls := client.Calls(); calls != 1 {
		t.Fatalf("expected exactly 1 initial ToolsList call, got %d", calls)
	}
}

func TestInvalidateCacheResetsReadiness(t *testing.T) {
	client := &blockingClient{
		tools:    []mcp.Tool{{Name: "tool1", Description: "desc"}},
		blockAt:  100,
		releaseC: make(chan struct{}),
	}
	close(client.releaseC)
	mgr := upstream.NewManager(context.Background(), []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	})
	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}
	if !mgr.Ready() {
		t.Fatal("manager must be ready after warmup")
	}
	mgr.InvalidateCache()
	if mgr.Ready() {
		t.Fatal("manager must become unready after cache invalidation")
	}
	_, err := mgr.ToolsList(context.Background())
	if !errors.Is(err, upstream.ErrNotReady) {
		t.Fatalf("expected ErrNotReady after invalidation, got %v", err)
	}
}

func TestWarmupAfterInvalidateRestoresReadiness(t *testing.T) {
	client := &blockingClient{
		tools:    []mcp.Tool{{Name: "tool1", Description: "desc"}},
		blockAt:  100,
		releaseC: make(chan struct{}),
	}
	close(client.releaseC)
	mgr := upstream.NewManager(context.Background(), []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	})
	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}
	mgr.InvalidateCache()
	if mgr.Ready() {
		t.Fatal("manager must be unready immediately after invalidation")
	}
	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup after invalidation: %v", err)
	}
	if !mgr.Ready() {
		t.Fatal("manager must be ready again after successful warmup")
	}
}

func TestInvalidateCacheDuringInFlightRefreshRestoresReadinessOnRefreshSuccess(t *testing.T) {
	releaseC := make(chan struct{})
	client := &blockingClient{
		tools:    []mcp.Tool{{Name: "tool1", Description: "desc"}},
		blockAt:  2,
		releaseC: releaseC,
	}
	mgr := upstream.NewManagerWithTTL(context.Background(), []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	}, 5*time.Millisecond)

	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	got, err := mgr.ToolsList(context.Background())
	if err != nil {
		t.Fatalf("ToolsList: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected stale cache before refresh completion, got %v", got)
	}

	for i := 0; i < 100; i++ {
		if mgr.BgRefreshInProgress() {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !mgr.BgRefreshInProgress() {
		t.Fatal("expected background refresh to be in progress")
	}

	mgr.InvalidateCache()
	if mgr.Ready() {
		t.Fatal("manager must become unready after invalidation while refresh is still in flight")
	}

	close(releaseC)
	for i := 0; i < 100; i++ {
		if !mgr.BgRefreshInProgress() {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !mgr.Ready() {
		t.Fatal("successful in-flight refresh must restore readiness after invalidation")
	}

	got, err = mgr.ToolsList(context.Background())
	if err != nil {
		t.Fatalf("ToolsList after refresh completion: %v", err)
	}
	if len(got) != 1 || got[0].Name != "p.tool1" {
		t.Fatalf("unexpected tools after refresh completion: %v", got)
	}
}

func TestStaleCacheReturnedImmediatelyWhileRefreshing(t *testing.T) {
	releaseC := make(chan struct{})
	tools := []mcp.Tool{{Name: "tool1", Description: "desc"}}
	client := &blockingClient{tools: tools, blockAt: 2, releaseC: releaseC}

	// Short TTL so cache expires quickly.
	mgr := upstream.NewManagerWithTTL(context.Background(), []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	}, 5*time.Millisecond)

	// Warmup: populates cache (call #1, not blocked).
	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}
	got, err := mgr.ToolsList(context.Background())
	if len(got) != 1 || got[0].Name != "p.tool1" {
		t.Fatalf("unexpected tools: %v", got)
	}

	// Wait for the cache TTL to expire.
	time.Sleep(10 * time.Millisecond)

	// Second call: should return stale cache immediately and launch background refresh (call #2, blocked).
	got, err = mgr.ToolsList(context.Background())
	if err != nil {
		t.Fatalf("stale ToolsList: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 stale tool, got %v", got)
	}

	// Poll until the background refresh goroutine is confirmed in-flight.
	var inProgress bool
	for i := 0; i < 50; i++ {
		if mgr.BgRefreshInProgress() {
			inProgress = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !inProgress {
		t.Error("expected background refresh to be in progress")
	}

	// Concurrent calls while refresh is blocked must all return stale,
	// and must NOT launch additional refresh goroutines.
	for i := 0; i < 10; i++ {
		got, err = mgr.ToolsList(context.Background())
		if err != nil {
			t.Fatalf("concurrent stale ToolsList: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 stale tool during refresh, got %v", got)
		}
	}

	// Unblock the background refresh.
	close(releaseC)

	// Wait for the refresh goroutine to finish.
	for i := 0; i < 100; i++ {
		if !mgr.BgRefreshInProgress() {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// Total client calls must be exactly 2: initial load + one background refresh.
	if n := client.Calls(); n != 2 {
		t.Errorf("expected 2 client calls (1 initial + 1 background), got %d", n)
	}
}

func TestToolsCallDoesNotBlockOnRefreshWhenStaleCacheExists(t *testing.T) {
	releaseC := make(chan struct{})
	client := &blockingClient{
		tools:    []mcp.Tool{{Name: "tool1", Description: "desc"}},
		blockAt:  2,
		releaseC: releaseC,
	}

	mgr := upstream.NewManagerWithTTL(context.Background(), []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	}, 5*time.Millisecond)
	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	start := time.Now()
	result, err := mgr.ToolsCall(context.Background(), &mcp.ToolsCallRequest{Name: "p.tool1"})
	if err != nil {
		t.Fatalf("ToolsCall: %v", err)
	}
	if result.UpstreamID != "test" {
		t.Fatalf("upstream id: want test, got %q", result.UpstreamID)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("ToolsCall took too long while refresh blocked: %v", elapsed)
	}
	if !mgr.BgRefreshInProgress() {
		t.Fatal("expected background refresh to be in progress")
	}
	close(releaseC)
}

// ---------------------------------------------------------------------------
// E6: Warmup cancellation and retry behavior
// ---------------------------------------------------------------------------

// slowClient blocks every ToolsList call until blockCh is closed.
type slowClient struct {
	tools   []mcp.Tool
	blockCh chan struct{}
}

func (c *slowClient) ToolsList(ctx context.Context) ([]mcp.Tool, error) {
	select {
	case <-c.blockCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return c.tools, nil
}

func (c *slowClient) ToolsCall(_ context.Context, _ *mcp.ToolsCallRequest) (*mcp.ToolsCallResult, error) {
	return nil, fmt.Errorf("not implemented")
}

// TestFirstCallerContextCancelDoesNotHostageInitialLoad verifies that a
// cancelled warmup attempt does not poison subsequent warmup retries.
func TestFirstCallerContextCancelDoesNotHostageInitialLoad(t *testing.T) {
	blockCh := make(chan struct{})
	tools := []mcp.Tool{{Name: "tool1", Description: "d"}}
	client := &slowClient{tools: tools, blockCh: blockCh}

	mgrCtx, mgrCancel := context.WithCancel(context.Background())
	defer mgrCancel()

	mgr := upstream.NewManagerWithTTL(mgrCtx, []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	}, time.Minute)

	// Warmup caller uses a context that we will cancel to simulate a timeout.
	callerCtx, callerCancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		err := mgr.Warmup(callerCtx)
		errCh <- err
	}()

	// Give the goroutine time to start and block on the loading channel.
	time.Sleep(20 * time.Millisecond)

	// Cancel the first caller's context — it should return with an error.
	callerCancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("expected error from cancelled caller context, got nil")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("first caller did not return after context cancel")
	}

	// Unblock the warmup call.
	close(blockCh)

	// A new warmup caller should succeed once the load completes.
	var err error
	for i := 0; i < 100; i++ {
		err = mgr.Warmup(context.Background())
		if err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("second warmup after load complete: %v", err)
	}

	// Calls should now succeed.
	var got []mcp.Tool
	got, err = mgr.ToolsList(context.Background())
	if err != nil {
		t.Fatalf("ToolsList after warmup: %v", err)
	}
	if len(got) != 1 || got[0].Name != "p.tool1" {
		t.Errorf("unexpected tools: %v", got)
	}
}

func TestWarmupRespectsCancellationWithoutHanging(t *testing.T) {
	blockCh := make(chan struct{})
	client := &slowClient{
		tools:   []mcp.Tool{{Name: "tool1", Description: "d"}},
		blockCh: blockCh,
	}
	mgrCtx, mgrCancel := context.WithCancel(context.Background())
	defer mgrCancel()

	mgr := upstream.NewManagerWithTTL(mgrCtx, []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	}, time.Minute)

	warmCtx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- mgr.Warmup(warmCtx)
	}()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected Warmup cancellation error")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Warmup did not exit after cancellation")
	}
	if mgr.Ready() {
		t.Fatal("manager must remain unready after canceled warmup")
	}
	close(blockCh)
}

// ---------------------------------------------------------------------------
// E6: Background refresh failure — stale cache preserved, no panic
// ---------------------------------------------------------------------------

// fakeCountClient returns tools for the first failAfter calls, then errors.
type fakeCountClient struct {
	mu        sync.Mutex
	n         int
	tools     []mcp.Tool
	failAfter int
}

func (c *fakeCountClient) ToolsList(_ context.Context) ([]mcp.Tool, error) {
	c.mu.Lock()
	c.n++
	n := c.n
	c.mu.Unlock()
	if n > c.failAfter {
		return nil, fmt.Errorf("injected failure on call %d", n)
	}
	return c.tools, nil
}

func (c *fakeCountClient) ToolsCall(_ context.Context, _ *mcp.ToolsCallRequest) (*mcp.ToolsCallResult, error) {
	return nil, fmt.Errorf("not implemented")
}

// TestBgRefreshFailurePreservesStaleCache verifies that a background cache
// refresh failure leaves the stale cache intact and does not panic or wipe
// the cached tool list.
func TestBgRefreshFailurePreservesStaleCache(t *testing.T) {
	goodTools := []mcp.Tool{{Name: "tool1", Description: "d"}}
	// Succeeds on call 1 (initial load), fails on all subsequent calls (bg refresh).
	client := &fakeCountClient{tools: goodTools, failAfter: 1}

	mgrCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := upstream.NewManagerWithTTL(mgrCtx, []upstream.Entry{
		{ID: "test", Prefix: "p", Client: client},
	}, 5*time.Millisecond)

	// Warmup (call 1: succeeds).
	if err := mgr.Warmup(context.Background()); err != nil {
		t.Fatalf("Warmup: %v", err)
	}
	got, err := mgr.ToolsList(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 tool, got %d", len(got))
	}

	// Let TTL expire, then trigger background refresh (call 2: fails).
	// The stale cache must be returned immediately.
	time.Sleep(10 * time.Millisecond)
	got, err = mgr.ToolsList(context.Background())
	if err != nil {
		t.Fatalf("stale cache call: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("stale cache: want 1 tool, got %d", len(got))
	}

	// Wait for the background goroutine to finish (it errors, but must not panic).
	for i := 0; i < 100; i++ {
		if !mgr.BgRefreshInProgress() {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// The stale cache must still be accessible — a failed refresh must not wipe it.
	got, err = mgr.ToolsList(context.Background())
	if err != nil {
		t.Fatalf("after failed refresh: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("after failed refresh: want 1 stale tool, got %d", len(got))
	}
	if !mgr.Ready() {
		t.Fatal("manager must remain ready while stale cache is still usable")
	}
}
