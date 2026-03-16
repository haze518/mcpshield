package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/haze518/mcpshield/internal/mcp"
)

func defaultInputSchema() map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
}

// Manager proxies MCP tool operations across upstream servers.
type Manager interface {
	ToolsList(ctx context.Context) ([]mcp.Tool, error)
	ToolsCall(ctx context.Context, req *mcp.ToolsCallRequest) (*CallResult, error)
}

// ManagerMetrics is implemented by observability.Registry. Accepted by
// SetMetrics to wire Prometheus counters without creating an import cycle.
type ManagerMetrics interface {
	IncToolsRefreshFail(upstreamID string)
}

// Client is the interface satisfied by transport.MCPHTTPClient.
type Client interface {
	ToolsList(ctx context.Context) ([]mcp.Tool, error)
	ToolsCall(ctx context.Context, req *mcp.ToolsCallRequest) (*mcp.ToolsCallResult, error)
}

// CallResult captures the routed upstream id and the returned MCP payload.
type CallResult struct {
	UpstreamID string
	Result     *mcp.ToolsCallResult
}

// Entry binds a Client to an id and prefix for aggregation.
type Entry struct {
	ID     string
	Prefix string
	Client Client
}

// ---- stub ---------------------------------------------------------------

type stubManager struct{}

func NewStubManager() Manager {
	return &stubManager{}
}

func (m *stubManager) ToolsList(_ context.Context) ([]mcp.Tool, error) {
	return []mcp.Tool{
		{
			Name:        "filesystem.read_file",
			Description: "Read a file from the filesystem",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string"},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "github.search_repositories",
			Description: "Search GitHub repositories",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string"},
				},
				"required": []string{"query"},
			},
		},
	}, nil
}

func (m *stubManager) ToolsCall(_ context.Context, req *mcp.ToolsCallRequest) (*CallResult, error) {
	argsJSON, err := json.Marshal(req.Arguments)
	if err != nil {
		argsJSON = []byte("{}")
	}
	return &CallResult{
		UpstreamID: "stub",
		Result: &mcp.ToolsCallResult{
			Content: []mcp.Content{
				{Type: "text", Text: fmt.Sprintf("called %s with %s", req.Name, string(argsJSON))},
			},
		},
	}, nil
}

// ---- real ---------------------------------------------------------------

const defaultCacheTTL = 10 * time.Second

type toolRoute struct {
	upstreamID   string
	client       Client
	originalName string
}

type toolsCache struct {
	tools    []mcp.Tool
	routeMap map[string]toolRoute
	expiry   time.Time
}

type realManager struct {
	ctx      context.Context // server lifecycle context
	entries  []Entry
	cacheTTL time.Duration

	mu        sync.Mutex
	cached    *toolsCache
	loading   chan struct{} // non-nil while first load in progress; closed on completion
	bgRefresh atomic.Bool  // true while a background cache refresh goroutine is running

	metrics ManagerMetrics // optional; nil = no Prometheus counters
}

// NewManager creates a real upstream manager. ctx is the server lifecycle
// context: background refresh goroutines are cancelled when ctx is done.
func NewManager(ctx context.Context, entries []Entry) *realManager {
	return &realManager{
		ctx:      ctx,
		entries:  entries,
		cacheTTL: defaultCacheTTL,
	}
}

// SetMetrics wires Prometheus counters for cache refresh failures.
// Must be called before the first ToolsList or ToolsCall to be race-free.
func (m *realManager) SetMetrics(metrics ManagerMetrics) {
	m.metrics = metrics
}

// InvalidateCache clears the cached tools list. Safe for concurrent use.
func (m *realManager) InvalidateCache() {
	m.mu.Lock()
	m.cached = nil
	m.mu.Unlock()
}

func (m *realManager) ToolsList(ctx context.Context) ([]mcp.Tool, error) {
	c, err := m.getCache(ctx)
	if err != nil {
		return nil, err
	}
	return c.tools, nil
}

func (m *realManager) ToolsCall(ctx context.Context, req *mcp.ToolsCallRequest) (*CallResult, error) {
	c, err := m.getCache(ctx)
	if err != nil {
		return nil, err
	}
	route, ok := c.routeMap[req.Name]
	if !ok {
		return nil, fmt.Errorf("unknown tool: %q", req.Name)
	}
	upstreamReq := &mcp.ToolsCallRequest{
		Name:      route.originalName,
		Arguments: req.Arguments,
	}
	result, err := route.client.ToolsCall(ctx, upstreamReq)
	if err != nil {
		return &CallResult{UpstreamID: route.upstreamID}, err
	}
	return &CallResult{
		UpstreamID: route.upstreamID,
		Result:     result,
	}, nil
}

// getCache returns a valid cache without holding mu during network I/O.
//
// Three states:
//  1. Valid cache (not expired): fast path, returned under lock.
//  2. No cache yet (first load): serialize via loading channel — first caller
//     spawns a goroutine using the manager's lifecycle context; subsequent
//     callers wait without performing extra network I/O.
//  3. Stale cache: return stale data immediately and trigger one background
//     refresh goroutine (guarded by bgRefresh to prevent goroutine accumulation).
func (m *realManager) getCache(ctx context.Context) (*toolsCache, error) {
	m.mu.Lock()

	// Fast path: valid, unexpired cache.
	if m.cached != nil && time.Now().Before(m.cached.expiry) {
		c := m.cached
		m.mu.Unlock()
		return c, nil
	}

	// Stale path: return the old cache to callers immediately.
	// A single background goroutine refreshes the cache asynchronously.
	if m.cached != nil {
		stale := m.cached
		m.mu.Unlock()
		if m.bgRefresh.CompareAndSwap(false, true) {
			go func() {
				defer m.bgRefresh.Store(false)
				ctx2, cancel := context.WithTimeout(m.ctx, 30*time.Second)
				defer cancel()
				if _, err := m.doRefresh(ctx2); err != nil && m.ctx.Err() == nil {
					slog.Default().Warn("upstream cache refresh failed",
						slog.String("error", err.Error()))
				}
			}()
		}
		return stale, nil
	}

	// First-load path: thundering herd prevention via a shared loading channel.
	// The first goroutine creates the channel and spawns a goroutine using the
	// manager's lifecycle context (not the first caller's context) so no single
	// caller is held hostage for the entire initial fetch.
	if m.loading != nil {
		ch := m.loading
		m.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		m.mu.Lock()
		c := m.cached
		m.mu.Unlock()
		if c == nil {
			return nil, fmt.Errorf("upstream: initial load failed")
		}
		return c, nil
	}

	// We are the first goroutine: create the loading channel and fetch
	// in a background goroutine using the server's lifecycle context.
	ch := make(chan struct{})
	m.loading = ch
	m.mu.Unlock()

	go func() {
		if _, err := m.doRefresh(m.ctx); err != nil && m.ctx.Err() == nil {
			slog.Default().Warn("upstream initial load failed",
				slog.String("error", err.Error()))
		}
		m.mu.Lock()
		m.loading = nil
		m.mu.Unlock()
		close(ch)
	}()

	// Wait for the load to complete or the caller's context to expire.
	select {
	case <-ch:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	m.mu.Lock()
	c := m.cached
	m.mu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("upstream: initial load failed")
	}
	return c, nil
}

// doRefresh fetches tools from all upstreams and atomically updates the cache.
// It never holds mu during network I/O.
func (m *realManager) doRefresh(ctx context.Context) (*toolsCache, error) {
	var tools []mcp.Tool
	routeMap := make(map[string]toolRoute)

	for _, entry := range m.entries {
		list, err := entry.Client.ToolsList(ctx)
		if err != nil {
			if m.metrics != nil {
				m.metrics.IncToolsRefreshFail(entry.ID)
			}
			return nil, fmt.Errorf("upstream %q tools/list: %w", entry.ID, err)
		}
		for _, t := range list {
			prefixed := entry.Prefix + "." + t.Name
			schema := t.InputSchema
			if len(schema) == 0 {
				schema = defaultInputSchema()
			}
			tools = append(tools, mcp.Tool{
				Name:        prefixed,
				Description: t.Description,
				InputSchema: schema,
			})
			routeMap[prefixed] = toolRoute{
				upstreamID:   entry.ID,
				client:       entry.Client,
				originalName: t.Name,
			}
		}
	}

	c := &toolsCache{
		tools:    tools,
		routeMap: routeMap,
		expiry:   time.Now().Add(m.cacheTTL),
	}
	m.mu.Lock()
	m.cached = c
	m.mu.Unlock()
	return c, nil
}
