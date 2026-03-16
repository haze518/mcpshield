// export_test.go — compiled only during `go test`. Exposes internal helpers
// for the external upstream_test package.
package upstream

import (
	"context"
	"time"
)

// NewManagerWithTTL creates a realManager with a custom cache TTL.
// Used by upstream_test to control cache expiry in unit tests.
func NewManagerWithTTL(ctx context.Context, entries []Entry, ttl time.Duration) *realManager {
	mgr, err := NewManager(ctx, entries, ManagerConfig{
		ToolsCacheTTL:  ttl,
		RefreshTimeout: 30 * time.Second,
	})
	if err != nil {
		panic(err)
	}
	return mgr
}

func NewManagerWithConfig(ctx context.Context, entries []Entry, cfg ManagerConfig) *realManager {
	mgr, err := NewManager(ctx, entries, cfg)
	if err != nil {
		panic(err)
	}
	return mgr
}

// BgRefreshInProgress reports whether a background cache refresh goroutine
// is currently running.
func (m *realManager) BgRefreshInProgress() bool { return m.bgRefresh.Load() }

// LoadingInProgress reports whether initial warmup is currently in flight.
func (m *realManager) LoadingInProgress() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loading != nil
}
