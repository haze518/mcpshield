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
	return &realManager{
		ctx:      ctx,
		entries:  entries,
		cacheTTL: ttl,
	}
}

// BgRefreshInProgress reports whether a background cache refresh goroutine
// is currently running.
func (m *realManager) BgRefreshInProgress() bool { return m.bgRefresh.Load() }
