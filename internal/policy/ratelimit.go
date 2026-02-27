package policy

import (
	"sync"
	"time"
)

// Limiter is the rate limiting interface used by the policy engine.
type Limiter interface {
	// Allow consumes one token for key in the current window.
	// Returns ok=true when the request is within the limit,
	// ok=false when the limit is exceeded.
	Allow(key string, max int, window time.Duration, now time.Time) (ok bool)
}

// ---- fixed-window implementation ----------------------------------------

type bucket struct {
	mu          sync.Mutex
	windowStart time.Time
	count       int
}

type fixedWindowLimiter struct {
	buckets sync.Map // string -> *bucket
}

// NewFixedWindowLimiter returns a Limiter backed by fixed-window counters.
// Each unique key has an independent window; state is in-process only.
func NewFixedWindowLimiter() Limiter {
	return &fixedWindowLimiter{}
}

func (l *fixedWindowLimiter) Allow(key string, max int, window time.Duration, now time.Time) bool {
	v, _ := l.buckets.LoadOrStore(key, &bucket{windowStart: now})
	b := v.(*bucket)
	b.mu.Lock()
	defer b.mu.Unlock()

	// Rotate window when expired.
	if now.Sub(b.windowStart) >= window {
		b.windowStart = now
		b.count = 0
	}

	if b.count >= max {
		return false
	}
	b.count++
	return true
}
