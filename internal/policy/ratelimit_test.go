package policy_test

import (
	"testing"
	"time"

	"github.com/haze518/mcpshield/internal/policy"
)

func TestFixedWindowLimiterAllowsUpToMax(t *testing.T) {
	l := policy.NewFixedWindowLimiter()
	now := time.Now()

	for i := range 3 {
		if !l.Allow("k", 3, time.Minute, now) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestFixedWindowLimiterDeniesAfterMax(t *testing.T) {
	l := policy.NewFixedWindowLimiter()
	now := time.Now()

	for range 3 {
		l.Allow("k", 3, time.Minute, now)
	}
	if l.Allow("k", 3, time.Minute, now) {
		t.Error("4th request should be denied")
	}
}

func TestFixedWindowLimiterResetsAfterWindow(t *testing.T) {
	l := policy.NewFixedWindowLimiter()
	t0 := time.Now()

	for range 3 {
		l.Allow("k", 3, time.Minute, t0)
	}
	// Advance past the window.
	t1 := t0.Add(61 * time.Second)
	if !l.Allow("k", 3, time.Minute, t1) {
		t.Error("first request after window reset should be allowed")
	}
}

func TestFixedWindowLimiterIsolatesKeys(t *testing.T) {
	l := policy.NewFixedWindowLimiter()
	now := time.Now()

	for range 3 {
		l.Allow("a", 3, time.Minute, now)
	}
	// Key "b" should have its own independent counter.
	if !l.Allow("b", 3, time.Minute, now) {
		t.Error("key 'b' should not be affected by key 'a' exhaustion")
	}
}
