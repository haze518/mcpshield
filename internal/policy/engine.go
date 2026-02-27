package policy

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/haze518/mcpshield/internal/mcp"
)

// Decision is the result of a policy evaluation.
type Decision struct {
	Action       string // "allow" | "deny"
	Rule         string // matched rule name (empty when not applicable)
	Reason       string // non-empty for deny
	RateLimited  bool   // true when the deny is due to rate limiting
	RetryAfterMs int64  // milliseconds until the rate-limit window resets (>0 when RateLimited)
}

// Engine evaluates policy for tool calls and controls the visible tool surface.
type Engine interface {
	Evaluate(ctx context.Context, call *mcp.ToolsCallRequest) Decision
	IsToolAllowed(name string) bool
}

// ---- context helpers ----------------------------------------------------

type ctxClientKey struct{}

// ContextWithClientID stores the authenticated client ID in ctx so the policy
// engine can use it for per-client rate limit bucketing.
func ContextWithClientID(ctx context.Context, clientID string) context.Context {
	return context.WithValue(ctx, ctxClientKey{}, clientID)
}

func clientIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxClientKey{}).(string)
	return v
}

// ---- deny-all engine ----------------------------------------------------

type denyAllEngine struct{}

// NewDenyAllEngine returns an Engine that denies everything.
func NewDenyAllEngine() Engine {
	return &denyAllEngine{}
}

func (e *denyAllEngine) Evaluate(_ context.Context, _ *mcp.ToolsCallRequest) Decision {
	return Decision{Action: "deny", Rule: "default", Reason: "deny-by-default policy"}
}

func (e *denyAllEngine) IsToolAllowed(_ string) bool { return false }

// ---- YAML policy engine -------------------------------------------------

// YAMLPolicyEngine evaluates a CompiledPolicy with support for atomic hot-swap.
type YAMLPolicyEngine struct {
	policy  atomic.Value // stores *CompiledPolicy; nil means deny-all (fail-closed)
	limiter Limiter
	timeNow func() time.Time
}

// NewYAMLPolicyEngine creates an engine loaded with initial policy.
// Pass nil to start in deny-all mode until the first Swap.
func NewYAMLPolicyEngine(initial *CompiledPolicy) *YAMLPolicyEngine {
	return NewYAMLPolicyEngineWithOptions(initial, NewFixedWindowLimiter(), time.Now)
}

// NewYAMLPolicyEngineWithOptions creates an engine with injected limiter and
// clock — useful for deterministic tests.
func NewYAMLPolicyEngineWithOptions(initial *CompiledPolicy, limiter Limiter, timeNow func() time.Time) *YAMLPolicyEngine {
	e := &YAMLPolicyEngine{
		limiter: limiter,
		timeNow: timeNow,
	}
	if initial != nil {
		e.policy.Store(initial)
	}
	return e
}

// Swap atomically replaces the active policy. Safe for concurrent use.
func (e *YAMLPolicyEngine) Swap(p *CompiledPolicy) {
	if p == nil {
		return
	}
	e.policy.Store(p)
}

func (e *YAMLPolicyEngine) load() *CompiledPolicy {
	v := e.policy.Load()
	if v == nil {
		return nil
	}
	return v.(*CompiledPolicy)
}

// IsToolAllowed reports whether the tool appears in any allow rule's surface.
// Returns false (fail-closed) when no policy is loaded.
func (e *YAMLPolicyEngine) IsToolAllowed(name string) bool {
	p := e.load()
	if p == nil {
		return false
	}
	_, ok := p.allowedSurface[name]
	return ok
}

// Evaluate runs the full deny-by-default algorithm against call, then checks
// rate limits on matching allow rules.
// Returns deny (fail-closed) when no policy is loaded.
func (e *YAMLPolicyEngine) Evaluate(ctx context.Context, call *mcp.ToolsCallRequest) Decision {
	p := e.load()
	if p == nil {
		return Decision{Action: "deny", Reason: "no policy loaded"}
	}

	d := p.evaluate(call)
	if d.Action != "allow" {
		return d
	}

	// Check rate limits on allow rules that cover this tool.
	now := e.timeNow()
	clientID := clientIDFromContext(ctx)

	for _, rule := range p.allowRules {
		if _, ok := rule.tools[call.Name]; !ok {
			continue
		}
		if rule.rateLimit == nil {
			continue
		}
		rl := rule.rateLimit
		key := fmt.Sprintf("global:%s:%s", rule.name, call.Name)
		if rl.per == "client" {
			key = fmt.Sprintf("client:%s:%s:%s", clientID, rule.name, call.Name)
		}
		if !e.limiter.Allow(key, rl.max, rl.window, now) {
			return Decision{
				Action:       "deny",
				Rule:         rule.name,
				Reason:       "rate limit exceeded",
				RateLimited:  true,
				RetryAfterMs: rl.window.Milliseconds(),
			}
		}
	}

	return d
}
