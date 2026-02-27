package policy_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/haze518/mcpshield/internal/mcp"
	"github.com/haze518/mcpshield/internal/policy"
)

const fixturePolicy = `
version: "1"

defaults:
  action: deny

toolsets:
  read_only:
    tools:
      - "filesystem.read_file"
      - "github.search_repositories"

rules:
  - name: "allow-read-only"
    action: allow
    toolset: read_only

  - name: "block-sensitive-paths"
    action: deny
    tools:
      - "filesystem.read_file"
    args:
      path:
        not_match: "^/etc/|^/root/"
    reason: "sensitive path"
`

func mustLoad(t *testing.T, yaml string) *policy.CompiledPolicy {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	return p
}

// ---- loader validation --------------------------------------------------

func TestLoaderAcceptsValidPolicy(t *testing.T) {
	p := mustLoad(t, fixturePolicy)
	if p == nil {
		t.Fatal("expected non-nil CompiledPolicy")
	}
}

func TestLoaderRejectsWrongVersion(t *testing.T) {
	_, err := policy.LoadFromBytes([]byte(`version: "2"\nrules: []`))
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestLoaderRejectsRuleWithoutToolsOrToolset(t *testing.T) {
	yaml := `
version: "1"
rules:
  - name: bad
    action: allow
`
	_, err := policy.LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error: rule must have tools or toolset")
	}
}

func TestLoaderRejectsDuplicateRuleNames(t *testing.T) {
	yaml := `
version: "1"
rules:
  - name: dup
    action: allow
    tools: ["tool.a"]
  - name: dup
    action: deny
    tools: ["tool.b"]
`
	_, err := policy.LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for duplicate rule name")
	}
}

func TestLoaderRejectsUnknownToolset(t *testing.T) {
	yaml := `
version: "1"
rules:
  - name: r1
    action: allow
    toolset: does_not_exist
`
	_, err := policy.LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for unknown toolset reference")
	}
}

func TestLoaderRejectsInvalidRegex(t *testing.T) {
	yaml := `
version: "1"
rules:
  - name: r1
    action: deny
    tools: ["tool.x"]
    args:
      path:
        not_match: "[invalid"
`
	_, err := policy.LoadFromBytes([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestLoaderCompilesRegex(t *testing.T) {
	// If regex compiles without error the CompiledPolicy is returned.
	yaml := `
version: "1"
rules:
  - name: r1
    action: deny
    tools: ["tool.x"]
    args:
      path:
        not_match: "^/etc/|^/root/"
`
	p, err := policy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == nil {
		t.Fatal("expected compiled policy")
	}
}

// ---- IsToolAllowed ------------------------------------------------------

func TestIsToolAllowedReturnsTrue(t *testing.T) {
	e := policy.NewYAMLPolicyEngine(mustLoad(t, fixturePolicy))
	if !e.IsToolAllowed("filesystem.read_file") {
		t.Error("filesystem.read_file should be in allowed surface")
	}
	if !e.IsToolAllowed("github.search_repositories") {
		t.Error("github.search_repositories should be in allowed surface")
	}
}

func TestIsToolAllowedReturnsFalseForUnknown(t *testing.T) {
	e := policy.NewYAMLPolicyEngine(mustLoad(t, fixturePolicy))
	if e.IsToolAllowed("dangerous.delete_everything") {
		t.Error("dangerous.delete_everything should not be allowed")
	}
}

func TestIsToolAllowedWithNilPolicy(t *testing.T) {
	e := policy.NewYAMLPolicyEngine(nil)
	if e.IsToolAllowed("any.tool") {
		t.Error("nil policy should deny all tools")
	}
}

// ---- Evaluate -----------------------------------------------------------

func TestEvaluateAllowsToolWithSafeArgs(t *testing.T) {
	e := policy.NewYAMLPolicyEngine(mustLoad(t, fixturePolicy))
	d := e.Evaluate(context.Background(), &mcp.ToolsCallRequest{
		Name:      "filesystem.read_file",
		Arguments: map[string]any{"path": "/home/user/file.txt"},
	})
	if d.Action != "allow" {
		t.Errorf("want allow, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestEvaluateDeniesToolNotInSurface(t *testing.T) {
	e := policy.NewYAMLPolicyEngine(mustLoad(t, fixturePolicy))
	d := e.Evaluate(context.Background(), &mcp.ToolsCallRequest{
		Name: "filesystem.delete_file",
	})
	if d.Action != "deny" {
		t.Errorf("want deny, got %s", d.Action)
	}
}

func TestEvaluateDenyRuleTriggersOnSensitivePath(t *testing.T) {
	e := policy.NewYAMLPolicyEngine(mustLoad(t, fixturePolicy))
	d := e.Evaluate(context.Background(), &mcp.ToolsCallRequest{
		Name:      "filesystem.read_file",
		Arguments: map[string]any{"path": "/etc/passwd"},
	})
	if d.Action != "deny" {
		t.Errorf("want deny, got %s", d.Action)
	}
	if d.Rule != "block-sensitive-paths" {
		t.Errorf("rule: want block-sensitive-paths, got %q", d.Rule)
	}
	if d.Reason != "sensitive path" {
		t.Errorf("reason: want 'sensitive path', got %q", d.Reason)
	}
}

func TestEvaluateDenyRuleTriggersOnRootPath(t *testing.T) {
	e := policy.NewYAMLPolicyEngine(mustLoad(t, fixturePolicy))
	d := e.Evaluate(context.Background(), &mcp.ToolsCallRequest{
		Name:      "filesystem.read_file",
		Arguments: map[string]any{"path": "/root/.ssh/id_rsa"},
	})
	if d.Action != "deny" {
		t.Errorf("want deny, got %s", d.Action)
	}
	if d.Rule != "block-sensitive-paths" {
		t.Errorf("rule: want block-sensitive-paths, got %q", d.Rule)
	}
}

func TestEvaluateDenyRuleMissingArg(t *testing.T) {
	// Deny rule has a validator for "path"; if path is absent the validator fails → deny.
	e := policy.NewYAMLPolicyEngine(mustLoad(t, fixturePolicy))
	d := e.Evaluate(context.Background(), &mcp.ToolsCallRequest{
		Name:      "filesystem.read_file",
		Arguments: map[string]any{},
	})
	if d.Action != "deny" {
		t.Errorf("want deny for missing path, got %s", d.Action)
	}
}

func TestEvaluateAllowsGitHubSearch(t *testing.T) {
	e := policy.NewYAMLPolicyEngine(mustLoad(t, fixturePolicy))
	d := e.Evaluate(context.Background(), &mcp.ToolsCallRequest{
		Name:      "github.search_repositories",
		Arguments: map[string]any{"query": "mcpshield"},
	})
	if d.Action != "allow" {
		t.Errorf("want allow, got %s (reason: %s)", d.Action, d.Reason)
	}
}

func TestEvaluateWithNilPolicyDenies(t *testing.T) {
	e := policy.NewYAMLPolicyEngine(nil)
	d := e.Evaluate(context.Background(), &mcp.ToolsCallRequest{Name: "any.tool"})
	if d.Action != "deny" {
		t.Errorf("want deny with nil policy, got %s", d.Action)
	}
}

func TestHotSwap(t *testing.T) {
	// Start deny-all, swap to permissive policy, verify.
	e := policy.NewYAMLPolicyEngine(nil)
	if e.IsToolAllowed("filesystem.read_file") {
		t.Error("expected deny before swap")
	}

	p := mustLoad(t, fixturePolicy)
	e.Swap(p)

	if !e.IsToolAllowed("filesystem.read_file") {
		t.Error("expected allow after swap")
	}
}

func TestDenyAllEngineIsToolAllowed(t *testing.T) {
	e := policy.NewDenyAllEngine()
	if e.IsToolAllowed("anything") {
		t.Error("deny-all engine should not allow any tool")
	}
}

func TestDenyAllEngineEvaluate(t *testing.T) {
	e := policy.NewDenyAllEngine()
	d := e.Evaluate(context.Background(), &mcp.ToolsCallRequest{Name: "any.tool"})
	if d.Action != "deny" {
		t.Errorf("want deny, got %s", d.Action)
	}
	if !strings.Contains(d.Reason, "deny") {
		t.Errorf("reason should mention deny, got %q", d.Reason)
	}
}

// ---- rate limit tests ---------------------------------------------------

const rateLimitPolicy = `
version: "1"
rules:
  - name: allow-fs-limited
    action: allow
    tools:
      - filesystem.read_file
    rate_limit:
      max: 2
      window: "60s"
      per: global
`

const rateLimitPerClientPolicy = `
version: "1"
rules:
  - name: allow-fs-per-client
    action: allow
    tools:
      - filesystem.read_file
    rate_limit:
      max: 1
      window: "60s"
      per: client
`

func rateLimitEngine(t *testing.T, yaml string, now time.Time) *policy.YAMLPolicyEngine {
	t.Helper()
	p := mustLoad(t, yaml)
	return policy.NewYAMLPolicyEngineWithOptions(p, policy.NewFixedWindowLimiter(), func() time.Time { return now })
}

func TestRateLimitAllowsUpToMax(t *testing.T) {
	now := time.Now()
	e := rateLimitEngine(t, rateLimitPolicy, now)
	call := &mcp.ToolsCallRequest{Name: "filesystem.read_file"}
	for i := range 2 {
		d := e.Evaluate(context.Background(), call)
		if d.Action != "allow" {
			t.Errorf("call %d: want allow, got %s (reason: %s)", i+1, d.Action, d.Reason)
		}
	}
}

func TestRateLimitDeniesAfterMax(t *testing.T) {
	now := time.Now()
	e := rateLimitEngine(t, rateLimitPolicy, now)
	call := &mcp.ToolsCallRequest{Name: "filesystem.read_file"}

	e.Evaluate(context.Background(), call)
	e.Evaluate(context.Background(), call)

	d := e.Evaluate(context.Background(), call)
	if d.Action != "deny" {
		t.Fatalf("want deny after max, got %s", d.Action)
	}
	if !d.RateLimited {
		t.Error("want RateLimited=true")
	}
	if d.RetryAfterMs != 60_000 {
		t.Errorf("RetryAfterMs: want 60000, got %d", d.RetryAfterMs)
	}
}

func TestRateLimitPerClientIsolation(t *testing.T) {
	now := time.Now()
	e := rateLimitEngine(t, rateLimitPerClientPolicy, now)
	call := &mcp.ToolsCallRequest{Name: "filesystem.read_file"}

	ctxA := policy.ContextWithClientID(context.Background(), "alice")
	ctxB := policy.ContextWithClientID(context.Background(), "bob")

	// Exhaust alice's quota.
	e.Evaluate(ctxA, call)
	dA := e.Evaluate(ctxA, call)
	if dA.Action != "deny" || !dA.RateLimited {
		t.Errorf("alice: want rate-limited deny, got action=%s RateLimited=%v", dA.Action, dA.RateLimited)
	}

	// Bob should still be allowed.
	dB := e.Evaluate(ctxB, call)
	if dB.Action != "allow" {
		t.Errorf("bob: want allow (independent bucket), got %s", dB.Action)
	}
}
