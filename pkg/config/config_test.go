package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/haze518/mcpshield/pkg/config"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadRejectsNonPositiveSessionTTL(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
  session_ttl: "-1m"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.BuildRuntime(); err == nil {
		t.Fatal("expected invalid session_ttl to fail")
	}
}

func TestLoadWithoutSessionMaxEntriesSucceeds(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("expected config without session_max_entries to succeed: %v", err)
	}
	if _, err := cfg.BuildRuntime(); err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	if cfg.Server.SessionMaxEntries != nil {
		t.Fatalf("expected session_max_entries to be nil when omitted, got %v", *cfg.Server.SessionMaxEntries)
	}
}

func TestLoadRejectsZeroSessionMaxEntries(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
  session_max_entries: 0
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.BuildRuntime(); err == nil {
		t.Fatal("expected zero session_max_entries to fail")
	}
}

func TestLoadRejectsNegativeSessionMaxEntries(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
  session_max_entries: -1
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.BuildRuntime(); err == nil {
		t.Fatal("expected negative session_max_entries to fail")
	}
}

func TestLoadAcceptsPositiveSessionMaxEntries(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
  session_max_entries: 100
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("expected positive session_max_entries to succeed: %v", err)
	}
	if _, err := cfg.BuildRuntime(); err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	if cfg.Server.SessionMaxEntries == nil || *cfg.Server.SessionMaxEntries != 100 {
		t.Fatalf("expected parsed session_max_entries=100, got %+v", cfg.Server.SessionMaxEntries)
	}
}

func TestLoadIgnoresSessionMaxEntriesSubstringWhenFieldOmitted(t *testing.T) {
	path := writeConfig(t, `
# session_max_entries: 0
server:
  listen: ":8080"
auth:
  type: "none"
policy_file: "session_max_entries is only mentioned here as plain text"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("expected omitted field with matching substring elsewhere to succeed: %v", err)
	}
	if _, err := cfg.BuildRuntime(); err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	if cfg.Server.SessionMaxEntries != nil {
		t.Fatalf("expected session_max_entries to remain nil, got %v", *cfg.Server.SessionMaxEntries)
	}
}

func TestLoadRejectsNonPositiveWarmupRetryInterval(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
  warmup_retry_interval: "0s"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.BuildRuntime(); err == nil {
		t.Fatal("expected non-positive warmup_retry_interval to fail")
	}
}

func TestLoadAcceptsPositiveWarmupRetryInterval(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
  warmup_retry_interval: "3s"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.BuildRuntime(); err != nil {
		t.Fatalf("expected positive warmup_retry_interval to succeed: %v", err)
	}
}

func TestLoadParsesRuntimeDurationsAndLimits(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":9090"
  max_request_bytes: 2048
  request_timeout: "45s"
  read_timeout: "15s"
  write_timeout: "16s"
  idle_timeout: "90s"
  warmup_timeout: "12s"
  warmup_retry_interval: "7s"
  session_ttl: "40m"
  session_max_entries: 50
upstreams:
  - id: mock
    prefix: mock
    url: http://localhost:9090/mcp
    request_timeout: "9s"
    max_response_bytes: 8192
    tools_cache_ttl: "20s"
    refresh_timeout: "40s"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	runtime, err := cfg.BuildRuntime()
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	if runtime.Server.Listen != ":9090" {
		t.Fatalf("Listen: want :9090, got %q", runtime.Server.Listen)
	}
	if runtime.Server.MaxRequestBytes != 2048 {
		t.Fatalf("MaxRequestBytes: want 2048, got %d", runtime.Server.MaxRequestBytes)
	}
	if runtime.Server.RequestTimeout != 45_000*time.Millisecond {
		t.Fatalf("RequestTimeout: got %v", runtime.Server.RequestTimeout)
	}
	if runtime.Server.WarmupTimeout != 12*time.Second {
		t.Fatalf("WarmupTimeout: got %v", runtime.Server.WarmupTimeout)
	}
	if len(runtime.Upstreams) != 1 {
		t.Fatalf("Upstreams: want 1, got %d", len(runtime.Upstreams))
	}
	if runtime.Upstreams[0].RequestTimeout != 9*time.Second {
		t.Fatalf("Upstream RequestTimeout: got %v", runtime.Upstreams[0].RequestTimeout)
	}
	if runtime.Upstreams[0].MaxResponseBytes != 8192 {
		t.Fatalf("Upstream MaxResponseBytes: got %d", runtime.Upstreams[0].MaxResponseBytes)
	}
	if runtime.UpstreamManager.ToolsCacheTTL != 20*time.Second {
		t.Fatalf("Manager ToolsCacheTTL: got %v", runtime.UpstreamManager.ToolsCacheTTL)
	}
	if runtime.UpstreamManager.RefreshTimeout != 40*time.Second {
		t.Fatalf("Manager RefreshTimeout: got %v", runtime.UpstreamManager.RefreshTimeout)
	}
}

func TestLoadRejectsInvalidDurationFields(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
  request_timeout: "not-a-duration"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.BuildRuntime(); err == nil {
		t.Fatal("expected invalid duration to fail")
	}
}

func TestLoadRejectsNonPositiveDurationFields(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
  warmup_timeout: "0s"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.BuildRuntime(); err == nil {
		t.Fatal("expected non-positive duration to fail")
	}
}

func TestLoadRejectsNonPositiveByteLimitsWhenExplicitlySet(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
  max_request_bytes: 0
upstreams:
  - id: mock
    prefix: mock
    url: http://localhost:9090/mcp
    max_response_bytes: -1
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.BuildRuntime(); err == nil {
		t.Fatal("expected non-positive byte limits to fail")
	}
}

func TestBuildRuntimeDoesNotMutateRawConfig(t *testing.T) {
	path := writeConfig(t, `
server:
  request_timeout: "45s"
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != "" {
		t.Fatalf("raw config should preserve omitted listen, got %q", cfg.Server.Listen)
	}
	runtime, err := cfg.BuildRuntime()
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	if runtime.Server.Listen != ":8080" {
		t.Fatalf("runtime default listen: want :8080, got %q", runtime.Server.Listen)
	}
	if cfg.Server.Listen != "" {
		t.Fatalf("BuildRuntime must not mutate raw config, got %q", cfg.Server.Listen)
	}
}

func TestBuildRuntimeAppliesDefaultsExplicitly(t *testing.T) {
	path := writeConfig(t, `
server: {}
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	runtime, err := cfg.BuildRuntime()
	if err != nil {
		t.Fatalf("BuildRuntime: %v", err)
	}
	if runtime.Server.RequestTimeout <= 0 || runtime.Server.MaxRequestBytes <= 0 {
		t.Fatal("expected defaults to be applied in runtime config")
	}
}
