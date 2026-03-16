package config_test

import (
	"os"
	"path/filepath"
	"testing"

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
	if _, err := config.Load(path); err == nil {
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
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected zero session_max_entries to fail")
	}
}

func TestLoadRejectsNegativeSessionMaxEntries(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
  session_max_entries: -1
`)
	if _, err := config.Load(path); err == nil {
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
	if _, err := config.Load(path); err == nil {
		t.Fatal("expected non-positive warmup_retry_interval to fail")
	}
}

func TestLoadAcceptsPositiveWarmupRetryInterval(t *testing.T) {
	path := writeConfig(t, `
server:
  listen: ":8080"
  warmup_retry_interval: "3s"
`)
	if _, err := config.Load(path); err != nil {
		t.Fatalf("expected positive warmup_retry_interval to succeed: %v", err)
	}
}
