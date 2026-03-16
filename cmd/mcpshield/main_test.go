package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/haze518/mcpshield/internal/audit"
	"github.com/haze518/mcpshield/pkg/config"
)

type warmupTestManager struct {
	mu       sync.Mutex
	ready    bool
	failures int
	calls    int
}

func (m *warmupTestManager) Warmup(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if m.failures > 0 {
		m.failures--
		return errors.New("warmup failed")
	}
	m.ready = true
	return nil
}

func (m *warmupTestManager) Ready() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready
}

// ---------------------------------------------------------------------------
// buildAuth: fail-open prevention
// ---------------------------------------------------------------------------

func TestBuildAuthEmptyTypeReturnsError(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{}, false)
	if err == nil {
		t.Fatal("expected error for empty auth.type, got nil")
	}
}

func TestBuildAuthNoneRequiresInsecureFlag(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{Type: "none"}, false)
	if err == nil {
		t.Fatal("expected error for auth.type='none' without insecure_allow_anonymous: true")
	}
}

func TestBuildAuthNoneSucceedsWithInsecureFlag(t *testing.T) {
	a, err := buildAuth(config.AuthConfig{Type: "none"}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestBuildAuthAPIKeyRequiresKeys(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{Type: "api_key"}, false)
	if err == nil {
		t.Fatal("expected error for api_key with no keys")
	}
}

func TestBuildAuthAPIKeyMissingKeyHashReturnsError(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{
		Type: "api_key",
		Keys: []config.AuthKeyConfig{
			{ID: "k1", KeyHash: "", ClientID: "team"},
		},
	}, false)
	if err == nil {
		t.Fatal("expected error for missing key_hash")
	}
}

func TestBuildAuthAPIKeyMissingClientIDReturnsError(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{
		Type: "api_key",
		Keys: []config.AuthKeyConfig{
			{ID: "k1", KeyHash: "sha256:abc", ClientID: ""},
		},
	}, false)
	if err == nil {
		t.Fatal("expected error for missing client_id")
	}
}

func TestBuildAuthAPIKeySucceeds(t *testing.T) {
	a, err := buildAuth(config.AuthConfig{
		Type: "api_key",
		Keys: []config.AuthKeyConfig{
			{ID: "k1", KeyHash: "sha256:abc123", ClientID: "team"},
		},
	}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

func TestBuildAuthUnknownTypeReturnsError(t *testing.T) {
	_, err := buildAuth(config.AuthConfig{Type: "jwt"}, false)
	if err == nil {
		t.Fatal("expected error for unknown auth type 'jwt'")
	}
}

func TestRunReplayReadOnlyBySession(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	store, err := audit.NewSQLiteStore(config.AuditSQLiteConfig{Path: dbPath, WAL: true})
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	base := time.Now()
	err = store.InsertBatch(context.Background(), []*audit.StoredEvent{
		{EventID: "e1", TsUnixNano: base.UnixNano(), SessionID: "session-1", ClientID: "client-1", Method: "initialize", Decision: "allow", UpstreamID: "gateway", EventHash: "h1"},
		{EventID: "e2", TsUnixNano: base.Add(time.Millisecond).UnixNano(), SessionID: "session-1", ClientID: "client-1", Method: "tools/call", ToolName: "filesystem.read_file", Decision: "allow", UpstreamID: "stub", ResponseJSON: `{"content":[{"type":"text","text":"ok"}]}`, EventHash: "h2"},
		{EventID: "e3", TsUnixNano: base.Add(2 * time.Millisecond).UnixNano(), SessionID: "session-2", ClientID: "client-2", Method: "tools/call", ToolName: "github.search_repositories", Decision: "deny", UpstreamID: "gateway", ErrorJSON: `{"message":"denied"}`, EventHash: "h3"},
	})
	if err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}
	_ = store.Close()

	var out bytes.Buffer
	runErr := runReplayTo(context.Background(), dbPath, "session-1", "read-only", "", &out)
	if runErr != nil {
		t.Fatalf("runReplay: %v", runErr)
	}
	if !bytes.Contains(out.Bytes(), []byte("session-1")) {
		t.Fatalf("expected session-1 in output, got %q", out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("client-1")) {
		t.Fatalf("expected client-1 in output, got %q", out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("session-2")) {
		t.Fatalf("did not expect session-2 in output, got %q", out.String())
	}
}

func TestRunWarmupUntilReadyRetriesUntilSuccess(t *testing.T) {
	mgr := &warmupTestManager{failures: 2}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runWarmupUntilReady(ctx, mgr, 50*time.Millisecond, 10*time.Millisecond, nilLogger())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("runWarmupUntilReady did not finish")
	}
	if !mgr.Ready() {
		t.Fatal("manager must be ready after retries succeed")
	}
	if mgr.calls < 3 {
		t.Fatalf("expected at least 3 warmup attempts, got %d", mgr.calls)
	}
}

func TestRunWarmupUntilReadyStopsOnCancel(t *testing.T) {
	mgr := &warmupTestManager{failures: 100}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runWarmupUntilReady(ctx, mgr, 50*time.Millisecond, 10*time.Millisecond, nilLogger())
		close(done)
	}()

	time.Sleep(25 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("runWarmupUntilReady did not stop on cancel")
	}
	if mgr.Ready() {
		t.Fatal("manager must not become ready after cancellation")
	}
}

func nilLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
}
