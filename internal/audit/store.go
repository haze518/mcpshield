package audit

import (
	"context"
	"time"
)

// StoredEvent is the database-level representation of an audit event.
// EventID is stored as a UUID string (TEXT in SQLite).
// All hash-chain fields are set by the writer goroutine before insertion.
type StoredEvent struct {
	EventID       string
	TsUnixNano    int64
	TraceID       string
	SpanID        string
	SessionID     string
	RequestID     string
	ClientID      string
	Method        string
	ToolName      string
	UpstreamID    string
	Decision      string
	PolicyRule    string
	Reason        string
	ArgumentsJSON string
	ResponseJSON  string
	ErrorJSON     string
	DurationUs    int64
	PrevHash      string
	EventHash     string
}

// Store is the persistence interface for audit events.
type Store interface {
	// InsertBatch inserts events in a single transaction.
	// EventHash and PrevHash must be pre-computed by the caller.
	InsertBatch(ctx context.Context, events []*StoredEvent) error

	// LastHash returns the event_hash of the most recently inserted event,
	// or "" if the store is empty.
	LastHash(ctx context.Context) (string, error)

	// Scan calls fn for each event ordered by (ts_unix_nano, event_id).
	// If since is non-zero, only events with ts >= since are returned.
	Scan(ctx context.Context, since time.Time, fn func(*StoredEvent) error) error

	// ScanSession calls fn for events matching session_id, ordered by ts.
	ScanSession(ctx context.Context, sessionID string, fn func(*StoredEvent) error) error

	// DeleteBefore deletes events with ts < cutoff. Returns the number of deleted rows.
	DeleteBefore(ctx context.Context, cutoff time.Time) (int64, error)

	// DBSize returns the size of the backing database file in bytes.
	DBSize(ctx context.Context) (int64, error)

	// TrimToSize deletes the oldest rows until DBSize <= maxBytes.
	TrimToSize(ctx context.Context, maxBytes int64) error

	// ResealChain recomputes all hashes from scratch starting from the oldest
	// remaining event (prev_hash = ""). Must be called after retention deletions
	// to maintain a verifiable chain. Safe to call on an empty store (no-op).
	ResealChain(ctx context.Context) error

	// Close releases all resources held by the store.
	Close() error
}
