package audit

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/haze518/mcpshield/pkg/config"
)

const schema = `
CREATE TABLE IF NOT EXISTS audit_events (
    event_id       TEXT    PRIMARY KEY,
    ts_unix_nano   INTEGER NOT NULL,
    trace_id       TEXT    NOT NULL DEFAULT '',
    span_id        TEXT    NOT NULL DEFAULT '',
    session_id     TEXT    NOT NULL DEFAULT '',
    request_id     TEXT    NOT NULL DEFAULT '',
    client_id      TEXT    NOT NULL DEFAULT '',
    method         TEXT    NOT NULL,
    tool_name      TEXT    NOT NULL DEFAULT '',
    upstream_id    TEXT    NOT NULL DEFAULT '',
    decision       TEXT    NOT NULL,
    policy_rule    TEXT    NOT NULL DEFAULT '',
    reason         TEXT    NOT NULL DEFAULT '',
    arguments_json TEXT    NOT NULL DEFAULT '',
    response_json  TEXT    NOT NULL DEFAULT '',
    error_json     TEXT    NOT NULL DEFAULT '',
    duration_us    INTEGER NOT NULL DEFAULT 0,
    prev_hash      TEXT    NOT NULL DEFAULT '',
    event_hash     TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts          ON audit_events(ts_unix_nano);
CREATE INDEX IF NOT EXISTS idx_audit_tool_ts     ON audit_events(tool_name, ts_unix_nano);
CREATE INDEX IF NOT EXISTS idx_audit_session_ts  ON audit_events(session_id, ts_unix_nano);
CREATE INDEX IF NOT EXISTS idx_audit_decision_ts ON audit_events(decision, ts_unix_nano);
CREATE INDEX IF NOT EXISTS idx_audit_client_ts   ON audit_events(client_id, ts_unix_nano);
`

const insertSQL = `
INSERT INTO audit_events (
    event_id, ts_unix_nano, trace_id, span_id, session_id, request_id,
    client_id, method, tool_name, upstream_id, decision, policy_rule,
    reason, arguments_json, response_json, error_json, duration_us,
    prev_hash, event_hash
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

const scanSQL = `
SELECT event_id, ts_unix_nano, trace_id, span_id, session_id, request_id,
       client_id, method, tool_name, upstream_id, decision, policy_rule,
       reason, arguments_json, response_json, error_json, duration_us,
       prev_hash, event_hash
FROM audit_events
WHERE ts_unix_nano >= ?
ORDER BY ts_unix_nano, event_id`

const scanSessionSQL = `
SELECT event_id, ts_unix_nano, trace_id, span_id, session_id, request_id,
       client_id, method, tool_name, upstream_id, decision, policy_rule,
       reason, arguments_json, response_json, error_json, duration_us,
       prev_hash, event_hash
FROM audit_events
WHERE session_id = ?
ORDER BY ts_unix_nano, event_id`

type sqliteStore struct {
	db   *sql.DB
	path string
}

// NewSQLiteStore opens (or creates) the SQLite audit database at cfg.Path,
// applies the schema, and configures WAL / synchronous / busy-timeout.
//
// Synchronous defaults:
//   - WAL + Synchronous="FULL"  → fully durable (safe for fail_closed mode)
//   - WAL + Synchronous="NORMAL" → faster but risks data loss on OS crash
//   - no WAL                    → DELETE journal mode (default SQLite)
func NewSQLiteStore(cfg config.AuditSQLiteConfig) (*sqliteStore, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("audit: sqlite path is required")
	}

	db, err := sql.Open("sqlite", cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("open audit db: %w", err)
	}
	// Single writer goroutine — cap the pool to avoid SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	if cfg.WAL {
		if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
			return nil, fmt.Errorf("set WAL: %w", err)
		}
		// Default to FULL synchronous in WAL mode for maximum durability.
		// Operators may override to NORMAL for higher throughput.
		// OFF is explicitly rejected: it risks data loss on OS crash.
		sync := "FULL"
		if cfg.Synchronous != "" {
			sync = strings.ToUpper(cfg.Synchronous)
			switch sync {
			case "FULL", "NORMAL", "EXTRA":
				// accepted
			default:
				_ = db.Close()
				return nil, fmt.Errorf("audit: invalid sqlite.synchronous %q: must be FULL, NORMAL, or EXTRA", cfg.Synchronous)
			}
		}
		if _, err := db.Exec("PRAGMA synchronous=" + sync + ";"); err != nil {
			return nil, fmt.Errorf("set synchronous=%s: %w", sync, err)
		}
	}

	if cfg.BusyTimeout != "" {
		d, err := time.ParseDuration(cfg.BusyTimeout)
		if err != nil {
			return nil, fmt.Errorf("audit: invalid busy_timeout %q: %w", cfg.BusyTimeout, err)
		}
		ms := d.Milliseconds()
		if _, err := db.Exec(fmt.Sprintf("PRAGMA busy_timeout=%d;", ms)); err != nil {
			return nil, fmt.Errorf("set busy_timeout: %w", err)
		}
	}

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate audit schema: %w", err)
	}

	return &sqliteStore{db: db, path: cfg.Path}, nil
}

// InsertBatch inserts a slice of events in a single transaction.
func (s *sqliteStore) InsertBatch(ctx context.Context, events []*StoredEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range events {
		if _, err := stmt.ExecContext(ctx,
			e.EventID, e.TsUnixNano, e.TraceID, e.SpanID, e.SessionID,
			e.RequestID, e.ClientID, e.Method, e.ToolName, e.UpstreamID,
			e.Decision, e.PolicyRule, e.Reason, e.ArgumentsJSON,
			e.ResponseJSON, e.ErrorJSON, e.DurationUs, e.PrevHash, e.EventHash,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// LastHash returns the event_hash of the most recently inserted row, or "".
func (s *sqliteStore) LastHash(ctx context.Context) (string, error) {
	var h string
	err := s.db.QueryRowContext(ctx,
		"SELECT event_hash FROM audit_events ORDER BY ts_unix_nano DESC, event_id DESC LIMIT 1",
	).Scan(&h)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return h, err
}

// Scan streams all events with ts >= since (zero = all) ordered by (ts, event_id).
func (s *sqliteStore) Scan(ctx context.Context, since time.Time, fn func(*StoredEvent) error) error {
	var sinceNano int64
	if !since.IsZero() {
		sinceNano = since.UnixNano()
	}
	rows, err := s.db.QueryContext(ctx, scanSQL, sinceNano)
	if err != nil {
		return err
	}
	defer rows.Close()
	return scanRows(rows, fn)
}

// ScanSession streams events for a specific session, ordered by ts.
func (s *sqliteStore) ScanSession(ctx context.Context, sessionID string, fn func(*StoredEvent) error) error {
	rows, err := s.db.QueryContext(ctx, scanSessionSQL, sessionID)
	if err != nil {
		return err
	}
	defer rows.Close()
	return scanRows(rows, fn)
}

func scanRows(rows *sql.Rows, fn func(*StoredEvent) error) error {
	for rows.Next() {
		e := &StoredEvent{}
		if err := rows.Scan(
			&e.EventID, &e.TsUnixNano, &e.TraceID, &e.SpanID, &e.SessionID,
			&e.RequestID, &e.ClientID, &e.Method, &e.ToolName, &e.UpstreamID,
			&e.Decision, &e.PolicyRule, &e.Reason, &e.ArgumentsJSON,
			&e.ResponseJSON, &e.ErrorJSON, &e.DurationUs, &e.PrevHash, &e.EventHash,
		); err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}

// DeleteBefore deletes events older than cutoff. Returns deleted row count.
// After a successful deletion it runs PRAGMA wal_checkpoint(TRUNCATE) so that
// the reclaimed space is reflected in the WAL file size (and thus in DBSize).
func (s *sqliteStore) DeleteBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		"DELETE FROM audit_events WHERE ts_unix_nano < ?", cutoff.UnixNano())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		_, _ = s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	}
	return n, nil
}

// DBSize returns the total on-disk size in bytes of the database files:
// the main DB file plus the WAL (-wal) and shared-memory (-shm) sidecar files
// when they are present. This gives an accurate picture of the space consumed
// even while the WAL is active.
func (s *sqliteStore) DBSize(_ context.Context) (int64, error) {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(s.path + suffix)
		if err != nil {
			if os.IsNotExist(err) {
				continue // WAL / SHM may not exist yet
			}
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

// TrimToSize deletes oldest rows in chunks until the total DB size (including
// WAL and SHM) is <= maxBytes. A PRAGMA wal_checkpoint(TRUNCATE) is issued
// after each chunk so that the WAL file shrinks and DBSize converges.
func (s *sqliteStore) TrimToSize(ctx context.Context, maxBytes int64) error {
	for {
		size, err := s.DBSize(ctx)
		if err != nil || size <= maxBytes {
			return err
		}
		res, err := s.db.ExecContext(ctx, `
			DELETE FROM audit_events WHERE event_id IN (
				SELECT event_id FROM audit_events ORDER BY ts_unix_nano, event_id LIMIT 100
			)`)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		_, _ = s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	}
}

// ResealChain recomputes all hashes from scratch starting at the oldest remaining
// event (prev_hash = ""). This is called by the logger's writer goroutine after
// retention deletes rows that were part of the chain head.
//
// The entire operation runs inside a single transaction. On failure the chain is
// unchanged. On success, VerifyChain will pass on the remaining events.
//
// NOTE: Pruning intentionally resets the chain anchor. Integrity is guaranteed
// within the retained history; events before the oldest retained row are no
// longer part of the verifiable chain.
func (s *sqliteStore) ResealChain(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Read all remaining events — only the data fields needed for hashing.
	rows, err := tx.QueryContext(ctx, `
		SELECT event_id, ts_unix_nano, trace_id, span_id, session_id, request_id,
		       client_id, method, tool_name, upstream_id, decision, policy_rule,
		       reason, arguments_json, response_json, error_json, duration_us
		FROM audit_events
		ORDER BY ts_unix_nano, event_id`)
	if err != nil {
		return err
	}

	var events []*StoredEvent
	for rows.Next() {
		e := &StoredEvent{}
		if err := rows.Scan(
			&e.EventID, &e.TsUnixNano, &e.TraceID, &e.SpanID, &e.SessionID,
			&e.RequestID, &e.ClientID, &e.Method, &e.ToolName, &e.UpstreamID,
			&e.Decision, &e.PolicyRule, &e.Reason, &e.ArgumentsJSON,
			&e.ResponseJSON, &e.ErrorJSON, &e.DurationUs,
		); err != nil {
			rows.Close()
			return err
		}
		events = append(events, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	if len(events) == 0 {
		return tx.Commit() // nothing to reseal
	}

	stmt, err := tx.PrepareContext(ctx,
		"UPDATE audit_events SET prev_hash = ?, event_hash = ? WHERE event_id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	prevHash := ""
	for _, e := range events {
		h, err := ComputeHash(prevHash, e)
		if err != nil {
			return fmt.Errorf("reseal: ComputeHash for %s: %w", e.EventID, err)
		}
		if _, err := stmt.ExecContext(ctx, prevHash, h, e.EventID); err != nil {
			return fmt.Errorf("reseal: update %s: %w", e.EventID, err)
		}
		prevHash = h
	}

	return tx.Commit()
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}

// ---- retention config helpers (used by SQLiteAuditLogger) ---------------

type retentionCfg struct {
	maxAge         time.Duration
	maxSizeBytes   int64
	vacuumInterval time.Duration
}

func parseRetentionConfig(cfg config.AuditRetentionConfig) (retentionCfg, error) {
	var rc retentionCfg
	if cfg.MaxAge != "" {
		d, err := parseDuration(cfg.MaxAge)
		if err != nil {
			return rc, fmt.Errorf("audit: invalid retention.max_age: %w", err)
		}
		rc.maxAge = d
	}
	if cfg.MaxSize != "" {
		b, err := parseBytes(cfg.MaxSize)
		if err != nil {
			return rc, fmt.Errorf("audit: invalid retention.max_size: %w", err)
		}
		rc.maxSizeBytes = b
	}
	if cfg.VacuumInterval != "" {
		d, err := time.ParseDuration(cfg.VacuumInterval)
		if err != nil {
			return rc, fmt.Errorf("audit: invalid retention.vacuum_interval: %w", err)
		}
		rc.vacuumInterval = d
	} else if rc.maxAge > 0 || rc.maxSizeBytes > 0 {
		rc.vacuumInterval = 24 * time.Hour
	}
	return rc, nil
}

// ---- helper parsers -----------------------------------------------------

// parseDuration extends time.ParseDuration with "d" (days) suffix.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// parseBytes parses human-readable byte sizes like "10GB", "256MB".
func parseBytes(s string) (int64, error) {
	upper := strings.ToUpper(strings.TrimSpace(s))
	for _, unit := range []struct {
		sfx string
		mul int64
	}{
		{"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10},
	} {
		if strings.HasSuffix(upper, unit.sfx) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(upper, unit.sfx), 64)
			if err != nil {
				return 0, fmt.Errorf("invalid size %q", s)
			}
			return int64(n * float64(unit.mul)), nil
		}
	}
	return strconv.ParseInt(strings.TrimSpace(s), 10, 64)
}
