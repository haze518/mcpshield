package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/haze518/mcpshield/pkg/config"
)
var (
	// ErrAuditFull is returned by Log in fail_closed mode when the write buffer is
	// full or when the last DB batch write failed. The gateway must deny the request.
	ErrAuditFull = errors.New("audit: write buffer full")
	ErrUnknownSqliteWriteMode = errors.New("audit: unknown sqlite write mode")
)

// Event is the application-level audit record created by the gateway.
type Event struct {
	// Core identity — populated by gateway.
	Timestamp  time.Time
	Action     string // JSON-RPC method, e.g. "tools/call"
	Tool       string // prefixed tool name
	Decision   string // "allow" | "deny" | "rate_limited"
	Reason     string
	PolicyRule string
	ClientID   string
	RequestID  string
	Duration   time.Duration
	Error      string

	// Extended fields — set when available.
	EventID    uuid.UUID
	TraceID    string
	SpanID     string
	SessionID  string
	UpstreamID string
	Arguments  map[string]any // serialised to arguments_json
	Response   any            // serialised to response_json
}

// AuditMetrics is implemented by observability.Registry. It is accepted by
// SQLiteAuditLogger.SetMetrics to wire Prometheus counters without creating
// an import cycle.
type AuditMetrics interface {
	IncAuditDropped(backend string)
	IncAuditWriteFail(backend string)
}

// Logger is the interface used by the gateway to record audit events.
//
// Semantics by mode:
//   - fail_closed: returns ErrAuditFull on queue-full OR last-DB-write failure.
//     The gateway must deny the request on non-nil error.
//   - best_effort: blocks until ctx is done; then drops and returns nil.
//   - drop:        never blocks; drops silently; always returns nil.
type Logger interface {
	Log(ctx context.Context, event *Event) error
	Close() error
}

// ---- noop logger --------------------------------------------------------

type noopLogger struct{}

func NewNoopLogger() Logger                          { return noopLogger{} }
func (noopLogger) Log(context.Context, *Event) error { return nil }
func (noopLogger) Close() error                      { return nil }

// ---- stdout logger ------------------------------------------------------

type stdoutLogger struct {
	ch   chan *Event
	done chan struct{}
}

func NewStdoutLogger() Logger {
	l := &stdoutLogger{
		ch:   make(chan *Event, 256),
		done: make(chan struct{}),
	}
	go l.run()
	return l
}

func (l *stdoutLogger) Log(_ context.Context, event *Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	select {
	case l.ch <- event:
	default:
		// drop silently — stdout logger is a dev-only tool
	}
	return nil
}

func (l *stdoutLogger) Close() error {
	close(l.ch)
	<-l.done
	return nil
}

func (l *stdoutLogger) run() {
	defer close(l.done)
	enc := json.NewEncoder(os.Stdout)
	for event := range l.ch {
		_ = enc.Encode(event)
	}
}

// ---- SQLite async batcher -----------------------------------------------


type sqliteWriteMode int8

const (
	sqliteWriteModeUnknown sqliteWriteMode = iota
	sqliteWriteModeBlock
	sqliteWriteModeFailClosed
	sqliteWriteModeBestEffort
	sqliteWriteModeDrop // non-blocking: never blocks, drops silently
)

func parseSqliteWriteMode(val string) (sqliteWriteMode, error) {
	switch val {
	case "block":
		return sqliteWriteModeBlock, nil
	case "fail_closed":
		return sqliteWriteModeFailClosed, nil
	case "best_effort":
		return sqliteWriteModeBestEffort, nil
	case "drop":
		return sqliteWriteModeDrop, nil
	default:
		return sqliteWriteModeUnknown, fmt.Errorf("%w: %q", ErrUnknownSqliteWriteMode, val)
	}
}

func (s sqliteWriteMode) String() string {
	switch s {
	case sqliteWriteModeBlock:
		return "block"
	case sqliteWriteModeBestEffort:
		return "best_effort"
	case sqliteWriteModeFailClosed:
		return "fail_closed"
	case sqliteWriteModeDrop:
		return "drop"
	default:
		return "unknown"
	}
}

type sqliteLoggerCfg struct {
	batchMaxEvents int
	batchMaxDelay  time.Duration
	mode           sqliteWriteMode
	hashChain      bool
}

// SQLiteAuditLogger is the production audit logger. It batches events
// asynchronously and writes them to a SQLite store with optional hash chaining.
//
// Retention (max_age, max_size) is run by the writer goroutine after each
// vacuum interval tick, ensuring it is always serialised with batch writes.
// This eliminates hash-chain races between concurrent goroutines.
type SQLiteAuditLogger struct {
	store    Store
	cfg      sqliteLoggerCfg
	ch       chan *Event
	done     chan struct{}
	dropped  atomic.Int64
	writes   atomic.Int64 // successful batch writes
	failures atomic.Int64 // failed batch writes (DB error)
	lastHash string       // maintained exclusively by the writer goroutine
	dbFailed atomic.Bool  // set on DB write error; cleared on success

	retention *retentionCfg // nil if not configured
	metrics   AuditMetrics  // optional; nil = no Prometheus counters
	log       *slog.Logger
}

// NewSQLiteAuditLogger constructs and starts the SQLite audit logger.
func NewSQLiteAuditLogger(cfg config.AuditConfig) (*SQLiteAuditLogger, error) {
	store, err := NewSQLiteStore(cfg.SQLite)
	if err != nil {
		return nil, err
	}

	batchDelay := 100 * time.Millisecond
	if cfg.Write.BatchMaxDelay != "" {
		if d, err2 := time.ParseDuration(cfg.Write.BatchMaxDelay); err2 == nil {
			batchDelay = d
		}
	}
	batchMax := cfg.Write.BatchMaxEvents
	if batchMax <= 0 {
		batchMax = 256
	}
	chanSize := cfg.Write.ChannelSize
	if chanSize <= 0 {
		chanSize = 4096
	}

	mode, err := parseSqliteWriteMode(cfg.Write.Mode)
	if err != nil {
		return nil, err
	}

	var retCfg *retentionCfg
	if rc, err := parseRetentionConfig(cfg.Retention); err != nil {
		_ = store.Close()
		return nil, err
	} else if rc.vacuumInterval > 0 {
		retCfg = &rc
	}

	l := &SQLiteAuditLogger{
		store: store,
		cfg: sqliteLoggerCfg{
			batchMaxEvents: batchMax,
			batchMaxDelay:  batchDelay,
			mode:           mode,
			hashChain:      cfg.Integrity.HashChain,
		},
		ch:        make(chan *Event, chanSize),
		done:      make(chan struct{}),
		retention: retCfg,
		log:       slog.Default(),
	}

	// Initialise the chain tip from DB before starting the goroutine.
	l.lastHash, _ = store.LastHash(context.Background())

	go l.run()
	return l, nil
}

// SetMetrics wires Prometheus counters for drops and write failures.
// Must be called before the first Log() call to be race-free.
func (l *SQLiteAuditLogger) SetMetrics(m AuditMetrics) { l.metrics = m }

// Dropped returns the count of events dropped since the logger started.
func (l *SQLiteAuditLogger) Dropped() int64 { return l.dropped.Load() }

// WriteFails returns the count of failed DB batch writes since the logger started.
func (l *SQLiteAuditLogger) WriteFails() int64 { return l.failures.Load() }

func (l *SQLiteAuditLogger) Log(ctx context.Context, event *Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.EventID == uuid.Nil {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("uuid.NewV7: %w", err)
		}
		event.EventID = id
	}

	switch l.cfg.mode {
	case sqliteWriteModeBlock:
		l.ch <- event
		return nil

	case sqliteWriteModeBestEffort:
		// Block until space available or context expires.
		select {
		case l.ch <- event:
			return nil
		case <-ctx.Done():
			l.reportDrop(1)
			return nil // never fails the request
		}

	case sqliteWriteModeDrop:
		// Non-blocking: drop immediately if channel is full.
		select {
		case l.ch <- event:
		default:
			l.reportDrop(1)
		}
		return nil

	default:
		// Reject immediately if the last batch write failed.
		if l.dbFailed.Load() {
			return ErrAuditFull
		}
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case l.ch <- event:
			return nil
		case <-ctx.Done():
			l.reportDrop(1)
			return ErrAuditFull
		case <-timer.C:
			l.reportDrop(1)
			return ErrAuditFull
		}
	}
}

func (l *SQLiteAuditLogger) Close() error {
	close(l.ch)
	<-l.done
	return l.store.Close()
}

// reportDrop increments the drop counter, emits a WARN log, and updates metrics.
func (l *SQLiteAuditLogger) reportDrop(n int64) {
	l.dropped.Add(n)
	l.log.Warn("audit events dropped",
		slog.Int64("count", n),
		slog.String("mode", l.cfg.mode.String()))
	if l.metrics != nil {
		for range n {
			l.metrics.IncAuditDropped("sqlite")
		}
	}
}

// reportWriteFail increments the failure counter, emits an ERROR log, and
// updates metrics. n is the number of events lost in the failed batch.
func (l *SQLiteAuditLogger) reportWriteFail(n int64, err error) {
	l.dropped.Add(n)
	l.failures.Add(1)
	l.dbFailed.Store(true)
	l.log.Error("audit batch write failed",
		slog.Int64("events_lost", n),
		slog.String("error", err.Error()))
	if l.metrics != nil {
		l.metrics.IncAuditWriteFail("sqlite")
		for range n {
			l.metrics.IncAuditDropped("sqlite")
		}
	}
}

// ---- writer goroutine ---------------------------------------------------

func (l *SQLiteAuditLogger) run() {
	defer close(l.done)

	batchTicker := time.NewTicker(l.cfg.batchMaxDelay)
	defer batchTicker.Stop()

	// Retention ticker: nil channel blocks forever (no retention case).
	var retentionCh <-chan time.Time
	if l.retention != nil {
		rt := time.NewTicker(l.retention.vacuumInterval)
		defer rt.Stop()
		retentionCh = rt.C
	}

	batch := make([]*Event, 0, l.cfg.batchMaxEvents)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		l.flushBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case e, ok := <-l.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= l.cfg.batchMaxEvents {
				flush()
			}
		case <-batchTicker.C:
			flush()
		case <-retentionCh:
			// Flush current batch first so retention sees all committed events.
			flush()
			l.runRetention()
		}
	}
}

// flushBatch writes a batch to the store.
//
// Hash-chain tip (lastHash) is only advanced AFTER a successful InsertBatch.
// If InsertBatch fails, lastHash is unchanged so the next successful batch
// chains correctly from the last committed event.
func (l *SQLiteAuditLogger) flushBatch(batch []*Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stored := make([]*StoredEvent, 0, len(batch))
	tip := l.lastHash // local copy; only written back on success

	for _, e := range batch {
		se := eventToStored(e)
		if l.cfg.hashChain {
			if h, err := ComputeHash(tip, se); err == nil {
				se.PrevHash = tip
				se.EventHash = h
				tip = h
			}
		} else {
			// Per-event hash without chaining (integrity of individual events).
			if h, err := ComputeHash("", se); err == nil {
				se.EventHash = h
			}
		}
		stored = append(stored, se)
	}

	if err := l.store.InsertBatch(ctx, stored); err != nil {
		// tip is NOT advanced — lastHash unchanged so chain stays valid.
		l.reportWriteFail(int64(len(batch)), err)
		return
	}

	// Only advance tip after commit succeeds.
	l.dbFailed.Store(false)
	l.writes.Add(1)
	l.lastHash = tip
}

// runRetention runs age and size retention, then reseals the hash chain if
// any rows were deleted. Must only be called from the writer goroutine.
func (l *SQLiteAuditLogger) runRetention() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var deleted bool

	if l.retention.maxAge > 0 {
		cutoff := time.Now().Add(-l.retention.maxAge)
		n, err := l.store.DeleteBefore(ctx, cutoff)
		if err != nil {
			l.log.Error("audit retention delete failed", slog.String("error", err.Error()))
		} else if n > 0 {
			l.log.Info("audit retention deleted events", slog.Int64("count", n))
			deleted = true
		}
	}

	if l.retention.maxSizeBytes > 0 {
		sz, _ := l.store.DBSize(ctx)
		if sz > l.retention.maxSizeBytes {
			if err := l.store.TrimToSize(ctx, l.retention.maxSizeBytes); err != nil {
				l.log.Error("audit retention trim failed", slog.String("error", err.Error()))
			} else {
				deleted = true
			}
		}
	}

	if deleted && l.cfg.hashChain {
		if err := l.store.ResealChain(ctx); err != nil {
			l.log.Error("audit chain reseal failed", slog.String("error", err.Error()))
			return
		}
		// Reload tip so the next batch chains from the resealed head.
		if h, err := l.store.LastHash(ctx); err == nil {
			l.lastHash = h
		}
		l.log.Info("audit chain resealed after retention")
	}
}

// ---- factory ------------------------------------------------------------

// NewLogger returns the Logger configured by cfg.
// Returns a NoopLogger if Enabled=false.
// When backend is empty, defaults to "sqlite" (fail-closed). Use backend="stdout"
// for a non-durable dev-only logger.
func NewLogger(cfg config.AuditConfig) (Logger, error) {
	if !cfg.Enabled {
		return NewNoopLogger(), nil
	}
	switch cfg.Backend {
	case "stdout":
		return NewStdoutLogger(), nil
	case "sqlite", "":
		if cfg.SQLite.Path == "" {
			return nil, fmt.Errorf("audit: sqlite.path is required (set audit.sqlite.path or audit.backend=stdout for dev)")
		}
		return NewSQLiteAuditLogger(cfg)
	default:
		return nil, fmt.Errorf("audit: unknown backend %q", cfg.Backend)
	}
}

// ---- helpers ------------------------------------------------------------

func eventToStored(e *Event) *StoredEvent {
	argsJSON := ""
	if len(e.Arguments) > 0 {
		if b, err := json.Marshal(e.Arguments); err == nil {
			argsJSON = string(b)
		}
	}
	respJSON := ""
	if e.Response != nil {
		if b, err := json.Marshal(e.Response); err == nil {
			respJSON = string(b)
		}
	}
	errJSON := ""
	if e.Error != "" {
		if b, err := json.Marshal(map[string]string{"message": e.Error}); err == nil {
			errJSON = string(b)
		}
	}
	return &StoredEvent{
		EventID:       e.EventID.String(),
		TsUnixNano:    e.Timestamp.UnixNano(),
		TraceID:       e.TraceID,
		SpanID:        e.SpanID,
		SessionID:     e.SessionID,
		RequestID:     e.RequestID,
		ClientID:      e.ClientID,
		Method:        e.Action,
		ToolName:      e.Tool,
		UpstreamID:    e.UpstreamID,
		Decision:      e.Decision,
		PolicyRule:    e.PolicyRule,
		Reason:        e.Reason,
		ArgumentsJSON: argsJSON,
		ResponseJSON:  respJSON,
		ErrorJSON:     errJSON,
		DurationUs:    e.Duration.Microseconds(),
	}
}
