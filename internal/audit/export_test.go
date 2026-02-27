// export_test.go — compiled only during `go test`. Provides internal helpers
// that the external audit_test package cannot construct directly.
package audit

import (
	"context"
	"log/slog"
	"time"
)

// noCloseStore wraps a Store so that Close() is a no-op.
// Used by NewTestLoggerWithStore so that logger.Close() does not close the
// caller's store (which the caller manages independently).
type noCloseStore struct{ Store }

func (noCloseStore) Close() error { return nil }

// NewTestLoggerWithStore constructs an SQLiteAuditLogger backed by an
// injected store. Used by audit_test to inject failing stores.
// The logger's Close() will NOT close the provided store.
func NewTestLoggerWithStore(store Store, mode string, hashChain bool, chanSize int) (*SQLiteAuditLogger, error) {
	m, err := parseSqliteWriteMode(mode)
	if err != nil {
		return nil, err
	}
	l := &SQLiteAuditLogger{
		store: noCloseStore{store},
		cfg: sqliteLoggerCfg{
			batchMaxEvents: 256,
			batchMaxDelay:  50 * time.Millisecond,
			mode:           m,
			hashChain:      hashChain,
		},
		ch:   make(chan *Event, chanSize),
		done: make(chan struct{}),
		log:  slog.Default(),
	}
	l.lastHash, _ = store.LastHash(context.Background())
	go l.run()
	return l, nil
}

// LastHashField exposes the in-memory chain tip for testing.
func (l *SQLiteAuditLogger) LastHashField() string { return l.lastHash }
