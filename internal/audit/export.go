package audit

import (
	"context"
	"encoding/json"
	"io"
	"time"
)

// ExportJSONL streams stored events as JSON Lines to w.
// If since is the zero time, all events are exported.
// Events are emitted in (ts_unix_nano, event_id) order.
func ExportJSONL(ctx context.Context, store Store, since time.Time, w io.Writer) error {
	enc := json.NewEncoder(w)
	return store.Scan(ctx, since, func(e *StoredEvent) error {
		return enc.Encode(e)
	})
}
