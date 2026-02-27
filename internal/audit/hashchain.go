package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// canonicalPayload covers ALL persisted fields except event_hash and prev_hash
// (which are the hash-chain metadata themselves). Using a struct with explicit
// json tags guarantees stable key order across Go versions and builds.
// Any mutation of a persisted field — including response_json or error_json —
// will produce a different hash and be detected by VerifyChain.
type canonicalPayload struct {
	EventID       string `json:"event_id"`
	TsUnixNano    int64  `json:"ts_unix_nano"`
	TraceID       string `json:"trace_id"`
	SpanID        string `json:"span_id"`
	SessionID     string `json:"session_id"`
	RequestID     string `json:"request_id"`
	ClientID      string `json:"client_id"`
	Method        string `json:"method"`
	ToolName      string `json:"tool_name"`
	UpstreamID    string `json:"upstream_id"`
	Decision      string `json:"decision"`
	PolicyRule    string `json:"policy_rule"`
	Reason        string `json:"reason"`
	ArgumentsJSON string `json:"arguments_json"`
	ResponseJSON  string `json:"response_json"`
	ErrorJSON     string `json:"error_json"`
	DurationUs    int64  `json:"duration_us"`
}

// canonicalizeEvent serialises all integrity-relevant fields of e into a
// deterministic JSON byte slice. Map fields (arguments, response, error) are
// already serialised to strings before reaching StoredEvent, so their ordering
// is stable (the stored string is used verbatim).
func canonicalizeEvent(e *StoredEvent) ([]byte, error) {
	return json.Marshal(canonicalPayload{
		EventID:       e.EventID,
		TsUnixNano:    e.TsUnixNano,
		TraceID:       e.TraceID,
		SpanID:        e.SpanID,
		SessionID:     e.SessionID,
		RequestID:     e.RequestID,
		ClientID:      e.ClientID,
		Method:        e.Method,
		ToolName:      e.ToolName,
		UpstreamID:    e.UpstreamID,
		Decision:      e.Decision,
		PolicyRule:    e.PolicyRule,
		Reason:        e.Reason,
		ArgumentsJSON: e.ArgumentsJSON,
		ResponseJSON:  e.ResponseJSON,
		ErrorJSON:     e.ErrorJSON,
		DurationUs:    e.DurationUs,
	})
}

// ComputeHash returns SHA-256( prevHash || canonicalJSON ) as a hex string.
// prevHash is "" for the first event in a chain (or after a reseal anchor).
func ComputeHash(prevHash string, e *StoredEvent) (string, error) {
	canonical, err := canonicalizeEvent(e)
	if err != nil {
		return "", fmt.Errorf("canonicalize: %w", err)
	}
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyChain scans all events in insertion order and validates every hash.
// After a retention reseal, the chain starts at prev_hash="" for the oldest
// remaining event — this is correct and expected.
// Returns the first error found, or nil if the chain is intact.
// An empty store is considered valid.
func VerifyChain(ctx context.Context, store Store) error {
	prevHash := ""
	return store.Scan(ctx, time.Time{}, func(e *StoredEvent) error {
		if e.PrevHash != prevHash {
			return fmt.Errorf("event %s: prev_hash mismatch (got %q, want %q)",
				e.EventID, e.PrevHash, prevHash)
		}
		want, err := ComputeHash(prevHash, e)
		if err != nil {
			return fmt.Errorf("event %s: %w", e.EventID, err)
		}
		if e.EventHash != want {
			return fmt.Errorf("event %s: hash mismatch (got %q, want %q)",
				e.EventID, e.EventHash, want)
		}
		prevHash = e.EventHash
		return nil
	})
}
