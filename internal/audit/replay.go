package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/haze518/mcpshield/internal/mcp"
	"github.com/haze518/mcpshield/internal/policy"
)

// ReplayReadOnly prints a tab-separated timeline for the given session to w:
//
//	<ts>  <tool>  <decision>  <policy_rule>  <duration_µs>µs
func ReplayReadOnly(ctx context.Context, store Store, sessionID string, w io.Writer) error {
	return store.ScanSession(ctx, sessionID, func(e *StoredEvent) error {
		ts := time.Unix(0, e.TsUnixNano).UTC().Format(time.RFC3339Nano)
		_, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%dµs\n",
			ts, e.ToolName, e.Decision, e.PolicyRule, e.DurationUs)
		return err
	})
}

// ReplayPolicyCheck re-evaluates recorded tools/call events for the session
// against engine and prints a diff line for each event:
//
//	<ts>  [=|CHANGED]  <tool>  old=<old_decision>  new=<new_decision>  rule=<rule>  [<reason>]
func ReplayPolicyCheck(
	ctx context.Context,
	store Store,
	sessionID string,
	engine policy.Engine,
	w io.Writer,
) error {
	return store.ScanSession(ctx, sessionID, func(e *StoredEvent) error {
		if e.Method != "tools/call" {
			return nil
		}

		var args map[string]any
		if e.ArgumentsJSON != "" {
			_ = json.Unmarshal([]byte(e.ArgumentsJSON), &args)
		}

		call := &mcp.ToolsCallRequest{Name: e.ToolName, Arguments: args}
		nd := engine.Evaluate(ctx, call)

		tag := "="
		if nd.Action != e.Decision {
			tag = "CHANGED"
		}

		ts := time.Unix(0, e.TsUnixNano).UTC().Format(time.RFC3339Nano)
		_, err := fmt.Fprintf(w, "%s\t%s\t%s\told=%s new=%s rule=%s [%s]\n",
			ts, tag, e.ToolName, e.Decision, nd.Action, nd.Rule, nd.Reason)
		return err
	})
}
