// Package audit records who did what. Events are append-only and must never
// contain secret values: callers pass command names and targets, not raw
// client input or payloads.
package audit

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// Result is the outcome of an audited action.
type Result string

// Results.
const (
	OK     Result = "ok"
	Denied Result = "denied" // authentication or authorization refused
	Error  Result = "error"  // bad input or an internal failure
)

// Field length caps. Longer values are truncated, not rejected: an audit
// row is better than none.
const (
	maxAction = 32
	maxTarget = 128
	maxDetail = 200
	maxAddr   = 64
)

// Event is one audited action.
type Event struct {
	UserID         int64  // 0 if the actor is not a known user
	KeyFingerprint string // empty if no key was verified
	RemoteAddr     string
	Action         string // command name, or "auth" / "session"
	Target         string // project or project:env, if any
	Result         Result
	Detail         string // short, fixed wording; never secret values
}

// Sink is where events are written. *store.Store implements it.
type Sink interface {
	InsertAudit(ctx context.Context, r store.AuditRow) error
}

// Log writes e to sink. Text fields are stripped of control characters and
// truncated, so a row is safe to print to a terminal later.
func Log(ctx context.Context, sink Sink, e Event) error {
	switch e.Result {
	case OK, Denied, Error:
	default:
		return fmt.Errorf("audit: invalid result %q", e.Result)
	}
	if e.Action == "" {
		return fmt.Errorf("audit: action required")
	}
	return sink.InsertAudit(ctx, store.AuditRow{
		UserID:         e.UserID,
		KeyFingerprint: Clean(e.KeyFingerprint, maxTarget),
		RemoteAddr:     Clean(e.RemoteAddr, maxAddr),
		Action:         Clean(e.Action, maxAction),
		Target:         Clean(e.Target, maxTarget),
		Result:         string(e.Result),
		Detail:         Clean(e.Detail, maxDetail),
	})
}

// Clean makes s safe to store and display: invalid UTF-8 and control
// characters (including newlines and terminal escapes) are removed, and the
// result is cut to at most max runes.
func Clean(s string, max int) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
