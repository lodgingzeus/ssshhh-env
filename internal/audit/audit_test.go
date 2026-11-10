package audit

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

func TestClean(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"plain", 10, "plain"},
		{"too long", 3, "too"},
		{"line1\nline2\r\tend", 50, "line1line2end"},
		{"\x1b[31mred\x1b[0m", 50, "[31mred[0m"},
		{"nul\x00byte", 50, "nulbyte"},
		{"bad\xffutf8", 50, "badutf8"},
		{"rtl\u202eoverride", 50, "rtloverride"},
		{"héllo wörld", 5, "héllo"},
		{"", 5, ""},
	}
	for _, tt := range tests {
		if got := Clean(tt.in, tt.max); got != tt.want {
			t.Errorf("Clean(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
		}
	}
}

func TestLog(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := Log(ctx, st, Event{
		RemoteAddr: "127.0.0.1",
		Action:     "push",
		Target:     "app\x1b]0;evil\x07:prod",
		Result:     Denied,
		Detail:     strings.Repeat("x", 500) + "\n",
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	r := rows[0]
	if r.Target != "app]0;evil:prod" || len(r.Detail) != maxDetail || r.Result != "denied" || r.UserID != 0 || r.KeyFingerprint != "" {
		t.Fatalf("row = %+v", r)
	}

	for _, bad := range []Event{
		{RemoteAddr: "x", Action: "push", Result: "maybe"},
		{RemoteAddr: "x", Action: "push"},
		{RemoteAddr: "x", Result: OK},
	} {
		if err := Log(ctx, st, bad); err == nil {
			t.Errorf("invalid event accepted: %+v", bad)
		}
	}
	if rows, _ := st.ListAudit(ctx, 10); len(rows) != 1 {
		t.Errorf("invalid events were written: %d rows", len(rows))
	}
}
