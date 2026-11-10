package commands

import (
	"fmt"
	"strings"
	"testing"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

func TestHistory(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", map[auth.Identity]string{e.bob: store.RoleReader})
	e.push(t, "app", "A=secret-a\nB=secret-b\n", "-m", "first")
	e.push(t, "app", "A=secret-a2\nB=secret-b\nC=secret-c\n")
	e.push(t, "app", "C=secret-c\n", "-m", "drop", "a", "and", "b")

	res, out, _ := e.run(e.bob, "", "history", "app")
	if res.Code != 0 || res.Outcome != audit.OK || res.Target != "app:default" {
		t.Fatalf("history: %+v", res)
	}
	want := []string{
		"version 3", "by root", "(1 variable)", "message: drop a and b", "removed: A, B",
		"version 2", "added:   C",
		"version 1", "message: first", "first version",
	}
	pos := 0
	for _, w := range want {
		i := strings.Index(out[pos:], w)
		if i < 0 {
			t.Fatalf("history lacks %q (in order):\n%s", w, out)
		}
		pos += i + len(w)
	}
	if strings.Contains(out, "secret-") {
		t.Fatalf("history shows values:\n%s", out)
	}

	// With a limit, the oldest shown version is still compared with its
	// predecessor, and the client is told there is more.
	_, out, _ = e.run(e.bob, "", "history", "app", "--limit", "2")
	if strings.Contains(out, "version 1") || strings.Contains(out, "first version") || !strings.Contains(out, "added:   C") || !strings.Contains(out, "showing the newest 2") {
		t.Errorf("limited history:\n%s", out)
	}
	_, out, _ = e.run(e.bob, "", "history", "app", "--limit", "3")
	if strings.Contains(out, "showing the newest") {
		t.Errorf("exact limit claims more versions:\n%s", out)
	}
}

func TestHistoryRefusals(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", nil)
	e.push(t, "app", sampleEnv)
	tests := []struct {
		name   string
		id     auth.Identity
		args   []string
		stderr string
	}{
		{"non-member", e.bob, []string{"history", "app"}, "no such project"},
		{"empty environment", e.root, []string{"history", "app:prod"}, "nothing has been pushed"},
		{"limit zero", e.root, []string{"history", "app", "--limit", "0"}, "usage: history"},
		{"limit too high", e.root, []string{"history", "app", "--limit", fmt.Sprint(maxHistory + 1)}, "usage: history"},
		{"limit not a number", e.root, []string{"history", "app", "--limit", "-1"}, "usage: history"},
		{"unknown flag", e.root, []string{"history", "app", "--all"}, "usage: history"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _, stderr := e.run(tt.id, "", tt.args...)
			if res.Code != 1 || !strings.Contains(stderr, tt.stderr) {
				t.Fatalf("%+v, stderr %q", res, stderr)
			}
		})
	}
}

func TestDiff(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", map[auth.Identity]string{e.bob: store.RoleReader})
	e.push(t, "app", "KEEP=same-value\nCHANGE=old-value\nGONE=gone-value\n")
	e.push(t, "app", "KEEP=same-value\nCHANGE=new-value\nNEW=new-var-value\n")

	res, out, _ := e.run(e.bob, "", "diff", "app", "1", "2")
	if res.Code != 0 || res.Detail != "versions 1 and 2" || res.Secret != nil {
		t.Fatalf("diff: %+v", res)
	}
	for _, w := range []string{"app:default: version 1 -> version 2", "added:   NEW", "removed: GONE", "changed: CHANGE"} {
		if !strings.Contains(out, w) {
			t.Errorf("diff lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "KEEP") || strings.Contains(out, "value") {
		t.Errorf("diff shows unchanged names or values:\n%s", out)
	}

	// Reversed, added and removed swap.
	_, out, _ = e.run(e.bob, "", "diff", "app", "2", "1")
	if !strings.Contains(out, "added:   GONE") || !strings.Contains(out, "removed: NEW") {
		t.Errorf("reversed diff:\n%s", out)
	}
	_, out, _ = e.run(e.bob, "", "diff", "app", "2", "2")
	if !strings.Contains(out, "no differences") {
		t.Errorf("same version:\n%s", out)
	}
}

func TestDiffRefusals(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", nil)
	e.push(t, "app", sampleEnv)
	tests := []struct {
		name   string
		id     auth.Identity
		args   []string
		stderr string
	}{
		{"non-member", e.bob, []string{"diff", "app", "1", "1"}, "no such project"},
		{"missing version", e.root, []string{"diff", "app", "1", "5"}, "app:default has no version 5"},
		{"missing environment", e.root, []string{"diff", "app:prod", "1", "1"}, "no such version"},
		{"one version", e.root, []string{"diff", "app", "1"}, "usage: diff"},
		{"zero", e.root, []string{"diff", "app", "0", "1"}, "usage: diff"},
		{"negative", e.root, []string{"diff", "app", "1", "-1"}, "usage: diff"},
		{"extra", e.root, []string{"diff", "app", "1", "1", "1"}, "usage: diff"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, out, stderr := e.run(tt.id, "", tt.args...)
			if res.Code != 1 || out != "" || !strings.Contains(stderr, tt.stderr) {
				t.Fatalf("%+v, stdout %q, stderr %q", res, out, stderr)
			}
		})
	}
}
