package commands

import (
	"context"
	"strings"
	"testing"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/authz"
)

func TestName(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{nil, "help"},
		{[]string{"help"}, "help"},
		{[]string{"whoami"}, "whoami"},
		{[]string{"whoami", "extra"}, "whoami"},
		{[]string{"push", "SECRET=hunter2"}, "push"},
		{[]string{"SECRET=hunter2"}, "unknown"},
		{[]string{""}, "unknown"},
		{[]string{"WHOAMI"}, "unknown"},
		{[]string{"pull "}, "unknown"},
	}
	for _, tt := range tests {
		if got := Name(tt.args); got != tt.want {
			t.Errorf("Name(%q) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

func TestRunBasics(t *testing.T) {
	e := newTestEnv(t)
	tests := []struct {
		name    string
		args    []string
		code    int
		outcome audit.Result
		stdout  string
		stderr  string
	}{
		{name: "empty", args: nil, code: 0, outcome: audit.OK, stdout: "usage:"},
		{name: "help", args: []string{"help"}, code: 0, outcome: audit.OK, stdout: "push <project[:env]>"},
		{name: "whoami", args: []string{"whoami"}, code: 0, outcome: audit.OK, stdout: "SHA256:root"},
		{name: "whoami admin", args: []string{"whoami"}, code: 0, outcome: audit.OK, stdout: "admin:       yes"},
		{name: "whoami extra", args: []string{"whoami", "x"}, code: 1, outcome: audit.Error, stderr: "usage: whoami"},
		{name: "unknown", args: []string{"SECRET=hunter2"}, code: 1, outcome: audit.Error, stderr: "unknown command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, out, errb := e.run(e.root, "", tt.args...)
			if res.Code != tt.code || res.Outcome != tt.outcome {
				t.Errorf("code, outcome = %d, %q, want %d, %q", res.Code, res.Outcome, tt.code, tt.outcome)
			}
			if !strings.Contains(out, tt.stdout) {
				t.Errorf("stdout %q missing %q", out, tt.stdout)
			}
			if !strings.Contains(errb, tt.stderr) {
				t.Errorf("stderr %q missing %q", errb, tt.stderr)
			}
			if strings.Contains(out+errb+res.Target+res.Detail, "hunter2") {
				t.Error("client input echoed back")
			}
			if res.Secret != nil {
				t.Error("a command that reads no secret returned one")
			}
		})
	}
}

// Every table entry must be complete, uniquely named and tied to an action
// the policy knows, or the command would be refused for everyone.
func TestCommandTable(t *testing.T) {
	seen := map[string]bool{}
	everything := authz.Subject{IsAdmin: true}
	for _, c := range table {
		if c.name == "" || c.summary == "" || c.run == nil {
			t.Errorf("incomplete command %+v", c)
		}
		if seen[c.name] || c.name == unknownName {
			t.Errorf("command name %q is duplicated or reserved", c.name)
		}
		seen[c.name] = true
		if !authz.Can(everything, c.action, authz.RoleOwner) {
			t.Errorf("command %q: action %q is not in the authz policy", c.name, c.action)
		}
		if string(c.action) != c.name {
			t.Errorf("command %q is checked as action %q", c.name, c.action)
		}
		// A command that needs a project role must say so, or Run would
		// check it with no role and refuse everyone.
		needsRole := !authz.Can(everything, c.action, authz.RoleNone)
		if needsRole != c.project {
			t.Errorf("command %q: project = %v, but its action needs a project role = %v", c.name, c.project, needsRole)
		}
		if c.project && !strings.HasPrefix(c.args, "<project") {
			t.Errorf("command %q: a project command's first argument must be the target, got %q", c.name, c.args)
		}
		if Name([]string{c.name}) != c.name {
			t.Errorf("Name does not recognise %q", c.name)
		}
		if !strings.Contains(helpText(), c.usage()) {
			t.Errorf("help does not list %q", c.usage())
		}
	}
	if !seen[helpName] {
		t.Error("no help command")
	}
}

// A command whose action the user may not perform is refused and never run.
func TestRunDeniesWithoutPermission(t *testing.T) {
	e := newTestEnv(t)
	ran := false
	saved := table
	defer func() { table = saved }()
	table = append(append([]command{}, saved...), command{
		name: "adminonly", summary: "test", action: authz.ManageUsers,
		run: func(_ context.Context, _ Deps, inv *invocation) Result {
			ran = true
			return inv.ok("")
		},
	})

	res, _, stderr := e.run(e.bob, "", "adminonly")
	if res.Code != 1 || res.Outcome != audit.Denied || ran || !strings.Contains(stderr, "permission denied") {
		t.Fatalf("non-admin: %+v, ran %v, stderr %q", res, ran, stderr)
	}
	res, _, _ = e.run(e.root, "", "adminonly")
	if res.Code != 0 || res.Outcome != audit.OK || !ran {
		t.Fatalf("admin: %+v, ran %v", res, ran)
	}
}
