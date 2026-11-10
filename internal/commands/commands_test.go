package commands

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
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
		{[]string{"SECRET=hunter2"}, "unknown"},
		{[]string{""}, "unknown"},
		{[]string{"WHOAMI"}, "unknown"},
	}
	for _, tt := range tests {
		if got := Name(tt.args); got != tt.want {
			t.Errorf("Name(%q) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

func TestRun(t *testing.T) {
	id := auth.Identity{Name: "alice", IsAdmin: true, Fingerprint: "SHA256:abc", KeyType: "ssh-ed25519"}
	tests := []struct {
		name   string
		args   []string
		code   int
		result audit.Result
		stdout string
		stderr string
	}{
		{name: "empty", args: nil, code: 0, result: audit.OK, stdout: "usage:"},
		{name: "help", args: []string{"help"}, code: 0, result: audit.OK, stdout: "usage:"},
		{name: "whoami", args: []string{"whoami"}, code: 0, result: audit.OK, stdout: "SHA256:abc"},
		{name: "whoami admin", args: []string{"whoami"}, code: 0, result: audit.OK, stdout: "admin:       yes"},
		{name: "whoami extra", args: []string{"whoami", "x"}, code: 1, result: audit.Error, stderr: "usage: whoami"},
		{name: "unknown", args: []string{"SECRET=hunter2"}, code: 1, result: audit.Error, stderr: "unknown command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code, result := Run(tt.args, id, &out, &errb)
			if code != tt.code || result != tt.result {
				t.Errorf("code, result = %d, %q, want %d, %q", code, result, tt.code, tt.result)
			}
			if !strings.Contains(out.String(), tt.stdout) {
				t.Errorf("stdout %q missing %q", out.String(), tt.stdout)
			}
			if !strings.Contains(errb.String(), tt.stderr) {
				t.Errorf("stderr %q missing %q", errb.String(), tt.stderr)
			}
			if strings.Contains(out.String()+errb.String(), "hunter2") {
				t.Error("client input echoed back")
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
		if Name([]string{c.name}) != c.name {
			t.Errorf("Name does not recognise %q", c.name)
		}
		if !strings.Contains(helpText(), c.name) {
			t.Errorf("help does not list %q", c.name)
		}
	}
	if !seen[helpName] {
		t.Error("no help command")
	}
}

// A command whose action the user may not perform is refused and never run.
func TestRunDeniesWithoutPermission(t *testing.T) {
	ran := false
	saved := table
	defer func() { table = saved }()
	table = append(append([]command{}, saved...), command{
		name: "adminonly", summary: "test", action: authz.ManageUsers,
		run: func([]string, auth.Identity, io.Writer, io.Writer) (int, audit.Result) {
			ran = true
			return 0, audit.OK
		},
	})

	var out, errb bytes.Buffer
	code, result := Run([]string{"adminonly"}, auth.Identity{Name: "bob"}, &out, &errb)
	if code != 1 || result != audit.Denied || ran || !strings.Contains(errb.String(), "permission denied") {
		t.Fatalf("non-admin: code %d, result %q, ran %v, stderr %q", code, result, ran, errb.String())
	}
	code, result = Run([]string{"adminonly"}, auth.Identity{Name: "alice", IsAdmin: true}, &out, &errb)
	if code != 0 || result != audit.OK || !ran {
		t.Fatalf("admin: code %d, result %q, ran %v", code, result, ran)
	}
}
