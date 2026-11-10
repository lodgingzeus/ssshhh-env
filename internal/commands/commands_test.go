package commands

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
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

// Every name that Name can return for a known command must map to an
// action, or the command would be refused for everyone.
func TestEveryCommandHasAnAction(t *testing.T) {
	for _, cmd := range []string{"help", "whoami"} {
		if _, ok := actions[cmd]; !ok {
			t.Errorf("command %q has no authz action", cmd)
		}
	}
	for cmd := range actions {
		if Name([]string{cmd}) != cmd {
			t.Errorf("action registered for %q, which Name does not recognise", cmd)
		}
	}
}
