package commands

import (
	"bytes"
	"strings"
	"testing"

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
	id := auth.Identity{Name: "alice", Fingerprint: "SHA256:abc", KeyType: "ssh-ed25519"}
	tests := []struct {
		name       string
		args       []string
		code       int
		stdout     string
		stderr     string
		echoesArgs bool
	}{
		{name: "empty", args: nil, code: 0, stdout: "usage:"},
		{name: "help", args: []string{"help"}, code: 0, stdout: "usage:"},
		{name: "whoami", args: []string{"whoami"}, code: 0, stdout: "SHA256:abc"},
		{name: "whoami extra", args: []string{"whoami", "x"}, code: 1, stderr: "usage: whoami"},
		{name: "unknown", args: []string{"SECRET=hunter2"}, code: 1, stderr: "unknown command"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := Run(tt.args, id, &out, &errb)
			if code != tt.code {
				t.Errorf("code = %d, want %d", code, tt.code)
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
