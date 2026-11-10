// Package commands parses and runs the commands clients send over SSH.
// It never executes external programs.
package commands

import (
	"fmt"
	"io"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/authz"
)

const helpText = `ssshhh-env: share .env files over ssh

usage: ssh <host> <command> [args]

commands:
  help      show this help
  whoami    show who you are authenticated as
`

// Name returns the command name safe to log: a known command, "help" for an
// empty command line, or "unknown". It never returns raw client input.
func Name(args []string) string {
	if len(args) == 0 {
		return "help"
	}
	switch args[0] {
	case "help", "whoami":
		return args[0]
	default:
		return "unknown"
	}
}

// actions maps each command name to the action authz decides on. A command
// without an entry cannot run.
var actions = map[string]authz.Action{
	"help":   authz.Help,
	"whoami": authz.Whoami,
}

// Run executes args for id. It returns the exit code and the outcome to
// record in the audit log.
func Run(args []string, id auth.Identity, stdout, stderr io.Writer) (int, audit.Result) {
	name := Name(args)
	if name == "unknown" {
		fmt.Fprint(stderr, "unknown command\n\n"+helpText)
		return 1, audit.Error
	}
	action, ok := actions[name]
	// No command takes a project yet, so the role is always RoleNone.
	if !ok || !authz.Can(authz.Subject{IsAdmin: id.IsAdmin}, action, authz.RoleNone) {
		fmt.Fprintln(stderr, "permission denied")
		return 1, audit.Denied
	}

	switch name {
	case "help":
		fmt.Fprint(stdout, helpText)
		return 0, audit.OK
	case "whoami":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "usage: whoami")
			return 1, audit.Error
		}
		admin := "no"
		if id.IsAdmin {
			admin = "yes"
		}
		fmt.Fprintf(stdout, "user:        %s\nadmin:       %s\nkey:         %s\nfingerprint: %s\n", id.Name, admin, id.KeyType, id.Fingerprint)
		return 0, audit.OK
	default:
		fmt.Fprintln(stderr, "permission denied")
		return 1, audit.Denied
	}
}
