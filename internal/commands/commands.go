// Package commands parses and runs the commands clients send over SSH.
// It never executes external programs.
package commands

import (
	"fmt"
	"io"
	"strings"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/authz"
)

// Names used when the command line does not name a known command.
const (
	helpName    = "help"
	unknownName = "unknown"
)

// command is one entry in the command table. Adding a command means adding
// one entry: its name, help line, authz action and handler all live here.
type command struct {
	name    string
	summary string
	action  authz.Action
	run     func(args []string, id auth.Identity, stdout, stderr io.Writer) (int, audit.Result)
}

// table lists every command, in help order. It is filled in init because
// the help handler reads the table.
var table []command

func init() {
	table = []command{
		{name: helpName, summary: "show this help", action: authz.Help, run: runHelp},
		{name: "whoami", summary: "show who you are authenticated as", action: authz.Whoami, run: runWhoami},
	}
}

func lookup(name string) (command, bool) {
	for _, c := range table {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

func helpText() string {
	var b strings.Builder
	b.WriteString("ssshhh-env: share .env files over ssh\n\nusage: ssh <host> <command> [args]\n\ncommands:\n")
	for _, c := range table {
		fmt.Fprintf(&b, "  %-9s %s\n", c.name, c.summary)
	}
	return b.String()
}

// Name returns the command name safe to log: a known command, "help" for an
// empty command line, or "unknown". It never returns raw client input.
func Name(args []string) string {
	if len(args) == 0 {
		return helpName
	}
	if c, ok := lookup(args[0]); ok {
		return c.name
	}
	return unknownName
}

// Run executes args for id. It returns the exit code and the outcome to
// record in the audit log.
func Run(args []string, id auth.Identity, stdout, stderr io.Writer) (int, audit.Result) {
	c, ok := lookup(Name(args))
	if !ok {
		fmt.Fprint(stderr, "unknown command\n\n"+helpText())
		return 1, audit.Error
	}
	// No command takes a project yet, so the role is always RoleNone.
	if !authz.Can(authz.Subject{IsAdmin: id.IsAdmin}, c.action, authz.RoleNone) {
		fmt.Fprintln(stderr, "permission denied")
		return 1, audit.Denied
	}
	return c.run(args, id, stdout, stderr)
}

func runHelp(_ []string, _ auth.Identity, stdout, _ io.Writer) (int, audit.Result) {
	fmt.Fprint(stdout, helpText())
	return 0, audit.OK
}

func runWhoami(args []string, id auth.Identity, stdout, stderr io.Writer) (int, audit.Result) {
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
}
