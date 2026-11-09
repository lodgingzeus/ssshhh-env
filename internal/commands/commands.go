// Package commands parses and runs the commands clients send over SSH.
// It never executes external programs.
package commands

import (
	"fmt"
	"io"

	"github.com/lodgingzeus/ssshhh-env/internal/auth"
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

// Run executes args for id and returns the exit code.
func Run(args []string, id auth.Identity, stdout, stderr io.Writer) int {
	switch Name(args) {
	case "help":
		fmt.Fprint(stdout, helpText)
		return 0
	case "whoami":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "usage: whoami")
			return 1
		}
		fmt.Fprintf(stdout, "user:        %s\nkey:         %s\nfingerprint: %s\n", id.Name, id.KeyType, id.Fingerprint)
		return 0
	default:
		fmt.Fprint(stderr, "unknown command\n\n"+helpText)
		return 1
	}
}
