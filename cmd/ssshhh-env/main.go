// Command ssshhh-env is a self-hosted SSH server for sharing .env files.
package main

import (
	"fmt"
	"io"
	"os"
)

const usage = `usage: ssshhh-env <command> [flags]

commands:
  serve           run the SSH server
  admin           server-side account management (run on the host)
  keygen-master   generate a 32-byte master key
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "serve", "admin", "keygen-master":
		fmt.Fprintf(stderr, "ssshhh-env: %s: not implemented yet\n", args[0])
		return 1
	default:
		fmt.Fprintf(stderr, "ssshhh-env: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
