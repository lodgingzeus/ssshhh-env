package commands

import (
	"io"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// Request is one command from an authenticated client.
type Request struct {
	// Line is the command line exactly as the client sent it. It may
	// contain anything, including secrets typed by mistake: never log it.
	Line   string
	ID     auth.Identity
	Stdin  io.Reader
	Stderr io.Writer
}

// Result is the outcome of a command.
type Result struct {
	Code    int          // exit status
	Outcome audit.Result // what to record in the audit log
	// Target is what the command addressed: a project, a project:env, or
	// user:<name> for account commands. It is set only once the name has
	// been validated, so it is safe to log.
	Target string
	// Detail is a short note for the audit log, in fixed wording.
	Detail string
	// Stdout is the command's output for the client's stdout, and Secret
	// is decrypted file content for it. Commands never write either
	// themselves: the caller must write the audit row first and send them
	// only if that succeeded, so no action looks done and no read happens
	// without a record.
	Stdout []byte
	Secret []byte
	// Changed reports that the command saved a change (a project, a
	// version, a membership, a user or a key). If the audit write then fails, the client must be told the
	// change was made, or a retry would make it twice.
	Changed bool
}

// invocation is a request after Run has resolved what it addresses.
type invocation struct {
	Request
	Args   []string  // Line split into words
	Params []string  // Args after the command's own words
	Stdout io.Writer // collected into Result.Stdout
	cmd    command
	// Set for commands that address a project: the caller has already been
	// authorised for cmd.action on it.
	target  Target
	project store.Project
	// user is the validated name of the account an account-management
	// command acts on, for the audit log.
	user string
}
