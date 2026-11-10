package commands

import (
	"context"
	"io"
	"log/slog"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/crypto"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// Store is the persistence the commands need. *store.Store implements it.
type Store interface {
	CreateProject(ctx context.Context, name string, creatorID int64, wrap func(projectID int64) (store.WrappedDEK, error)) (store.Project, error)
	ProjectByName(ctx context.Context, name string) (store.Project, error)
	MemberRole(ctx context.Context, projectID, userID int64) (string, error)
	AppendVersion(ctx context.Context, v store.NewVersion, seal func(envID, number int64) (store.SealedVersion, error)) (store.Version, error)
	LatestVersion(ctx context.Context, projectID int64, envName string) (store.Version, error)
	VersionByNumber(ctx context.Context, projectID int64, envName string, number int64) (store.Version, error)
}

// Deps is what every command runs against. All fields are required.
type Deps struct {
	Store     Store
	MasterKey *crypto.MasterKey
	Log       *slog.Logger
}

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
	// Target is the project or project:env the command addressed. It is
	// set only once the name has been validated, so it is safe to log.
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
	// Changed reports that the command saved a change (a project or a
	// version). If the audit write then fails, the client must be told the
	// change was made, or a retry would make it twice.
	Changed bool
}

// invocation is a request after Run has resolved what it addresses.
type invocation struct {
	Request
	Args   []string  // Line split into words
	Stdout io.Writer // collected into Result.Stdout
	cmd    command
	// Set for commands that address a project: the caller has already been
	// authorised for cmd.action on it.
	target  Target
	project store.Project
}
