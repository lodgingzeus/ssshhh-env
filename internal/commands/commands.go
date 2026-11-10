// Package commands parses and runs the commands clients send over SSH.
// It never executes external programs.
package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/authz"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// Names used when the command line does not name a known command.
const (
	helpName    = "help"
	unknownName = "unknown"
)

// Split splits a command line into words at whitespace. Quotes and
// backslashes are ordinary characters: no command needs an argument with
// spaces in it except push -m, which takes its message from the raw line
// (see afterWords). Nothing is ever unparseable, so a line can't be
// half-understood.
func Split(line string) []string { return strings.Fields(line) }

// afterWords returns line without its first n words, trimmed of
// surrounding whitespace. Words are separated exactly as Split separates
// them.
func afterWords(line string, n int) string {
	rest := line
	for range n {
		rest = strings.TrimLeftFunc(rest, unicode.IsSpace)
		i := strings.IndexFunc(rest, unicode.IsSpace)
		if i < 0 {
			return ""
		}
		rest = rest[i:]
	}
	return strings.TrimSpace(rest)
}

// Name returns the command name safe to log: a known command such as
// "push" or "user add", "help" for an empty command line, or "unknown". It
// never returns raw client input.
func Name(args []string) string {
	if len(args) == 0 {
		return helpName
	}
	if c, ok := lookup(args); ok {
		return c.name
	}
	return unknownName
}

// Run executes req. Authorization happens here, before any handler runs:
// a handler can assume the caller may perform its command's action.
//
// What a handler writes to stdout is returned in Result.Stdout rather than
// sent, so that nothing reaches the client before the action is audited.
func Run(ctx context.Context, d Deps, req Request) Result {
	args := Split(req.Line)
	if len(args) == 0 {
		args = []string{helpName}
	}
	c, ok := lookup(args)
	if !ok {
		fmt.Fprint(req.Stderr, "unknown command\n\n"+helpText())
		return Result{Code: 1, Outcome: audit.Error}
	}
	var out bytes.Buffer
	inv := &invocation{Request: req, Args: args, Params: args[c.words():], Stdout: &out, cmd: c}
	res := run(ctx, d, inv)
	res.Stdout = out.Bytes()
	return res
}

// run checks authorization for inv and calls its handler.
func run(ctx context.Context, d Deps, inv *invocation) Result {
	c, req := inv.cmd, inv.Request
	sub := authz.Subject{IsAdmin: req.ID.IsAdmin}

	if c.scope == scopeNone {
		if !authz.Can(sub, c.action, authz.RoleNone) {
			fmt.Fprintln(req.Stderr, "permission denied")
			return Result{Code: 1, Outcome: audit.Denied}
		}
		return c.run(ctx, d, inv)
	}

	if len(inv.Params) < 1 {
		return inv.usageError()
	}
	if c.scope == scopeProject {
		// A bare project name: membership is per project, not per
		// environment, so "app:prod" is refused rather than read as "app".
		project, _, hasEnv := strings.Cut(inv.Params[0], ":")
		if hasEnv && ValidName(project) {
			return inv.refuse("environment given", fmt.Sprintf("access is per project: give %s, not an environment", project))
		}
		if !ValidName(inv.Params[0]) {
			return inv.refuse("invalid project name", errBadTarget.Error())
		}
		inv.target = Target{Project: inv.Params[0]}
	} else {
		target, err := ParseTarget(inv.Params[0])
		if err != nil {
			return inv.refuse("invalid target", err.Error())
		}
		inv.target = target
	}
	project, role, err := resolveProject(ctx, d.Store, inv.target.Project, req.ID.UserID)
	if err != nil {
		return inv.internal(d, "resolve project", err)
	}
	if !authz.Can(sub, c.action, role) {
		return inv.deny(role)
	}
	inv.project = project
	res := c.run(ctx, d, inv)
	res.Target = inv.auditTarget()
	return res
}

// resolveProject returns the project called name and the user's role in
// it. A project that does not exist is reported as RoleNone, the same as
// one the user is not a member of.
func resolveProject(ctx context.Context, st Store, name string, userID int64) (store.Project, authz.Role, error) {
	p, err := st.ProjectByName(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return store.Project{}, authz.RoleNone, nil
	}
	if err != nil {
		return store.Project{}, authz.RoleNone, err
	}
	role, err := st.MemberRole(ctx, p.ID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Project{}, authz.RoleNone, nil
	}
	if err != nil {
		return store.Project{}, authz.RoleNone, err
	}
	return p, authz.ParseRole(role), nil
}
