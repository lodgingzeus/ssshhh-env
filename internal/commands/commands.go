// Package commands parses and runs the commands clients send over SSH.
// It never executes external programs.
package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/authz"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// Names used when the command line does not name a known command.
const (
	helpName    = "help"
	unknownName = "unknown"
)

// command is one entry in the command table. Adding a command means adding
// one entry: its name, arguments, help line, authz action and handler all
// live here.
type command struct {
	name    string
	args    string // argument synopsis for help and usage errors
	summary string
	action  authz.Action
	// project marks a command whose first argument is a project[:env]
	// target. Run resolves the target and checks the caller's role in that
	// project before the handler is called.
	project bool
	run     func(ctx context.Context, d Deps, inv *invocation) Result
}

// usage returns the command with its argument synopsis.
func (c command) usage() string {
	if c.args == "" {
		return c.name
	}
	return c.name + " " + c.args
}

// table lists every command, in help order. It is filled in init because
// the help handler reads the table.
var table []command

func init() {
	table = []command{
		{name: helpName, summary: "show this help", action: authz.Help, run: runHelp},
		{name: "whoami", summary: "show who you are authenticated as", action: authz.Whoami, run: runWhoami},
		{name: "init", args: "<project>", summary: "create a project (server admins only)", action: authz.Init, run: runInit},
		{name: "push", args: "<project[:env]> [-m message]", summary: "store the .env file on stdin as a new version", action: authz.Push, project: true, run: runPush},
		{name: "pull", args: "<project[:env]> [--version N]", summary: "print the latest .env file, or version N", action: authz.Pull, project: true, run: runPull},
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
		fmt.Fprintf(&b, "  %-37s %s\n", c.usage(), c.summary)
	}
	b.WriteString("\nexamples:\n  ssh <host> push myapp < .env\n  ssh <host> pull myapp:prod > .env.prod\n")
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

// Run executes req. Authorization happens here, before any handler runs:
// a handler can assume the caller may perform its command's action.
func Run(ctx context.Context, d Deps, req Request) Result {
	c, ok := lookup(Name(req.Args))
	if !ok {
		fmt.Fprint(req.Stderr, "unknown command\n\n"+helpText())
		return Result{Code: 1, Outcome: audit.Error}
	}
	inv := &invocation{Request: req, cmd: c}
	sub := authz.Subject{IsAdmin: req.ID.IsAdmin}

	if !c.project {
		if !authz.Can(sub, c.action, authz.RoleNone) {
			fmt.Fprintln(req.Stderr, "permission denied")
			return Result{Code: 1, Outcome: audit.Denied}
		}
		return c.run(ctx, d, inv)
	}

	if len(req.Args) < 2 {
		return inv.usageError()
	}
	target, err := ParseTarget(req.Args[1])
	if err != nil {
		return inv.refuse("invalid target", err.Error())
	}
	inv.target = target
	project, role, err := resolveProject(ctx, d.Store, target.Project, req.ID.UserID)
	if err != nil {
		return inv.internal(d, "resolve project", err)
	}
	if !authz.Can(sub, c.action, role) {
		return inv.deny(role)
	}
	inv.project = project
	res := c.run(ctx, d, inv)
	res.Target = target.String()
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
