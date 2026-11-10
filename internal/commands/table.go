package commands

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/lodgingzeus/ssshhh-env/internal/authz"
)

// scope is what a command's first parameter addresses.
type scope int

const (
	scopeNone    scope = iota // no project
	scopeProject              // a bare project name
	scopeTarget               // project[:env]
)

// command is one entry in the command table. Adding a command means adding
// one entry: its name, arguments, help line, authz action and handler all
// live here.
type command struct {
	name    string // one word, or two for grouped commands ("user add")
	args    string // argument synopsis for help and usage errors
	summary string
	action  authz.Action
	// scope says whether the first parameter names a project. For those,
	// Run resolves it and checks the caller's role in that project before
	// the handler is called.
	scope scope
	run   func(ctx context.Context, d Deps, inv *invocation) Result
}

// usage returns the command with its argument synopsis.
func (c command) usage() string {
	if c.args == "" {
		return c.name
	}
	return c.name + " " + c.args
}

// words is how many words of the command line the name takes up.
func (c command) words() int { return strings.Count(c.name, " ") + 1 }

// table lists every command, in help order. It is filled in init because
// the help handler reads the table.
var table []command

func init() {
	table = []command{
		{name: helpName, summary: "show this help", action: authz.Help, run: runHelp},
		{name: "whoami", summary: "show who you are and your projects", action: authz.Whoami, run: runWhoami},
		{name: "projects", summary: "list the projects you are a member of", action: authz.Projects, run: runProjects},
		{name: "init", args: "<project>", summary: "create a project (server admins only)", action: authz.Init, run: runInit},
		{name: "push", args: "<project[:env]> [-m message]", summary: "store the .env file on stdin as a new version", action: authz.Push, scope: scopeTarget, run: runPush},
		{name: "pull", args: "<project[:env]> [--version N]", summary: "print the latest .env file, or version N", action: authz.Pull, scope: scopeTarget, run: runPull},
		{name: "history", args: "<project[:env]> [--limit N]", summary: "list versions, newest first", action: authz.History, scope: scopeTarget, run: runHistory},
		{name: "diff", args: "<project[:env]> <a> <b>", summary: "show variable names added, removed or changed", action: authz.Diff, scope: scopeTarget, run: runDiff},
		{name: "members", args: "<project>", summary: "list who has which role", action: authz.Members, scope: scopeProject, run: runMembers},
		{name: "grant", args: "<project> <user|@github-user> [--role r]", summary: "give access (role: reader, writer or owner)", action: authz.Grant, scope: scopeProject, run: runGrant},
		{name: "revoke", args: "<project> <user|@github-user>", summary: "take access away", action: authz.Revoke, scope: scopeProject, run: runRevoke},
		{name: "user add", args: "<name> [--github <login>]", summary: "add a user with keys from stdin or GitHub (admins)", action: authz.ManageUsers, run: runUserAdd},
		{name: "user list", summary: "list users (admins)", action: authz.ManageUsers, run: runUserList},
		{name: "user disable", args: "<name>", summary: "disable a user (admins)", action: authz.ManageUsers, run: runUserDisable},
		{name: "key list", args: "<user>", summary: "list a user's keys (admins)", action: authz.ManageUsers, run: runKeyList},
		{name: "key add", args: "<user>", summary: "add keys from stdin to a user (admins)", action: authz.ManageUsers, run: runKeyAdd},
		{name: "key remove", args: "<user> <fingerprint>", summary: "remove one of a user's keys (admins)", action: authz.ManageUsers, run: runKeyRemove},
		{name: "key refresh", args: "<user>", summary: "re-fetch a user's keys from GitHub (admins)", action: authz.ManageUsers, run: runKeyRefresh},
	}
}

// lookup finds the command args start with. Two-word names are tried
// first, so "user add" is never mistaken for a command called "user".
func lookup(args []string) (command, bool) {
	for _, n := range []int{2, 1} {
		if len(args) < n {
			continue
		}
		name := strings.Join(args[:n], " ")
		if i := slices.IndexFunc(table, func(c command) bool { return c.name == name }); i >= 0 {
			return table[i], true
		}
	}
	return command{}, false
}

func helpText() string {
	width := 0
	for _, c := range table {
		width = max(width, len(c.usage()))
	}
	var b strings.Builder
	b.WriteString("ssshhh-env: share .env files over ssh\n\nusage: ssh <host> <command> [args]\n\ncommands:\n")
	for _, c := range table {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, c.usage(), c.summary)
	}
	b.WriteString("\nexamples:\n  ssh <host> push myapp < .env\n  ssh <host> pull myapp:prod > .env.prod\n  ssh <host> grant myapp @octocat --role writer\n")
	return b.String()
}
