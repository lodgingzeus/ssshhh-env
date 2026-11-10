package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/github"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// errBadUserName is shown for an invalid new user name.
const errBadUserName = "invalid name: use 1-64 letters, digits, '.', '_' or '-', starting with a letter or digit"

// parseUserAddArgs parses "<name> [--github <login>]".
func parseUserAddArgs(params []string) (name, login string, ok bool) {
	switch {
	case len(params) == 1:
		return params[0], "", true
	case len(params) == 3 && params[1] == "--github":
		// GitHub logins are case-insensitive; store them one way.
		return params[0], strings.ToLower(params[2]), true
	default:
		return "", "", false
	}
}

// runUserAdd creates a user, with keys from stdin or fetched from GitHub
// and pinned. New users are never server admins: that is decided on the
// host, not over the network.
func runUserAdd(ctx context.Context, d Deps, inv *invocation) Result {
	name, login, ok := parseUserAddArgs(inv.Params)
	if !ok {
		return inv.usageError()
	}
	if !auth.ValidName(name) {
		return inv.refuse("invalid user name", errBadUserName)
	}
	if login != "" && !github.ValidLogin(login) {
		return inv.refuse("invalid github login", "invalid GitHub username")
	}
	inv.user = name

	// Checked before any network request; CreateUser checks again.
	if _, taken, err := findUser(ctx, d.Store, userRef{name: name}); err != nil {
		return inv.internal(d, "look up user", err)
	} else if taken {
		return inv.refuse("name taken", "a user with that name already exists")
	}
	if login != "" {
		if u, linked, err := findUser(ctx, d.Store, userRef{login: login}); err != nil {
			return inv.internal(d, "look up user", err)
		} else if linked {
			return inv.refuse("github login in use", fmt.Sprintf("GitHub user @%s was already added as %s", login, u.Name))
		}
	}

	var (
		pubs   []gossh.PublicKey
		fail   *Result
		source = store.SourceManual
	)
	if login != "" {
		source = store.SourceGitHub
		pubs, fail = fetchGitHubKeys(ctx, d, inv, login)
	} else {
		pubs, fail = readStdinKeys(inv)
	}
	if fail != nil {
		return *fail
	}
	keys, fail := acceptKeys(inv, pubs, source)
	if fail != nil {
		return *fail
	}

	u, err := d.Store.CreateUser(ctx, store.NewUser{Name: name, GitHubLogin: login}, keys)
	switch {
	case errors.Is(err, store.ErrExists):
		return inv.refuse("name taken", "a user with that name already exists")
	case errors.Is(err, store.ErrKeyInUse):
		return inv.refuse("key in use", "one of those keys is already registered to another user")
	case err != nil:
		return inv.internal(d, "create user", err)
	}
	fmt.Fprintf(inv.Stdout, "added user %s with these keys:\n", u.Name)
	writeFingerprints(inv.Stdout, keyFingerprints(keys))
	if source == store.SourceGitHub {
		fmt.Fprint(inv.Stdout, pinnedNotice)
	}
	fmt.Fprintf(inv.Stdout, "next: ssh <host> grant <project> %s\n", u.Name)
	res := inv.ok(fmt.Sprintf("user created with %s from %s", plural(len(keys), "key"), source))
	res.Changed = true
	return res
}

// runUserList lists every user.
func runUserList(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) != 0 {
		return inv.usageError()
	}
	users, err := d.Store.ListUsers(ctx)
	if err != nil {
		return inv.internal(d, "list users", err)
	}
	for _, u := range users {
		var notes []string
		if u.IsAdmin {
			notes = append(notes, "admin")
		}
		if u.GitHubLogin != "" {
			notes = append(notes, "github @"+u.GitHubLogin)
		}
		if u.Disabled {
			notes = append(notes, "disabled")
		}
		fmt.Fprintf(inv.Stdout, "%-24s %-7s  %s\n", u.Name, plural(u.Keys, "key"), strings.Join(notes, ", "))
	}
	return inv.ok("")
}

// runUserDisable disables a user: their keys stop working at once, on open
// connections too. Their memberships are kept, so the record of who could
// read what stays intact.
func runUserDisable(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) != 1 {
		return inv.usageError()
	}
	u, fail := requireUser(ctx, d, inv, inv.Params[0], true)
	if fail != nil {
		return *fail
	}
	switch {
	case u.ID == inv.ID.UserID:
		return inv.refuse("cannot disable self", "you can't disable your own account")
	case u.Disabled:
		return inv.refuse("already disabled", fmt.Sprintf("%s is already disabled", u.Name))
	}
	err := d.Store.DisableUser(ctx, u.ID)
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		return inv.refuse("last admin", fmt.Sprintf("%s is the only enabled admin", u.Name))
	case errors.Is(err, store.ErrNotFound):
		return inv.refuse("already disabled", fmt.Sprintf("%s is already disabled", u.Name))
	case err != nil:
		return inv.internal(d, "disable user", err)
	}

	fmt.Fprintf(inv.Stdout, "disabled %s; their keys no longer work\n", u.Name)
	memberships, err := d.Store.ProjectsForUser(ctx, u.ID)
	if err != nil {
		d.Log.Error("list projects failed", "cmd", inv.cmd.name, "target", inv.auditTarget(), "err", err)
	}
	if len(memberships) > 0 {
		names := make([]string, 0, len(memberships))
		for _, m := range memberships {
			names = append(names, m.Project)
		}
		fmt.Fprintf(inv.Stdout, "they could read: %s\nRotate the secrets in those projects: what they already pulled stays with them.\n", strings.Join(names, ", "))
	}
	res := inv.ok("user disabled")
	res.Changed = true
	return res
}
