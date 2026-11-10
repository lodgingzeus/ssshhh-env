package commands

import (
	"context"
	"errors"
	"strings"

	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/github"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// userRef is a user as named on a command line: by user name, or by GitHub
// login with a leading '@'.
type userRef struct {
	name  string // set for "name"
	login string // set for "@login"
}

// parseUserRef validates s as a user name or "@" and a GitHub login.
// GitHub logins are case-insensitive, so they are lowercased: an account
// created from @OctoCat is named octocat.
func parseUserRef(s string) (userRef, bool) {
	if login, ok := strings.CutPrefix(s, "@"); ok {
		return userRef{login: strings.ToLower(login)}, github.ValidLogin(login)
	}
	return userRef{name: s}, auth.ValidName(s)
}

// String returns the reference as typed: "name" or "@login".
func (r userRef) String() string {
	if r.login != "" {
		return "@" + r.login
	}
	return r.name
}

// errBadUser is shown for a malformed user argument. The argument itself
// is not echoed.
const errBadUser = "invalid user: give a user name, or @ and a GitHub username"

// findUser looks up the user ref names. found is false, with a nil error,
// if there is no such user.
func findUser(ctx context.Context, st Store, ref userRef) (u store.User, found bool, err error) {
	if ref.login != "" {
		u, err = st.UserByGitHubLogin(ctx, ref.login)
	} else {
		u, err = st.UserByName(ctx, ref.name)
	}
	if errors.Is(err, store.ErrNotFound) {
		return store.User{}, false, nil
	}
	return u, err == nil, err
}

// requireUser parses arg and looks the user up. On failure it returns the
// Result to give the client. For account commands it also records the
// user's name as the audit target.
func requireUser(ctx context.Context, d Deps, inv *invocation, arg string, audited bool) (store.User, *Result) {
	fail := func(r Result) (store.User, *Result) { return store.User{}, &r }
	ref, ok := parseUserRef(arg)
	if !ok {
		return fail(inv.refuse("invalid user", errBadUser))
	}
	u, found, err := findUser(ctx, d.Store, ref)
	if err != nil {
		return fail(inv.internal(d, "look up user", err))
	}
	if !found {
		return fail(inv.refuse("no such user", "no such user: "+ref.String()))
	}
	if audited {
		inv.user = u.Name
	}
	return u, nil
}
