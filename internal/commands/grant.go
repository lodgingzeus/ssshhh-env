package commands

import (
	"context"
	"errors"
	"fmt"

	"github.com/lodgingzeus/ssshhh-env/internal/authz"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// parseGrantArgs parses what follows the user: nothing (reader), or
// "--role r". given reports whether a role was named explicitly.
func parseGrantArgs(rest []string) (role authz.Role, given, ok bool) {
	if len(rest) == 0 {
		return authz.RoleReader, false, true
	}
	if len(rest) != 2 || rest[0] != "--role" {
		return authz.RoleNone, false, false
	}
	role = authz.ParseRole(rest[1])
	return role, true, role != authz.RoleNone
}

// runGrant gives a user a role in a project. A user named as @login who
// has no account yet gets one, with their GitHub keys fetched now and
// pinned. Granting to an existing member changes their role only if a
// different --role is given explicitly.
func runGrant(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) < 2 {
		return inv.usageError()
	}
	role, roleGiven, ok := parseGrantArgs(inv.Params[2:])
	if !ok {
		return inv.usageError()
	}
	ref, ok := parseUserRef(inv.Params[1])
	if !ok {
		return inv.refuse("invalid user", errBadUser)
	}
	u, created, fail := granteeUser(ctx, d, inv, ref)
	if fail != nil {
		return *fail
	}
	if u.Disabled {
		return inv.refuse("user disabled", fmt.Sprintf("%s is disabled", u.Name))
	}

	res := grantRole(ctx, d, inv, u, role, roleGiven)
	if created != "" {
		// The account exists now whether or not the role was granted.
		res.Changed = true
		res.Detail = created + "; " + res.Detail
	}
	return res
}

// grantRole adds u to the project with role, or changes their role.
func grantRole(ctx context.Context, d Deps, inv *invocation, u store.User, role authz.Role, roleGiven bool) Result {
	project := inv.target.Project
	current, err := d.Store.MemberRole(ctx, inv.project.ID, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		err = d.Store.AddMember(ctx, inv.project.ID, u.ID, role.String(), inv.ID.UserID)
		if errors.Is(err, store.ErrExists) {
			return inv.refuse("already a member", fmt.Sprintf("%s was just added to %s by someone else", u.Name, project))
		}
		if err != nil {
			return inv.internal(d, "add member", err)
		}
		fmt.Fprintf(inv.Stdout, "granted %s the %s role in %s\n", u.Name, role, project)
		res := inv.ok(fmt.Sprintf("granted %s to %s", role, u.Name))
		res.Changed = true
		return res
	}
	if err != nil {
		return inv.internal(d, "look up member", err)
	}

	switch {
	case current == role.String():
		return inv.refuse("already has role", fmt.Sprintf("%s is already a %s of %s", u.Name, current, project))
	case !roleGiven:
		return inv.refuse("already a member", fmt.Sprintf("%s is already a %s of %s; give --role to change it", u.Name, current, project))
	}
	err = d.Store.SetMemberRole(ctx, inv.project.ID, u.ID, role.String(), inv.ID.UserID)
	switch {
	case errors.Is(err, store.ErrLastOwner):
		return inv.refuse("last owner", fmt.Sprintf("%s is the only owner of %s; grant another owner first", u.Name, project))
	case errors.Is(err, store.ErrNotFound):
		return inv.refuse("not a member", fmt.Sprintf("%s was just removed from %s by someone else", u.Name, project))
	case err != nil:
		return inv.internal(d, "set member role", err)
	}
	fmt.Fprintf(inv.Stdout, "changed %s's role in %s from %s to %s\n", u.Name, project, current, role)
	res := inv.ok(fmt.Sprintf("changed %s from %s to %s", u.Name, current, role))
	res.Changed = true
	return res
}

// granteeUser finds the user ref names, creating them from GitHub if ref
// is an @login nobody has been added under yet. created describes the new
// account for the audit log, or is empty if the user already existed.
func granteeUser(ctx context.Context, d Deps, inv *invocation, ref userRef) (u store.User, created string, fail *Result) {
	failed := func(r Result) (store.User, string, *Result) { return store.User{}, "", &r }

	u, found, err := findUser(ctx, d.Store, ref)
	if err != nil {
		return failed(inv.internal(d, "look up user", err))
	}
	if found {
		// An existing user's keys were pinned when they were added. They
		// are not fetched again here: that would let a change on GitHub
		// slip in without an admin's `key refresh`.
		return u, "", nil
	}
	if ref.login == "" {
		return failed(inv.refuse("no such user", fmt.Sprintf("no such user: %s (to add someone from GitHub, use @their-github-username)", ref.name)))
	}

	// A GitHub login is a valid user name, and the new account is named
	// after it. A different person may already have that name.
	if _, taken, err := findUser(ctx, d.Store, userRef{name: ref.login}); err != nil {
		return failed(inv.internal(d, "look up user", err))
	} else if taken {
		return failed(inv.refuse("name taken", fmt.Sprintf(
			"a user named %s already exists but was not added from GitHub @%s; grant them by name if they are the same person", ref.login, ref.login)))
	}

	pubs, fail := fetchGitHubKeys(ctx, d, inv, ref.login)
	if fail != nil {
		return store.User{}, "", fail
	}
	keys, fail := acceptKeys(inv, pubs, store.SourceGitHub)
	if fail != nil {
		return store.User{}, "", fail
	}
	u, err = d.Store.CreateUser(ctx, store.NewUser{Name: ref.login, GitHubLogin: ref.login}, keys)
	switch {
	case errors.Is(err, store.ErrExists):
		return failed(inv.refuse("name taken", fmt.Sprintf("a user named %s was just added by someone else; try again", ref.login)))
	case errors.Is(err, store.ErrKeyInUse):
		return failed(inv.refuse("key in use", fmt.Sprintf(
			"a key of GitHub user @%s is already registered to another user; grant that user by name instead", ref.login)))
	case err != nil:
		return failed(inv.internal(d, "create user", err))
	}

	fmt.Fprintf(inv.Stdout, "added user %s from GitHub @%s with these keys:\n", u.Name, ref.login)
	writeFingerprints(inv.Stdout, keyFingerprints(keys))
	fmt.Fprint(inv.Stdout, pinnedNotice+"\n")
	return u, fmt.Sprintf("created user %s from github with %s", u.Name, plural(len(keys), "key")), nil
}
