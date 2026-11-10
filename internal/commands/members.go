package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// runMembers lists a project's members and their roles.
func runMembers(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) != 1 {
		return inv.usageError()
	}
	members, err := d.Store.ListMembers(ctx, inv.project.ID)
	if err != nil {
		return inv.internal(d, "list members", err)
	}
	fmt.Fprintf(inv.Stdout, "%s\n", inv.target.Project)
	for _, m := range members {
		note := ""
		if m.Disabled {
			note = "  (disabled)"
		}
		fmt.Fprintf(inv.Stdout, "  %-6s  %-20s  granted by %s on %s%s\n", m.Role, m.Name, m.GrantedBy, m.GrantedAt, note)
	}
	return inv.ok("")
}

// runRevoke removes a user's access to a project. It takes effect at once:
// every command checks membership afresh. What the user already pulled
// can't be taken back, so the owner is told to rotate those secrets.
func runRevoke(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) != 2 {
		return inv.usageError()
	}
	u, fail := requireUser(ctx, d, inv, inv.Params[1], false)
	if fail != nil {
		return *fail
	}
	err := d.Store.RemoveMember(ctx, inv.project.ID, u.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return inv.refuse("not a member", fmt.Sprintf("%s is not a member of %s", u.Name, inv.target.Project))
	case errors.Is(err, store.ErrLastOwner):
		return inv.refuse("last owner", fmt.Sprintf("%s is the only owner of %s; grant another owner first", u.Name, inv.target.Project))
	case err != nil:
		return inv.internal(d, "remove member", err)
	}

	fmt.Fprintf(inv.Stdout, "revoked %s's access to %s\n", u.Name, inv.target.Project)
	// The change is made; a failure listing environments only loses the
	// detail of the reminder, not the reminder itself.
	envs, err := d.Store.EnvironmentNames(ctx, inv.project.ID)
	if err != nil {
		d.Log.Error("list environments failed", "cmd", inv.cmd.name, "target", inv.auditTarget(), "err", err)
	}
	switch {
	case err == nil && len(envs) == 0:
		fmt.Fprintln(inv.Stdout, "nothing has been pushed to this project, so there is nothing to rotate")
	default:
		if len(envs) > 0 {
			fmt.Fprintf(inv.Stdout, "\n%s could read: %s\n", u.Name, strings.Join(envs, ", "))
		}
		fmt.Fprintf(inv.Stdout, "Revoking access does not un-share what they already pulled.\n"+
			"Rotate those secrets: change them where they are issued, then push the new values.\n")
	}
	res := inv.ok("revoked " + u.Name)
	res.Changed = true
	return res
}
