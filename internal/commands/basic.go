package commands

import (
	"context"
	"fmt"
	"strings"
)

func runHelp(_ context.Context, _ Deps, inv *invocation) Result {
	fmt.Fprint(inv.Stdout, helpText())
	return inv.ok("")
}

// runWhoami shows the caller's account, key and role in each project.
func runWhoami(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) != 0 {
		return inv.usageError()
	}
	memberships, err := d.Store.ProjectsForUser(ctx, inv.ID.UserID)
	if err != nil {
		return inv.internal(d, "list projects", err)
	}
	id := inv.ID
	admin := "no"
	if id.IsAdmin {
		admin = "yes"
	}
	roles := make([]string, 0, len(memberships))
	for _, m := range memberships {
		roles = append(roles, fmt.Sprintf("%s (%s)", m.Project, m.Role))
	}
	projects := "none"
	if len(roles) > 0 {
		projects = strings.Join(roles, ", ")
	}
	fmt.Fprintf(inv.Stdout, "user:        %s\nadmin:       %s\nkey:         %s\nfingerprint: %s\nprojects:    %s\n",
		id.Name, admin, id.KeyType, id.Fingerprint, projects)
	return inv.ok("")
}

// runProjects lists the projects the caller is a member of. Server admins
// see only their own projects too: being an admin grants no project access.
func runProjects(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) != 0 {
		return inv.usageError()
	}
	memberships, err := d.Store.ProjectsForUser(ctx, inv.ID.UserID)
	if err != nil {
		return inv.internal(d, "list projects", err)
	}
	if len(memberships) == 0 {
		fmt.Fprintln(inv.Stdout, "you are not a member of any project")
		return inv.ok("")
	}
	for _, m := range memberships {
		envs := "no environments yet"
		if len(m.Envs) > 0 {
			envs = "environments: " + strings.Join(m.Envs, ", ")
		}
		fmt.Fprintf(inv.Stdout, "%-24s %-6s  %s\n", m.Project, m.Role, envs)
	}
	return inv.ok("")
}
