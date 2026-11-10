package commands

import (
	"context"
	"errors"
	"fmt"

	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// runInit creates a project with a fresh data key. The creator becomes its
// owner, which is the only way a server admin gets access to a project.
func runInit(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Args) != 2 {
		return inv.usageError()
	}
	name := inv.Args[1]
	if !ValidName(name) {
		return inv.refuse("invalid project name", errBadTarget.Error())
	}
	inv.target = Target{Project: name}

	_, err := d.Store.CreateProject(ctx, name, inv.ID.UserID, newProjectDEK(d.MasterKey))
	if errors.Is(err, store.ErrExists) {
		return inv.refuse("project already exists", "a project with that name already exists")
	}
	if err != nil {
		return inv.internal(d, "create project", err)
	}
	fmt.Fprintf(inv.Stdout, "created project %s; you are its owner\nnext: ssh <host> push %s < .env\n", name, name)
	return inv.ok("project created")
}
