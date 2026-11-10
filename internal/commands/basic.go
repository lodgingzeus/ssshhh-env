package commands

import (
	"context"
	"fmt"
)

func runHelp(_ context.Context, _ Deps, inv *invocation) Result {
	fmt.Fprint(inv.Stdout, helpText())
	return inv.ok("")
}

func runWhoami(_ context.Context, _ Deps, inv *invocation) Result {
	if len(inv.Args) != 1 {
		return inv.usageError()
	}
	id := inv.ID
	admin := "no"
	if id.IsAdmin {
		admin = "yes"
	}
	fmt.Fprintf(inv.Stdout, "user:        %s\nadmin:       %s\nkey:         %s\nfingerprint: %s\n", id.Name, admin, id.KeyType, id.Fingerprint)
	return inv.ok("")
}
