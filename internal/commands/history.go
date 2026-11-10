package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/lodgingzeus/ssshhh-env/internal/envfile"
	"github.com/lodgingzeus/ssshhh-env/internal/sanitize"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// History limits: how many versions are listed by default, and at most.
const (
	defaultHistory = 20
	maxHistory     = 1000
)

// parseHistoryArgs parses what follows the target: nothing, or
// "--limit N" with 1 <= N <= maxHistory.
func parseHistoryArgs(rest []string) (limit int, ok bool) {
	if len(rest) == 0 {
		return defaultHistory, true
	}
	if len(rest) != 2 || rest[0] != "--limit" {
		return 0, false
	}
	n, ok := parsePositive(rest[1])
	if !ok || n > maxHistory {
		return 0, false
	}
	return int(n), true
}

// runHistory lists an environment's versions from their stored metadata.
// It decrypts nothing: names added and removed come from the key names
// stored with each version.
func runHistory(ctx context.Context, d Deps, inv *invocation) Result {
	limit, ok := parseHistoryArgs(inv.Params[1:])
	if !ok {
		return inv.usageError()
	}
	// One more than shown, so the oldest shown version can be compared
	// with the one before it.
	versions, err := d.Store.ListVersions(ctx, inv.project.ID, inv.target.Env, limit+1)
	if errors.Is(err, store.ErrNotFound) {
		return inv.refuse("no such environment", "nothing has been pushed to that environment yet")
	}
	if err != nil {
		return inv.internal(d, "list versions", err)
	}
	more := len(versions) > limit
	shown := versions[:min(len(versions), limit)]

	fmt.Fprintf(inv.Stdout, "%s\n", inv.target)
	for i, v := range shown {
		fmt.Fprintf(inv.Stdout, "\nversion %d  %s  by %s  (%s)\n", v.Number, v.CreatedAt, sanitize.Text(v.Author, 64), plural(len(v.KeyNames), "variable"))
		if v.Message != "" {
			fmt.Fprintf(inv.Stdout, "  message: %s\n", sanitize.Text(v.Message, maxMessageLen))
		}
		if i+1 < len(versions) {
			writeNameChanges(inv.Stdout, envfile.NameChanges(versions[i+1].KeyNames, v.KeyNames))
		} else {
			fmt.Fprintln(inv.Stdout, "  first version")
		}
	}
	if more {
		fmt.Fprintf(inv.Stdout, "\nshowing the newest %d; use --limit N (up to %d) to see more\n", limit, maxHistory)
	}
	return inv.ok("")
}

// writeNameChanges prints the names added and removed by one version.
func writeNameChanges(w io.Writer, ch envfile.Changes) {
	if len(ch.Added) == 0 && len(ch.Removed) == 0 {
		fmt.Fprintln(w, "  no variables added or removed")
		return
	}
	writeNames(w, "added:  ", ch.Added)
	writeNames(w, "removed:", ch.Removed)
}

// runDiff compares two versions of an environment and prints the names of
// the variables that were added, removed or changed. Both versions are
// decrypted to compare values, but values are never printed: envfile.Diff
// returns names only.
func runDiff(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) != 3 {
		return inv.usageError()
	}
	a, okA := parsePositive(inv.Params[1])
	b, okB := parsePositive(inv.Params[2])
	if !okA || !okB {
		return inv.usageError()
	}
	older, _, fail := readVersion(ctx, d, inv, a)
	if fail != nil {
		return *fail
	}
	newer, _, fail := readVersion(ctx, d, inv, b)
	if fail != nil {
		return *fail
	}
	ch, err := envfile.Diff(older, newer)
	if err != nil {
		// Every stored version passed the same parser when it was pushed.
		return inv.internal(d, "compare versions", err)
	}

	fmt.Fprintf(inv.Stdout, "%s: version %d -> version %d\n", inv.target, a, b)
	if len(ch.Added)+len(ch.Removed)+len(ch.Changed) == 0 {
		fmt.Fprintln(inv.Stdout, "no differences")
	} else {
		writeNames(inv.Stdout, "added:  ", ch.Added)
		writeNames(inv.Stdout, "removed:", ch.Removed)
		writeNames(inv.Stdout, "changed:", ch.Changed)
	}
	return inv.ok(fmt.Sprintf("versions %d and %d", a, b))
}

// writeNames prints a labelled, comma-separated list of variable names, or
// nothing if the list is empty. Names passed envfile's validation, which
// allows no control characters.
func writeNames(w io.Writer, label string, names []string) {
	if len(names) > 0 {
		fmt.Fprintf(w, "  %s %s\n", label, strings.Join(names, ", "))
	}
}

// plural returns "1 variable" or "N variables".
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
