package commands

import (
	"context"
	"errors"
	"fmt"

	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// runKeyList lists a user's keys.
func runKeyList(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) != 1 {
		return inv.usageError()
	}
	u, fail := requireUser(ctx, d, inv, inv.Params[0], true)
	if fail != nil {
		return *fail
	}
	keys, err := d.Store.KeysForUser(ctx, u.ID)
	if err != nil {
		return inv.internal(d, "list keys", err)
	}
	for _, k := range keys {
		used := k.LastUsedAt
		if used == "" {
			used = "never"
		}
		fmt.Fprintf(inv.Stdout, "%s  %-22s %-6s  last used %s\n", k.Fingerprint, k.KeyType, k.Source, used)
	}
	return inv.ok("")
}

// runKeyAdd adds the keys on stdin to a user.
func runKeyAdd(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) != 1 {
		return inv.usageError()
	}
	u, fail := requireUser(ctx, d, inv, inv.Params[0], true)
	if fail != nil {
		return *fail
	}
	pubs, fail := readStdinKeys(inv)
	if fail != nil {
		return *fail
	}
	keys, fail := acceptKeys(inv, pubs, store.SourceManual)
	if fail != nil {
		return *fail
	}
	added, err := d.Store.AddKeys(ctx, u.ID, keys)
	switch {
	case errors.Is(err, store.ErrKeyInUse):
		return inv.refuse("key in use", "one of those keys is already registered to another user; nothing was added")
	case err != nil:
		return inv.internal(d, "add keys", err)
	}
	if len(added) == 0 {
		fmt.Fprintf(inv.Stdout, "%s already has all of those keys; nothing changed\n", u.Name)
		return inv.ok("no new keys")
	}
	fmt.Fprintf(inv.Stdout, "added to %s:\n", u.Name)
	writeFingerprints(inv.Stdout, added)
	res := inv.ok(fmt.Sprintf("added %s", plural(len(added), "key")))
	res.Changed = true
	return res
}

// runKeyRemove removes one of a user's keys by fingerprint. A user's last
// key can't be removed: disable the user to lock them out.
func runKeyRemove(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) != 2 {
		return inv.usageError()
	}
	u, fail := requireUser(ctx, d, inv, inv.Params[0], true)
	if fail != nil {
		return *fail
	}
	fp := inv.Params[1]
	if !fingerprintRe.MatchString(fp) {
		return inv.refuse("invalid fingerprint", "invalid fingerprint: expected SHA256:... as shown by `key list`")
	}
	err := d.Store.RemoveKey(ctx, u.ID, fp)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return inv.refuse("no such key", fmt.Sprintf("%s has no key with that fingerprint", u.Name))
	case errors.Is(err, store.ErrLastKey):
		return inv.refuse("last key", fmt.Sprintf("that is %s's only key; use `user disable` to lock them out", u.Name))
	case err != nil:
		return inv.internal(d, "remove key", err)
	}
	fmt.Fprintf(inv.Stdout, "removed %s from %s; it no longer works\n", fp, u.Name)
	res := inv.ok("removed " + fp)
	res.Changed = true
	return res
}

// runKeyRefresh fetches a GitHub user's keys again and makes them the
// user's pinned GitHub keys. This is the only way a change on GitHub
// reaches the server, and it shows exactly what changed.
func runKeyRefresh(ctx context.Context, d Deps, inv *invocation) Result {
	if len(inv.Params) != 1 {
		return inv.usageError()
	}
	u, fail := requireUser(ctx, d, inv, inv.Params[0], true)
	if fail != nil {
		return *fail
	}
	if u.GitHubLogin == "" {
		return inv.refuse("not a github user", fmt.Sprintf("%s was not added from GitHub; use `key add` and `key remove`", u.Name))
	}
	pubs, fail := fetchGitHubKeys(ctx, d, inv, u.GitHubLogin)
	if fail != nil {
		return *fail
	}
	keys, fail := acceptKeys(inv, pubs, store.SourceGitHub)
	if fail != nil {
		return *fail
	}
	ch, err := d.Store.ReplaceGitHubKeys(ctx, u.ID, keys)
	switch {
	case errors.Is(err, store.ErrKeyInUse):
		return inv.refuse("key in use", "a key on GitHub is registered to another user; nothing changed")
	case err != nil:
		return inv.internal(d, "replace keys", err)
	}
	if len(ch.Added) == 0 && len(ch.Removed) == 0 {
		fmt.Fprintf(inv.Stdout, "%s's keys on GitHub @%s match the pinned ones; nothing changed\n", u.Name, u.GitHubLogin)
		return inv.ok("no changes")
	}
	if len(ch.Added) > 0 {
		fmt.Fprintf(inv.Stdout, "added (now pinned):\n")
		writeFingerprints(inv.Stdout, ch.Added)
	}
	if len(ch.Removed) > 0 {
		fmt.Fprintf(inv.Stdout, "removed (no longer on GitHub):\n")
		writeFingerprints(inv.Stdout, ch.Removed)
	}
	if len(ch.Added) > 0 {
		fmt.Fprint(inv.Stdout, "The added keys work now. Confirm them with the person, and remove any they\ndon't recognise with `key remove`.\n")
	}
	res := inv.ok(fmt.Sprintf("refreshed from github: %d added, %d removed", len(ch.Added), len(ch.Removed)))
	res.Changed = true
	return res
}
