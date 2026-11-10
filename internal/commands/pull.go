package commands

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/lodgingzeus/ssshhh-env/internal/crypto"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// parsePullArgs parses what follows the target: nothing, or "--version N"
// with N a positive decimal number. A version of 0 means the latest.
func parsePullArgs(rest []string) (version int64, ok bool) {
	if len(rest) == 0 {
		return 0, true
	}
	if len(rest) != 2 || rest[0] != "--version" {
		return 0, false
	}
	// ParseUint refuses signs, spaces and anything else that isn't a digit.
	n, err := strconv.ParseUint(rest[1], 10, 63)
	if err != nil || n == 0 {
		return 0, false
	}
	return int64(n), true // #nosec G115 -- parsed with bitSize 63
}

// runPull decrypts one version of an environment's .env file. It returns
// the plaintext in Result.Secret instead of writing it, so the caller can
// record the read before any of it leaves the server.
func runPull(ctx context.Context, d Deps, inv *invocation) Result {
	number, ok := parsePullArgs(inv.Args[2:])
	if !ok {
		return inv.usageError()
	}

	var (
		v   store.Version
		err error
	)
	if number == 0 {
		v, err = d.Store.LatestVersion(ctx, inv.project.ID, inv.target.Env)
	} else {
		v, err = d.Store.VersionByNumber(ctx, inv.project.ID, inv.target.Env, number)
	}
	if errors.Is(err, store.ErrNotFound) {
		if number == 0 {
			return inv.refuse("no such environment", "nothing has been pushed to that environment yet")
		}
		return inv.refuse("no such version", "no such version")
	}
	if err != nil {
		return inv.internal(d, "read version", err)
	}

	dek, err := projectDEK(d.MasterKey, inv.project)
	if err != nil {
		return inv.internal(d, "unwrap data key", err)
	}
	plaintext, err := dek.OpenVersion(
		crypto.VersionRef{ProjectID: inv.project.ID, EnvID: v.EnvID, Version: v.Number},
		crypto.Sealed{Nonce: v.Nonce, Ciphertext: v.Ciphertext})
	if err != nil {
		// The stored row does not decrypt as itself: it was modified, or
		// moved from another row.
		return inv.internal(d, "decrypt version", err)
	}
	res := inv.ok(fmt.Sprintf("version %d", v.Number))
	res.Secret = plaintext
	return res
}
