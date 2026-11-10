package commands

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/github"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// maxKeyInput caps how many bytes of public keys are read from stdin.
const maxKeyInput = 64 << 10

// fingerprintRe is the form of an OpenSSH SHA256 fingerprint: unpadded
// base64 of a 32-byte hash.
var fingerprintRe = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// keyPolicyHint lists the key types the server accepts.
const keyPolicyHint = "allowed: ed25519, ECDSA, FIDO sk-*, RSA of 3072 bits or more"

// readStdinKeys reads public keys in authorized_keys format from stdin.
// On failure it returns the Result to give the client.
func readStdinKeys(inv *invocation) ([]gossh.PublicKey, *Result) {
	fail := func(r Result) ([]gossh.PublicKey, *Result) { return nil, &r }
	data, err := io.ReadAll(io.LimitReader(inv.Stdin, maxKeyInput+1))
	if err != nil {
		return fail(inv.refuse("could not read input", "could not read public keys from stdin"))
	}
	if len(data) > maxKeyInput {
		return fail(inv.refuse("input too large", fmt.Sprintf("public keys on stdin exceed %d KB", maxKeyInput>>10)))
	}
	// ParsePublicKeys errors give a line number and a fixed reason only.
	pubs, err := auth.ParsePublicKeys(data)
	if err != nil {
		return fail(inv.refuse("invalid public keys", "refused: "+err.Error()))
	}
	if len(pubs) == 0 {
		return fail(inv.refuse("no keys given", "no public keys on stdin (send a .pub file, e.g. < ~/.ssh/id_ed25519.pub)"))
	}
	return pubs, nil
}

// fetchGitHubKeys fetches login's keys from GitHub. On failure it returns
// the Result to give the client.
func fetchGitHubKeys(ctx context.Context, d Deps, inv *invocation, login string) ([]gossh.PublicKey, *Result) {
	pubs, err := d.GitHub.Keys(ctx, login)
	switch {
	case err == nil:
		return pubs, nil
	case errors.Is(err, github.ErrUserNotFound):
		r := inv.refuse("github user not found", fmt.Sprintf("GitHub has no user @%s", login))
		return nil, &r
	case errors.Is(err, github.ErrNoKeys):
		r := inv.refuse("github user has no keys", fmt.Sprintf("GitHub user @%s has no SSH keys", login))
		return nil, &r
	default:
		// Network and HTTP failures are logged, not shown.
		d.Log.Error("github key fetch failed", "cmd", inv.cmd.name, "login", login, "err", err)
		r := inv.refuse("github fetch failed", "could not fetch keys from GitHub; try again later")
		return nil, &r
	}
}

// acceptKeys applies the key policy and returns the keys to store. Each
// refused key is reported on stderr by type and fingerprint. On failure,
// when no key is acceptable, it returns the Result to give the client.
func acceptKeys(inv *invocation, pubs []gossh.PublicKey, source string) ([]store.NewKey, *Result) {
	var keys []store.NewKey
	for _, pub := range pubs {
		k, err := auth.NewKey(pub, source)
		if err != nil {
			fmt.Fprintf(inv.Stderr, "skipping %s %s: key type or size not allowed\n", pub.Type(), auth.Fingerprint(pub))
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		r := inv.refuse("no acceptable keys", "no acceptable keys ("+keyPolicyHint+")")
		return nil, &r
	}
	return keys, nil
}

// writeFingerprints prints one line per fingerprint, indented.
func writeFingerprints(w io.Writer, fps []string) {
	for _, fp := range fps {
		fmt.Fprintf(w, "  %s\n", fp)
	}
}

// keyFingerprints returns the fingerprints of keys, in order.
func keyFingerprints(keys []store.NewKey) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Fingerprint)
	}
	return out
}

// pinnedNotice tells the person adding keys from GitHub what to check.
const pinnedNotice = "These keys were fetched from GitHub once and are now pinned: later changes\n" +
	"on GitHub have no effect until an admin runs `key refresh`. Confirm the\n" +
	"fingerprints with the person (ssh-keygen -lf ~/.ssh/id_ed25519.pub).\n"
