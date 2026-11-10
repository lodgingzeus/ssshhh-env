package commands

import (
	"context"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/lodgingzeus/ssshhh-env/internal/crypto"
	"github.com/lodgingzeus/ssshhh-env/internal/envfile"
	"github.com/lodgingzeus/ssshhh-env/internal/sanitize"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// maxMessageLen is the longest -m message, in characters.
const maxMessageLen = 200

// parsePushArgs parses what follows the target: nothing, or "-m" and a
// message. ssh joins its arguments with spaces before sending them, so an
// unquoted multi-word message arrives as several arguments; everything
// after -m is the message.
func parsePushArgs(rest []string) (message string, ok bool) {
	if len(rest) == 0 {
		return "", true
	}
	if rest[0] != "-m" || len(rest) < 2 {
		return "", false
	}
	return strings.Join(rest[1:], " "), true
}

// runPush stores the .env file on stdin as the environment's next version.
// The file is validated, then encrypted before it reaches the store.
func runPush(ctx context.Context, d Deps, inv *invocation) Result {
	message, ok := parsePushArgs(inv.Args[2:])
	if !ok {
		return inv.usageError()
	}
	if utf8.RuneCountInString(message) > maxMessageLen {
		return inv.refuse("message too long", fmt.Sprintf("message is longer than %d characters", maxMessageLen))
	}
	message = sanitize.Text(message, maxMessageLen)

	// One byte over the limit is enough to know the file is too large,
	// without reading whatever else the client sends.
	data, err := io.ReadAll(io.LimitReader(inv.Stdin, envfile.MaxSize+1))
	if err != nil {
		return inv.refuse("could not read input", "could not read the .env file from stdin")
	}
	names, err := envfile.Parse(data)
	if err != nil {
		// envfile errors carry a line number and a fixed reason, never
		// any of the file's content.
		return inv.refuse("invalid .env file", "refused: "+err.Error())
	}

	dek, err := projectDEK(d.MasterKey, inv.project)
	if err != nil {
		return inv.internal(d, "unwrap data key", err)
	}
	v, err := d.Store.AppendVersion(ctx, store.NewVersion{
		ProjectID: inv.project.ID,
		EnvName:   inv.target.Env,
		AuthorID:  inv.ID.UserID,
		Message:   message,
		KeyNames:  names,
		SizeBytes: int64(len(data)),
	}, func(envID, number int64) (store.SealedVersion, error) {
		sealed, err := dek.SealVersion(crypto.VersionRef{ProjectID: inv.project.ID, EnvID: envID, Version: number}, data)
		if err != nil {
			return store.SealedVersion{}, err
		}
		return store.SealedVersion{Nonce: sealed.Nonce, Ciphertext: sealed.Ciphertext}, nil
	})
	if err != nil {
		return inv.internal(d, "store version", err)
	}
	noun := "variables"
	if len(names) == 1 {
		noun = "variable"
	}
	fmt.Fprintf(inv.Stdout, "pushed %s version %d (%d %s)\n", inv.target, v.Number, len(names), noun)
	return inv.ok(fmt.Sprintf("version %d", v.Number))
}
