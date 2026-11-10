package commands

import (
	"context"
	"errors"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// Every account command is for server admins only.
func TestAccountCommandsNeedAdmin(t *testing.T) {
	e := newTestEnv(t)
	for _, line := range []string{"user add carol", "user list", "user disable bob", "key list bob", "key add bob", "key remove bob SHA256:x", "key refresh bob"} {
		res, out, stderr := e.runLine(e.alice, authorizedKeys(newPubKey(t)), line)
		if res.Code != 1 || res.Outcome != audit.Denied || out != "" || !strings.Contains(stderr, "permission denied") {
			t.Errorf("%q as non-admin: %+v, %q", line, res, stderr)
		}
	}
	if _, err := e.st.UserByName(context.Background(), "carol"); !errors.Is(err, store.ErrNotFound) {
		t.Error("a non-admin created a user")
	}
}

func TestUserAdd(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	k1, k2 := newPubKey(t), newPubKey(t)

	res, out, stderr := e.run(e.root, authorizedKeys(k1, k2, weakRSAKey(t)), "user", "add", "carol")
	if res.Code != 0 || !res.Changed || res.Target != "user:carol" || res.Detail != "user created with 2 keys from manual" {
		t.Fatalf("user add: %+v, %q", res, stderr)
	}
	if !strings.Contains(out, auth.Fingerprint(k1)) || !strings.Contains(out, auth.Fingerprint(k2)) || !strings.Contains(stderr, "skipping ssh-rsa") {
		t.Errorf("output %q, stderr %q", out, stderr)
	}
	u, err := e.st.UserByName(ctx, "carol")
	if err != nil || u.IsAdmin || u.GitHubLogin != "" {
		t.Fatalf("carol = %+v, %v", u, err)
	}

	gh := newPubKey(t)
	e.github.users["dave-gh"] = []gossh.PublicKey{gh}
	res, out, _ = e.run(e.root, "", "user", "add", "dave", "--github", "Dave-GH")
	if res.Code != 0 || !strings.Contains(out, auth.Fingerprint(gh)) || !strings.Contains(out, "pinned") {
		t.Fatalf("user add --github: %+v, %q", res, out)
	}
	if u, err := e.st.UserByGitHubLogin(ctx, "dave-gh"); err != nil || u.Name != "dave" {
		t.Fatalf("dave = %+v, %v", u, err)
	}
}

func TestUserAddRefusals(t *testing.T) {
	e := newTestEnv(t)
	e.github.users["bob-gh"] = []gossh.PublicKey{newPubKey(t)}
	if res, _, stderr := e.run(e.root, "", "user", "add", "bobby", "--github", "bob-gh"); res.Code != 0 {
		t.Fatal(stderr)
	}
	tests := []struct {
		name, stdin, line, stderr string
	}{
		{"no name", "", "user add", "usage: user add"},
		{"bad flag", "", "user add x --gh y", "usage: user add"},
		{"bad name", "", "user add -x", "invalid name"},
		{"bad login", "", "user add x --github -bad", "invalid GitHub username"},
		{"taken name, other case", authorizedKeys(newPubKey(t)), "user add BOB", "already exists"},
		{"github login already added", "", "user add other --github BOB-GH", "already added as bobby"},
		{"no keys on stdin", "", "user add carol", "no public keys on stdin"},
		{"not keys", "hello\n", "user add carol", "line 1: not a public key"},
		{"key options", "command=\"x\" " + authorizedKeys(newPubKey(t)), "user add carol", "key options are not supported"},
		{"only weak keys", authorizedKeys(weakRSAKey(t)), "user add carol", "no acceptable keys"},
		{"too much input", strings.Repeat("#", maxKeyInput+1), "user add carol", "exceed"},
		{"key of another user", authorizedKeys(newPubKey(t)) + e.aliceKeyLine(t), "user add carol", "already registered to another user"},
		{"github user missing", "", "user add carol --github nobody", "GitHub has no user @nobody"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _, stderr := e.runLine(e.root, tt.stdin, tt.line)
			if res.Code != 1 || res.Changed || !strings.Contains(stderr, tt.stderr) {
				t.Fatalf("%+v, stderr %q", res, stderr)
			}
		})
	}
	if _, err := e.st.UserByName(context.Background(), "carol"); !errors.Is(err, store.ErrNotFound) {
		t.Error("a refused user add created carol")
	}
}

// aliceKeyLine registers a real key for alice and returns it as a line.
func (e *testEnv) aliceKeyLine(t *testing.T) string {
	t.Helper()
	k := newPubKey(t)
	if _, err := e.st.AddKeys(context.Background(), e.alice.UserID, []store.NewKey{mustNewKey(t, k)}); err != nil {
		t.Fatal(err)
	}
	return authorizedKeys(k)
}

func TestUserListAndDisable(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", map[auth.Identity]string{e.bob: store.RoleReader})

	_, out, _ := e.run(e.root, "", "user", "list")
	if !strings.Contains(out, "root") || !strings.Contains(out, "admin") || !strings.Contains(out, "bob") || !strings.Contains(out, "1 key") {
		t.Errorf("user list:\n%s", out)
	}

	res, out, _ := e.run(e.root, "", "user", "disable", "bob")
	if res.Code != 0 || !res.Changed || res.Target != "user:bob" || !strings.Contains(out, "they could read: app") {
		t.Fatalf("disable: %+v, %q", res, out)
	}
	if _, out, _ := e.run(e.root, "", "user", "list"); !strings.Contains(out, "disabled") {
		t.Errorf("user list doesn't show disabled:\n%s", out)
	}

	for _, tt := range []struct{ line, stderr string }{
		{"user disable bob", "already disabled"},
		{"user disable root", "can't disable your own account"},
		{"user disable nobody", "no such user"},
		{"user disable", "usage: user disable"},
	} {
		if res, _, stderr := e.runLine(e.root, "", tt.line); res.Code != 1 || !strings.Contains(stderr, tt.stderr) {
			t.Errorf("%q: %+v, %q", tt.line, res, stderr)
		}
	}
}

func TestDisableLastAdmin(t *testing.T) {
	e := newTestEnv(t)
	// A second admin can't disable root if root is the only other admin...
	admin2, err := e.st.CreateUser(context.Background(), store.NewUser{Name: "admin2", IsAdmin: true}, []store.NewKey{mustNewKey(t, newPubKey(t))})
	if err != nil {
		t.Fatal(err)
	}
	id2 := auth.Identity{UserID: admin2.ID, Name: "admin2", IsAdmin: true}
	if res, _, stderr := e.run(id2, "", "user", "disable", "root"); res.Code != 0 {
		t.Fatalf("disable one of two admins: %s", stderr)
	}
	// ...and once root is disabled, admin2 is the last one.
	if err := e.st.DisableUser(context.Background(), admin2.ID); !errors.Is(err, store.ErrLastAdmin) {
		t.Fatalf("last admin: %v", err)
	}
}

func TestKeyCommands(t *testing.T) {
	e := newTestEnv(t)
	k1, k2 := newPubKey(t), newPubKey(t)

	res, out, _ := e.run(e.root, authorizedKeys(k1, k2), "key", "add", "bob")
	if res.Code != 0 || !res.Changed || res.Detail != "added 2 keys" || !strings.Contains(out, auth.Fingerprint(k1)) {
		t.Fatalf("key add: %+v, %q", res, out)
	}
	res, out, _ = e.run(e.root, authorizedKeys(k1), "key", "add", "bob")
	if res.Code != 0 || res.Changed || !strings.Contains(out, "nothing changed") {
		t.Fatalf("key add again: %+v, %q", res, out)
	}
	if res, _, stderr := e.run(e.root, authorizedKeys(k1), "key", "add", "alice"); res.Code != 1 || !strings.Contains(stderr, "already registered to another user") {
		t.Fatalf("key add of bob's key to alice: %+v, %q", res, stderr)
	}

	_, out, _ = e.run(e.root, "", "key", "list", "bob")
	if strings.Count(out, "SHA256:") != 3 || !strings.Contains(out, "never") {
		t.Errorf("key list:\n%s", out)
	}

	fp := auth.Fingerprint(k1)
	if res, out, _ := e.run(e.root, "", "key", "remove", "bob", fp); res.Code != 0 || !res.Changed || !strings.Contains(out, "removed "+fp) {
		t.Fatalf("key remove: %+v, %q", res, out)
	}
	for _, tt := range []struct{ line, stderr string }{
		{"key remove bob " + fp, "no key with that fingerprint"},
		{"key remove bob not-a-fingerprint", "invalid fingerprint"},
		{"key remove alice " + auth.Fingerprint(k2), "no key with that fingerprint"},
		{"key remove alice SHA256:alice", "invalid fingerprint"},
		{"key refresh bob", "was not added from GitHub"},
		{"key add", "usage: key add"},
	} {
		if res, _, stderr := e.runLine(e.root, "", tt.line); res.Code != 1 || !strings.Contains(stderr, tt.stderr) {
			t.Errorf("%q: %+v, %q", tt.line, res, stderr)
		}
	}
}

func TestKeyRemoveLastKey(t *testing.T) {
	e := newTestEnv(t)
	k := newPubKey(t)
	if res, _, stderr := e.run(e.root, authorizedKeys(k), "user", "add", "carol"); res.Code != 0 {
		t.Fatal(stderr)
	}
	res, _, stderr := e.run(e.root, "", "key", "remove", "carol", auth.Fingerprint(k))
	if res.Code != 1 || !strings.Contains(stderr, "only key") {
		t.Fatalf("remove last key: %+v, %q", res, stderr)
	}
}

func TestKeyRefresh(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	old1, old2, manual := newPubKey(t), newPubKey(t), newPubKey(t)
	e.github.users["octo"] = []gossh.PublicKey{old1, old2}
	if res, _, stderr := e.run(e.root, "", "user", "add", "octo", "--github", "octo"); res.Code != 0 {
		t.Fatal(stderr)
	}
	if res, _, stderr := e.run(e.root, authorizedKeys(manual), "key", "add", "octo"); res.Code != 0 {
		t.Fatal(stderr)
	}

	// Nothing changed on GitHub.
	if res, out, _ := e.run(e.root, "", "key", "refresh", "octo"); res.Code != 0 || res.Changed || !strings.Contains(out, "nothing changed") {
		t.Fatalf("no-op refresh: %+v, %q", res, out)
	}

	added := newPubKey(t)
	e.github.users["octo"] = []gossh.PublicKey{old2, added}
	res, out, _ := e.run(e.root, "", "key", "refresh", "octo")
	if res.Code != 0 || !res.Changed || res.Detail != "refreshed from github: 1 added, 1 removed" {
		t.Fatalf("refresh: %+v", res)
	}
	addedAt, removedAt := strings.Index(out, auth.Fingerprint(added)), strings.Index(out, auth.Fingerprint(old1))
	if addedAt < 0 || removedAt < 0 || addedAt > strings.Index(out, "removed") {
		t.Errorf("refresh output:\n%s", out)
	}
	u, _ := e.st.UserByName(ctx, "octo")
	fps := strings.Join(keysOf(t, e, u.ID), " ")
	if strings.Contains(fps, auth.Fingerprint(old1)) || !strings.Contains(fps, auth.Fingerprint(manual)) || !strings.Contains(fps, auth.Fingerprint(added)) {
		t.Errorf("keys after refresh: %s", fps)
	}

	// GitHub now lists nothing usable: refused, nothing removed.
	e.github.users["octo"] = nil
	if res, _, stderr := e.run(e.root, "", "key", "refresh", "octo"); res.Code != 1 || !strings.Contains(stderr, "no SSH keys") {
		t.Fatalf("refresh to no keys: %+v, %q", res, stderr)
	}
	if got := keysOf(t, e, u.ID); len(got) != 3 {
		t.Errorf("a refused refresh changed keys: %v", got)
	}
}
