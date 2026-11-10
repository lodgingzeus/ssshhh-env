package commands

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

func TestGrantAndRevoke(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	p := e.project(t, "app", nil)
	e.push(t, "app", sampleEnv)
	e.push(t, "app:prod", sampleEnv)

	// Before the grant, bob is told the project might not exist.
	if res, _, stderr := e.run(e.bob, "", "pull", "app"); res.Outcome != audit.Denied || !strings.Contains(stderr, "no such project") {
		t.Fatalf("pull before grant: %+v, %q", res, stderr)
	}

	res, out, _ := e.run(e.root, "", "grant", "app", "bob")
	if res.Code != 0 || !res.Changed || res.Target != "app" || res.Detail != "granted reader to bob" || !strings.Contains(out, "granted bob the reader role in app") {
		t.Fatalf("grant: %+v, %q", res, out)
	}
	if res, _, _ := e.run(e.bob, "", "pull", "app"); res.Code != 0 || string(res.Secret) != sampleEnv {
		t.Fatalf("pull after grant: %+v", res)
	}
	// A reader can't push or manage members.
	for _, args := range [][]string{{"push", "app"}, {"grant", "app", "alice"}, {"revoke", "app", "root"}} {
		if res, _, stderr := e.run(e.bob, sampleEnv, args...); res.Outcome != audit.Denied || !strings.Contains(stderr, "your role in app is reader") {
			t.Errorf("%v as reader: %+v, %q", args, res, stderr)
		}
	}

	res, out, _ = e.run(e.root, "", "revoke", "app", "bob")
	if res.Code != 0 || !res.Changed || res.Detail != "revoked bob" {
		t.Fatalf("revoke: %+v", res)
	}
	for _, want := range []string{"revoked bob's access to app", "bob could read: default, prod", "Rotate those secrets"} {
		if !strings.Contains(out, want) {
			t.Errorf("revoke output lacks %q:\n%s", want, out)
		}
	}
	if res, _, stderr := e.run(e.bob, "", "pull", "app"); res.Outcome != audit.Denied || !strings.Contains(stderr, "no such project") {
		t.Fatalf("pull after revoke: %+v, %q", res, stderr)
	}
	if _, err := e.st.MemberRole(ctx, p.ID, e.bob.UserID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("membership left after revoke: %v", err)
	}
}

func TestGrantRoleChanges(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", map[auth.Identity]string{e.bob: store.RoleReader})

	tests := []struct {
		name   string
		args   []string
		code   int
		output string
	}{
		{"same role again", []string{"grant", "app", "bob"}, 1, "already a reader of app"},
		{"no role given", []string{"grant", "app", "bob"}, 1, "already a reader"},
		{"explicit same role", []string{"grant", "app", "bob", "--role", "reader"}, 1, "already a reader"},
		{"promote", []string{"grant", "app", "bob", "--role", "owner"}, 0, "from reader to owner"},
		{"demote the original owner", []string{"grant", "app", "root", "--role", "writer"}, 0, "from owner to writer"},
		{"demote the last owner", []string{"grant", "app", "bob", "--role", "reader"}, 1, "only owner of app"},
		{"revoke the last owner", []string{"revoke", "app", "bob"}, 1, "only owner of app"},
	}
	for _, tt := range tests {
		id := e.root
		if tt.name == "demote the last owner" || tt.name == "revoke the last owner" {
			id = e.bob // root is only a writer by now
		}
		res, out, stderr := e.run(id, "", tt.args...)
		if res.Code != tt.code || !strings.Contains(out+stderr, tt.output) {
			t.Errorf("%s: %+v, out %q, stderr %q", tt.name, res, out, stderr)
		}
	}
}

func TestGrantRevokeRefusals(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", nil)
	if err := e.st.DisableUser(context.Background(), e.alice.UserID); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		args   []string
		stderr string
	}{
		{"env in project", []string{"grant", "app:prod", "bob"}, "access is per project: give app, not an environment"},
		{"env in bad project", []string{"grant", "A:prod", "bob"}, "invalid name"},
		{"no user", []string{"grant", "app"}, "usage: grant"},
		{"bad role", []string{"grant", "app", "bob", "--role", "admin"}, "usage: grant"},
		{"role without value", []string{"grant", "app", "bob", "--role"}, "usage: grant"},
		{"bad user name", []string{"grant", "app", "b\x1b[0m"}, "invalid user"},
		{"bad github login", []string{"grant", "app", "@-x"}, "invalid user"},
		{"unknown user", []string{"grant", "app", "carol"}, "no such user: carol"},
		{"disabled user", []string{"grant", "app", "alice"}, "alice is disabled"},
		{"revoke non-member", []string{"revoke", "app", "bob"}, "bob is not a member of app"},
		{"revoke unknown user", []string{"revoke", "app", "carol"}, "no such user"},
		{"revoke extra argument", []string{"revoke", "app", "bob", "x"}, "usage: revoke"},
		{"members of env", []string{"members", "app:prod"}, "access is per project"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _, stderr := e.run(e.root, "", tt.args...)
			if res.Code != 1 || res.Changed || !strings.Contains(stderr, tt.stderr) {
				t.Fatalf("%+v, stderr %q", res, stderr)
			}
			if strings.Contains(stderr, "\x1b") {
				t.Errorf("escape sequence echoed: %q", stderr)
			}
		})
	}
	// A non-member is refused the same way whether or not the project exists.
	_, _, real := e.run(e.bob, "", "grant", "app", "bob")
	_, _, ghost := e.run(e.bob, "", "grant", "ghost", "bob")
	if real != ghost || !strings.Contains(real, "no such project") {
		t.Errorf("non-member refusals differ: %q vs %q", real, ghost)
	}
}

func TestGrantFromGitHub(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	e.project(t, "app", nil)
	k1, k2 := newPubKey(t), newPubKey(t)
	e.github.users["octocat"] = []gossh.PublicKey{k1, k2}

	res, out, _ := e.run(e.root, "", "grant", "app", "@OctoCat", "--role", "writer")
	if res.Code != 0 || !res.Changed {
		t.Fatalf("grant @octocat: %+v", res)
	}
	for _, want := range []string{"added user octocat from GitHub @octocat", auth.Fingerprint(k1), auth.Fingerprint(k2), "pinned", "granted octocat the writer role"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !strings.HasPrefix(res.Detail, "created user octocat from github with 2 keys; granted writer") {
		t.Errorf("detail = %q", res.Detail)
	}
	u, err := e.st.UserByGitHubLogin(ctx, "octocat")
	if err != nil || u.IsAdmin {
		t.Fatalf("user = %+v, %v", u, err)
	}

	// A second grant uses the pinned keys and does not fetch again, even
	// though the GitHub account now lists a different key.
	e.project(t, "web", nil)
	e.github.users["octocat"] = []gossh.PublicKey{newPubKey(t)}
	fetches := e.github.fetches
	if res, out, _ := e.run(e.root, "", "grant", "web", "@octocat"); res.Code != 0 || strings.Contains(out, "added user") {
		t.Fatalf("second grant: %+v, %q", res, out)
	}
	if e.github.fetches != fetches {
		t.Error("an existing GitHub user's keys were fetched again")
	}
	if fps := keysOf(t, e, u.ID); len(fps) != 2 {
		t.Errorf("keys changed without a refresh: %v", fps)
	}
}

func TestGrantFromGitHubRefusals(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", nil)
	e.github.users["nokeys"] = nil
	e.github.users["bob"] = []gossh.PublicKey{newPubKey(t)}
	e.github.users["weak"] = []gossh.PublicKey{weakRSAKey(t)}
	aliceKey := newPubKey(t)
	if _, err := e.st.AddKeys(context.Background(), e.alice.UserID, []store.NewKey{mustNewKey(t, aliceKey)}); err != nil {
		t.Fatal(err)
	}
	e.github.users["alice-gh"] = []gossh.PublicKey{aliceKey}

	tests := []struct{ login, stderr string }{
		{"ghost", "GitHub has no user @ghost"},
		{"nokeys", "has no SSH keys"},
		{"bob", "a user named bob already exists but was not added from GitHub"},
		{"weak", "no acceptable keys"},
		{"alice-gh", "already registered to another user"},
	}
	for _, tt := range tests {
		res, _, stderr := e.run(e.root, "", "grant", "app", "@"+tt.login)
		if res.Code != 1 || res.Changed || !strings.Contains(stderr, tt.stderr) {
			t.Errorf("@%s: %+v, stderr %q", tt.login, res, stderr)
		}
		if _, err := e.st.UserByGitHubLogin(context.Background(), tt.login); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("@%s: a user was created: %v", tt.login, err)
		}
	}

	// A network failure is logged, not shown.
	e.github.err = errors.New("dial tcp: secret-internal-host:443 refused")
	res, _, stderr := e.run(e.root, "", "grant", "app", "@someone")
	if res.Code != 1 || !strings.Contains(stderr, "could not fetch keys from GitHub") || strings.Contains(stderr, "secret-internal-host") {
		t.Errorf("network failure: %+v, %q", res, stderr)
	}
	if !strings.Contains(e.logs.String(), "secret-internal-host") {
		t.Error("network failure not logged")
	}
}

func TestMembersProjectsWhoami(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", map[auth.Identity]string{e.alice: store.RoleWriter, e.bob: store.RoleReader})
	e.project(t, "web", nil)
	e.push(t, "app:prod", sampleEnv)

	res, out, _ := e.run(e.bob, "", "members", "app")
	if res.Code != 0 || res.Target != "app" {
		t.Fatalf("members: %+v", res)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.Contains(lines[1], "owner") || !strings.Contains(lines[1], "root") ||
		!strings.Contains(lines[2], "writer") || !strings.Contains(lines[3], "reader") {
		t.Errorf("members output:\n%s", out)
	}
	if res, _, _ := e.run(e.bob, "", "members", "web"); res.Outcome != audit.Denied {
		t.Errorf("members of a project bob isn't in: %+v", res)
	}

	_, out, _ = e.run(e.bob, "", "projects")
	if !strings.Contains(out, "app") || !strings.Contains(out, "reader") || !strings.Contains(out, "environments: prod") || strings.Contains(out, "web") {
		t.Errorf("bob's projects:\n%s", out)
	}
	_, out, _ = e.run(e.root, "", "projects")
	if !strings.Contains(out, "web") || !strings.Contains(out, "no environments yet") {
		t.Errorf("root's projects:\n%s", out)
	}
	// An admin sees only projects they are a member of.
	e.project(t, "solo", nil)
	for _, args := range [][]string{{"grant", "solo", "alice", "--role", "owner"}, {"revoke", "solo", "root"}} {
		if res, _, stderr := e.run(e.root, "", args...); res.Code != 0 {
			t.Fatalf("%v: %s", args, stderr)
		}
	}
	if _, out, _ := e.run(e.root, "", "projects"); strings.Contains(out, "solo") {
		t.Errorf("admin sees a project they left:\n%s", out)
	}

	_, out, _ = e.run(e.alice, "", "whoami")
	if !strings.Contains(out, "projects:    app (writer), solo (owner)") {
		t.Errorf("whoami:\n%s", out)
	}
	_, out, _ = e.run(e.alice, "", "projects", "extra")
	if out != "" {
		t.Errorf("projects with an argument printed %q", out)
	}
	newUser := e.bob
	newUser.UserID = 9999
	if _, out, _ := e.run(newUser, "", "projects"); !strings.Contains(out, "not a member of any project") {
		t.Errorf("no projects: %q", out)
	}
}

func keysOf(t *testing.T, e *testEnv, userID int64) []string {
	t.Helper()
	keys, err := e.st.KeysForUser(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, k := range keys {
		out = append(out, k.Fingerprint)
	}
	return out
}

func mustNewKey(t *testing.T, pub gossh.PublicKey) store.NewKey {
	t.Helper()
	k, err := auth.NewKey(pub, store.SourceManual)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// weakRSAKey returns a 1024-bit RSA key, which the key policy refuses.
func weakRSAKey(t *testing.T) gossh.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024) // #nosec G403 -- deliberately weak, for a refusal test
	if err != nil {
		t.Fatal(err)
	}
	k, err := gossh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
