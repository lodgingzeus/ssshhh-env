package server

import (
	"context"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/github"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

const teamEnv = "DB_URL=postgres://u:p@host/db\nAPI_KEY=sk-123\n"

// fakeGitHub serves fixed keys per login.
type fakeGitHub map[string][]gossh.PublicKey

func (f fakeGitHub) Keys(_ context.Context, login string) ([]gossh.PublicKey, error) {
	keys, ok := f[login]
	if !ok {
		return nil, github.ErrUserNotFound
	}
	return keys, nil
}

func dialAs(t *testing.T, ts *testServer, signer gossh.Signer) *gossh.Client {
	t.Helper()
	c, err := ts.dial(gossh.PublicKeys(signer))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// A second user goes through granted -> pull works -> revoked -> pull
// denied, over real SSH, including on a connection opened before the
// revoke.
func TestGrantPullRevokeOverSSH(t *testing.T) {
	bob := newSigner(t)
	ts := startServerWithKeys(t, map[string]gossh.PublicKey{"bob": bob.PublicKey()}, nil)
	ts.initProject(t, "app", nil)
	root, bobConn := ts.dialRoot(t), dialAs(t, ts, bob)
	if _, stderr, code := runCmdInput(t, root, "push app:prod", teamEnv); code != 0 {
		t.Fatalf("push: %s", stderr)
	}

	if _, stderr, code := runCmd(t, bobConn, "pull app:prod"); code != 1 || !strings.Contains(stderr, "no such project") {
		t.Fatalf("pull before grant: exit %d, %q", code, stderr)
	}
	if out, stderr, code := runCmd(t, root, "grant app bob"); code != 0 || !strings.Contains(out, "granted bob the reader role") {
		t.Fatalf("grant: exit %d, %q %q", code, out, stderr)
	}
	if out, _, code := runCmd(t, bobConn, "pull app:prod"); code != 0 || out != teamEnv {
		t.Fatalf("pull after grant: exit %d, %q", code, out)
	}
	if _, stderr, code := runCmdInput(t, bobConn, "push app:prod", teamEnv); code != 1 || !strings.Contains(stderr, "your role in app is reader") {
		t.Fatalf("push as reader: exit %d, %q", code, stderr)
	}
	if out, _, code := runCmd(t, bobConn, "members app"); code != 0 || !strings.Contains(out, "bob") {
		t.Fatalf("members as reader: exit %d, %q", code, out)
	}

	out, _, code := runCmd(t, root, "revoke app bob")
	if code != 0 || !strings.Contains(out, "bob could read: prod") || !strings.Contains(out, "Rotate those secrets") {
		t.Fatalf("revoke: exit %d, %q", code, out)
	}
	// Same connection as before the revoke: every session checks afresh.
	out, stderr, code := runCmd(t, bobConn, "pull app:prod")
	if code != 1 || out != "" || !strings.Contains(stderr, "no such project") {
		t.Fatalf("pull after revoke: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	for _, cmd := range []string{"history app:prod", "diff app:prod 1 1", "members app"} {
		if out, _, code := runCmd(t, bobConn, cmd); code != 1 || out != "" {
			t.Errorf("%q after revoke: exit %d, %q", cmd, code, out)
		}
	}

	var actions []string
	for _, r := range ts.audit(t) {
		if r.UserID == ts.users["bob"].ID || r.Action == "grant" || r.Action == "revoke" {
			actions = append(actions, r.Action+"/"+r.Result+"/"+r.Target)
		}
	}
	want := []string{
		"pull/denied/app:prod", "grant/ok/app", "pull/ok/app:prod", "push/denied/app:prod", "members/ok/app",
		"revoke/ok/app", "pull/denied/app:prod", "history/denied/app:prod", "diff/denied/app:prod", "members/denied/app",
	}
	if strings.Join(actions, " ") != strings.Join(want, " ") {
		t.Errorf("audit:\n got %v\nwant %v", actions, want)
	}
}

// An owner grants a GitHub user who has no account yet: their keys are
// fetched, pinned, and work for a new connection straight away.
func TestGrantGitHubUserOverSSH(t *testing.T) {
	octo := newSigner(t)
	ts := startServer(t, func(c *Config) {
		c.GitHub = fakeGitHub{"octocat": {octo.PublicKey()}}
	})
	ts.initProject(t, "app", nil)
	root := ts.dialRoot(t)
	if _, stderr, code := runCmdInput(t, root, "push app", teamEnv); code != 0 {
		t.Fatalf("push: %s", stderr)
	}

	// Unknown before the grant.
	if _, err := ts.dial(gossh.PublicKeys(octo)); err == nil {
		t.Fatal("unregistered key accepted")
	}
	out, stderr, code := runCmd(t, root, "grant app @octocat --role writer")
	if code != 0 || !strings.Contains(out, gossh.FingerprintSHA256(octo.PublicKey())) || !strings.Contains(out, "pinned") {
		t.Fatalf("grant: exit %d, %q %q", code, out, stderr)
	}
	c := dialAs(t, ts, octo)
	if out, _, code := runCmd(t, c, "pull app"); code != 0 || out != teamEnv {
		t.Fatalf("pull as new user: exit %d, %q", code, out)
	}
	if out, _, _ := runCmd(t, c, "whoami"); !strings.Contains(out, "user:        octocat") || !strings.Contains(out, "app (writer)") {
		t.Errorf("whoami: %q", out)
	}
	u, err := ts.st.UserByGitHubLogin(context.Background(), "octocat")
	if err != nil || u.IsAdmin {
		t.Fatalf("user = %+v, %v", u, err)
	}
	if role, err := ts.st.MemberRole(context.Background(), mustProjectID(t, ts, "app"), u.ID); err != nil || role != store.RoleWriter {
		t.Fatalf("role = %q, %v", role, err)
	}
}

// Disabling a user over SSH cuts off a connection they already have open.
func TestUserDisableOverSSH(t *testing.T) {
	ts := startServer(t, nil)
	alice := ts.dialAlice(t)
	if _, _, code := runCmd(t, alice, "whoami"); code != 0 {
		t.Fatal("whoami before disable failed")
	}
	if out, stderr, code := runCmd(t, ts.dialRoot(t), "user disable alice"); code != 0 {
		t.Fatalf("disable: exit %d, %q %q", code, out, stderr)
	}
	if out, _, code := runCmd(t, alice, "whoami"); code != 1 || out != "" {
		t.Fatalf("whoami after disable: exit %d, %q", code, out)
	}
}

func mustProjectID(t *testing.T, ts *testServer, name string) int64 {
	t.Helper()
	p, err := ts.st.ProjectByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return p.ID
}
