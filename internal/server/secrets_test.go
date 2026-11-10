package server

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/envfile"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// initProject creates a project as root and adds members by user name.
func (ts *testServer) initProject(t *testing.T, name string, members map[string]string) {
	t.Helper()
	ctx := context.Background()
	if _, stderr, code := runCmd(t, ts.dialRoot(t), "init "+name); code != 0 {
		t.Fatalf("init %s: exit %d, %s", name, code, stderr)
	}
	p, err := ts.st.ProjectByName(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	for user, role := range members {
		if err := ts.st.AddMember(ctx, p.ID, ts.users[user].ID, role, ts.users["root"].ID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPushPullOverSSH(t *testing.T) {
	ts := startServer(t, nil)
	ts.initProject(t, "app", map[string]string{"alice": store.RoleReader})
	root, alice := ts.dialRoot(t), ts.dialAlice(t)
	const env = "# prod database\nDB_URL=postgres://u:p@host/db\nAPI_KEY=\"sk-123\"\n"

	out, stderr, code := runCmdInput(t, root, "push app -m first version", env)
	if code != 0 || !strings.Contains(out, "pushed app:default version 1 (2 variables)") {
		t.Fatalf("push: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	// A reader gets back exactly the bytes that were pushed.
	out, stderr, code = runCmd(t, alice, "pull app")
	if code != 0 || out != env || stderr != "" {
		t.Fatalf("pull: exit %d, stdout %q, stderr %q", code, out, stderr)
	}

	if _, _, code := runCmdInput(t, root, "push app", "DB_URL=changed\n"); code != 0 {
		t.Fatalf("second push: exit %d", code)
	}
	if out, _, _ := runCmd(t, alice, "pull app"); out != "DB_URL=changed\n" {
		t.Fatalf("pull after second push = %q", out)
	}
	if out, _, _ := runCmd(t, alice, "pull app --version 1"); out != env {
		t.Fatalf("pull --version 1 = %q", out)
	}

	// A reader can't push, and the attempt changes nothing.
	out, stderr, code = runCmdInput(t, alice, "push app", "DB_URL=hijacked\n")
	if code != 1 || out != "" || !strings.Contains(stderr, "permission denied") {
		t.Fatalf("reader push: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	if out, _, _ := runCmd(t, root, "pull app"); out != "DB_URL=changed\n" {
		t.Fatalf("pull after refused push = %q", out)
	}

	// Each step was audited with its target, and reads are audited too.
	type row struct{ user, action, target, result, detail string }
	want := []row{
		{"root", "init", "app", "ok", "project created"},
		{"root", "push", "app:default", "ok", "version 1"},
		{"alice", "pull", "app:default", "ok", "version 1"},
		{"root", "push", "app:default", "ok", "version 2"},
		{"alice", "pull", "app:default", "ok", "version 2"},
		{"alice", "pull", "app:default", "ok", "version 1"},
		{"alice", "push", "app:default", "denied", ""},
		{"root", "pull", "app:default", "ok", "version 2"},
	}
	rows := ts.audit(t)
	if len(rows) != len(want) {
		t.Fatalf("audit rows = %d, want %d: %+v", len(rows), len(want), rows)
	}
	for i, w := range want {
		r := rows[i]
		if got := (row{"", r.Action, r.Target, r.Result, r.Detail}); r.UserID != ts.users[w.user].ID ||
			got != (row{"", w.action, w.target, w.result, w.detail}) {
			t.Errorf("audit row %d = user %d %+v, want %+v", i, r.UserID, got, w)
		}
	}
}

func TestProjectAccessOverSSH(t *testing.T) {
	ts := startServer(t, nil)
	ts.initProject(t, "app", nil)
	if _, _, code := runCmdInput(t, ts.dialRoot(t), "push app", "A=1\n"); code != 0 {
		t.Fatalf("push: exit %d", code)
	}
	alice := ts.dialAlice(t)

	// Not a member: the same answer for a real project and a missing one.
	for _, cmd := range []string{"pull app", "pull ghost", "push app", "push ghost"} {
		out, stderr, code := runCmdInput(t, alice, cmd, "A=1\n")
		if code != 1 || out != "" || !strings.Contains(stderr, "no such project, or you don't have access to it") {
			t.Errorf("%q: exit %d, stdout %q, stderr %q", cmd, code, out, stderr)
		}
	}
	// Only a server admin may create projects.
	if _, stderr, code := runCmd(t, alice, "init mine"); code != 1 || !strings.Contains(stderr, "permission denied") {
		t.Errorf("init as non-admin: exit %d, stderr %q", code, stderr)
	}
	if _, err := ts.st.ProjectByName(context.Background(), "mine"); err == nil {
		t.Error("a non-admin created a project")
	}
}

func TestOversizedPushRejected(t *testing.T) {
	ts := startServer(t, nil)
	ts.initProject(t, "app", nil)
	root := ts.dialRoot(t)

	big := "A=" + strings.Repeat("x", envfile.MaxSize)
	out, stderr, code := runCmdInput(t, root, "push app", big)
	if code != 1 || out != "" || !strings.Contains(stderr, "larger than 256 KB") {
		t.Fatalf("oversized push: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	if _, stderr, code := runCmd(t, root, "pull app"); code != 1 || !strings.Contains(stderr, "nothing has been pushed") {
		t.Fatalf("oversized push was stored: exit %d, stderr %q", code, stderr)
	}
	// The largest allowed file still goes through.
	atLimit := big[:envfile.MaxSize]
	if _, stderr, code := runCmdInput(t, root, "push app", atLimit); code != 0 {
		t.Fatalf("push at the size limit: exit %d, stderr %q", code, stderr)
	}
	if out, _, _ := runCmd(t, root, "pull app"); out != atLimit {
		t.Fatalf("pull returned %d bytes, want %d", len(out), len(atLimit))
	}
}

// A read that cannot be written to the audit log must not happen: the
// secret stays on the server.
func TestPullSendsNothingIfAuditFails(t *testing.T) {
	ts := startServer(t, nil)
	ts.initProject(t, "app", nil)
	root := ts.dialRoot(t)
	if _, _, code := runCmdInput(t, root, "push app", "SECRET=hunter2\n"); code != 0 {
		t.Fatalf("push: exit %d", code)
	}
	if out, _, code := runCmd(t, root, "pull app"); code != 0 || out != "SECRET=hunter2\n" {
		t.Fatalf("pull before: exit %d, stdout %q", code, out)
	}

	// Break audit writes only; everything else in the database still works.
	db, err := sql.Open("sqlite", ts.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER audit_down BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'audit down'); END`); err != nil {
		t.Fatal(err)
	}

	out, stderr, code := runCmd(t, root, "pull app")
	if code == 0 || out != "" || strings.Contains(out+stderr, "hunter2") {
		t.Fatalf("pull with the audit log down: exit %d, stdout %q, stderr %q", code, out, stderr)
	}
	if !strings.Contains(stderr, "internal error") {
		t.Errorf("stderr = %q", stderr)
	}
}

// The canary is pushed as a secret value, then every command is run. It
// may appear in the output of a successful pull and nowhere else: not in
// any other output, the logs, the audit log, or the database files.
func TestCanaryNeverLeaks(t *testing.T) {
	const (
		canary  = "CANARY_9f3a1c7e42b8"
		varName = "LEAK_TEST_VARIABLE"
	)
	env := fmt.Sprintf("%s=%s\nOTHER=\"multi\n%s\nline\"\n", varName, canary, canary)

	ts := startServer(t, nil)
	ts.initProject(t, "app", map[string]string{"alice": store.RoleReader})
	root, alice := ts.dialRoot(t), ts.dialAlice(t)

	steps := []struct {
		client *gossh.Client
		cmd    string
		stdin  string
		pull   bool // a successful pull: the one place the canary belongs
	}{
		{root, "push app -m initial", env, false},
		{root, "push app:prod", env, false},
		{root, "pull app", "", true},
		{alice, "pull app:prod --version 1", "", true},
		{root, "help", "", false},
		{root, "whoami", "", false},
		{root, "init other", "", false},
		{root, "init app", "", false},
		// Refused pushes whose content holds the canary in every position.
		{root, "push app", canary + "\n", false},
		{root, "push app", "A=1\n" + canary + " " + canary + "\n", false},
		{root, "push app", "A=\"" + canary + "\n", false},
		{root, "push app", "A=\"x\" " + canary + "\n", false},
		{root, "push app", canary + "=1\n" + canary + "=2\n", false},
		{root, "push app", "9" + canary + "=1\n", false},
		{root, "push app", "A=" + canary + "\x00\n", false},
		{root, "push app", "A=" + canary + "\xff\n", false},
		{root, "push app", "A=" + canary + strings.Repeat("x", envfile.MaxSize), false},
		{alice, "push app", env, false},
		{alice, "push ghost", env, false},
		// Failing pulls.
		{root, "pull app --version 99", "", false},
		{root, "pull app:staging", "", false},
		{root, "pull other", "", false},
		{alice, "pull other", "", false},
		{root, "pull app --version x", "", false},
	}
	var elsewhere strings.Builder
	for _, s := range steps {
		out, stderr, code := runCmdInput(t, s.client, s.cmd, s.stdin)
		if s.pull {
			if code != 0 || out != env {
				t.Fatalf("%q: exit %d, stdout %q; the test needs this pull to work", s.cmd, code, out)
			}
			elsewhere.WriteString(stderr)
			continue
		}
		elsewhere.WriteString(out + stderr)
	}

	if strings.Contains(elsewhere.String(), canary) {
		t.Error("canary in command output other than a successful pull")
	}
	if strings.Contains(ts.logs.String(), canary) {
		t.Errorf("canary in the server log:\n%s", ts.logs.String())
	}
	rows := ts.audit(t)
	if len(rows) != len(steps)+1 { // +1 for initProject's init
		t.Errorf("audit rows = %d, want %d", len(rows), len(steps)+1)
	}
	for _, r := range rows {
		if strings.Contains(fmt.Sprintf("%+v", r), canary) {
			t.Errorf("canary in the audit log: %+v", r)
		}
	}

	// The database on disk, including its write-ahead log.
	sawVarName := false
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(ts.dbPath + suffix)
		if err != nil {
			if suffix == "" {
				t.Fatal(err)
			}
			continue
		}
		if bytes.Contains(data, []byte(canary)) {
			t.Errorf("canary stored in plaintext in the database file %q", "test.db"+suffix)
		}
		sawVarName = sawVarName || bytes.Contains(data, []byte(varName))
	}
	// Variable names are stored in the clear, so finding one proves the
	// scan above was looking at the data that was really written.
	if !sawVarName {
		t.Error("variable name not found in the database files; the plaintext scan is not checking the right data")
	}
}
