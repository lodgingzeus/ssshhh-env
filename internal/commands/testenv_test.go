package commands

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/crypto"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// testEnv is a real store and master key with three users: root (a server
// admin), and alice and bob (not admins).
type testEnv struct {
	deps Deps
	st   *store.Store
	logs *bytes.Buffer
	root auth.Identity
	alice,
	bob auth.Identity
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	mk, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	e := &testEnv{st: st, logs: &bytes.Buffer{}}
	e.deps = Deps{Store: st, MasterKey: mk, Log: slog.New(slog.NewTextHandler(e.logs, nil))}

	user := func(name string, admin bool) auth.Identity {
		key := store.NewKey{Fingerprint: "SHA256:" + name, PublicKey: "ssh-ed25519 AAAA" + name, KeyType: "ssh-ed25519", Source: store.SourceManual}
		u, err := st.CreateUser(ctx, store.NewUser{Name: name, IsAdmin: admin}, []store.NewKey{key})
		if err != nil {
			t.Fatal(err)
		}
		return auth.Identity{UserID: u.ID, Name: name, IsAdmin: admin, Fingerprint: key.Fingerprint, KeyType: key.KeyType}
	}
	e.root, e.alice, e.bob = user("root", true), user("alice", false), user("bob", false)
	return e
}

// run executes one command and returns its result, stdout and stderr.
func (e *testEnv) run(id auth.Identity, stdin string, args ...string) (Result, string, string) {
	return e.runWith(e.deps, id, strings.NewReader(stdin), args...)
}

func (e *testEnv) runWith(d Deps, id auth.Identity, stdin io.Reader, args ...string) (Result, string, string) {
	var out, errb bytes.Buffer
	res := Run(context.Background(), d, Request{Args: args, ID: id, Stdin: stdin, Stdout: &out, Stderr: &errb})
	return res, out.String(), errb.String()
}

// project creates a project owned by root and gives each listed user the
// role named for them.
func (e *testEnv) project(t *testing.T, name string, members map[auth.Identity]string) store.Project {
	t.Helper()
	ctx := context.Background()
	if res, _, stderr := e.run(e.root, "", "init", name); res.Code != 0 {
		t.Fatalf("init %s: %s", name, stderr)
	}
	p, err := e.st.ProjectByName(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	for id, role := range members {
		if err := e.st.AddMember(ctx, p.ID, id.UserID, role, e.root.UserID); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// push stores content as root and fails the test if it is refused.
func (e *testEnv) push(t *testing.T, target, content string, extra ...string) {
	t.Helper()
	if res, _, stderr := e.run(e.root, content, append([]string{"push", target}, extra...)...); res.Code != 0 {
		t.Fatalf("push %s: %s", target, stderr)
	}
}
