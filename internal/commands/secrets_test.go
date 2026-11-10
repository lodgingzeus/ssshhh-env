package commands

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/crypto"
	"github.com/lodgingzeus/ssshhh-env/internal/envfile"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

const sampleEnv = "# database\nDB_URL=postgres://u:p@host/db\nAPI_KEY=\"sk-123\"\n"

func TestInit(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	res, out, _ := e.run(e.root, "", "init", "app")
	if res.Code != 0 || res.Outcome != audit.OK || res.Target != "app" || !strings.Contains(out, "created project app") {
		t.Fatalf("init: %+v, stdout %q", res, out)
	}
	p, err := e.st.ProjectByName(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	if role, err := e.st.MemberRole(ctx, p.ID, e.root.UserID); err != nil || role != store.RoleOwner {
		t.Fatalf("creator role = %q, err %v", role, err)
	}
	// The stored data key is wrapped under the server's master key and
	// bound to this project.
	if p.MasterKeyID != e.deps.MasterKey.ID() {
		t.Fatalf("master key id = %q", p.MasterKeyID)
	}
	if _, err := projectDEK(e.deps.MasterKey, p); err != nil {
		t.Fatalf("stored data key does not unwrap: %v", err)
	}

	res, _, stderr := e.run(e.root, "", "init", "app")
	if res.Code != 1 || res.Outcome != audit.Error || !strings.Contains(stderr, "already exists") {
		t.Fatalf("duplicate: %+v, stderr %q", res, stderr)
	}
}

func TestInitRefusals(t *testing.T) {
	e := newTestEnv(t)
	tests := []struct {
		name    string
		id      auth.Identity
		args    []string
		outcome audit.Result
		stderr  string
	}{
		{"not an admin", e.alice, []string{"init", "app"}, audit.Denied, "permission denied"},
		{"no name", e.root, []string{"init"}, audit.Error, "usage: init <project>"},
		{"extra argument", e.root, []string{"init", "app", "extra"}, audit.Error, "usage: init <project>"},
		{"with env", e.root, []string{"init", "app:prod"}, audit.Error, "invalid name"},
		{"uppercase", e.root, []string{"init", "App"}, audit.Error, "invalid name"},
		{"escape sequence", e.root, []string{"init", "a\x1b[31m"}, audit.Error, "invalid name"},
		{"path", e.root, []string{"init", "../x"}, audit.Error, "invalid name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _, stderr := e.run(tt.id, "", tt.args...)
			if res.Code != 1 || res.Outcome != tt.outcome || !strings.Contains(stderr, tt.stderr) {
				t.Fatalf("%+v, stderr %q", res, stderr)
			}
			if res.Target != "" {
				t.Errorf("unvalidated input recorded as audit target %q", res.Target)
			}
			if len(tt.args) > 1 && strings.Contains(stderr, tt.args[1]) && !ValidName(tt.args[1]) {
				t.Errorf("invalid name echoed back: %q", stderr)
			}
		})
	}
	if _, err := e.st.ProjectByName(context.Background(), "app"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused init created a project: err = %v", err)
	}
}

func TestPushPullRoundTrip(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", nil)

	// Awkward but valid content must come back byte for byte.
	contents := []string{
		sampleEnv,
		"A=1",                           // no trailing newline
		"A=1\r\nB=2\r\n",                // CRLF
		"KEY=\"line1\nline2\"\n\n\n",    // multi-line value, trailing blanks
		"  A = spaced  \n\t# c\n",       // odd spacing
		"U=héllo ✓\nE=\n",               // unicode, empty value
		"A=" + strings.Repeat("x", 100), // longer
	}
	for i, content := range contents {
		res, out, stderr := e.run(e.root, content, "push", "app")
		if res.Code != 0 || res.Outcome != audit.OK || res.Target != "app:default" {
			t.Fatalf("push %d: %+v, stderr %q", i, res, stderr)
		}
		wantVersion := i + 1
		if !strings.Contains(out, "pushed app:default version ") || res.Detail != "version "+strconv.Itoa(wantVersion) {
			t.Fatalf("push %d: stdout %q, detail %q", i, out, res.Detail)
		}
		if res.Secret != nil {
			t.Fatal("push returned a secret")
		}

		res, out, _ = e.run(e.root, "", "pull", "app")
		if res.Code != 0 || res.Outcome != audit.OK || string(res.Secret) != content {
			t.Fatalf("pull %d: %+v", i, res)
		}
		if out != "" {
			t.Fatalf("pull wrote to stdout itself: %q", out)
		}
	}
	// Every earlier version is still there, unchanged.
	for i, content := range contents {
		res, _, _ := e.run(e.root, "", "pull", "app", "--version", strconv.Itoa(i+1))
		if res.Code != 0 || string(res.Secret) != content || res.Detail != "version "+strconv.Itoa(i+1) {
			t.Fatalf("pull --version %d: %+v", i+1, res)
		}
	}
}

func TestEnvironmentsAreSeparate(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", nil)
	e.project(t, "other", nil)
	e.push(t, "app", "WHERE=app-default\n")
	e.push(t, "app:prod", "WHERE=app-prod\n")
	e.push(t, "other:prod", "WHERE=other-prod\n")

	for target, want := range map[string]string{
		"app":         "WHERE=app-default\n",
		"app:default": "WHERE=app-default\n",
		"app:prod":    "WHERE=app-prod\n",
		"other:prod":  "WHERE=other-prod\n",
	} {
		if res, _, _ := e.run(e.root, "", "pull", target); string(res.Secret) != want {
			t.Errorf("pull %s = %q, want %q", target, res.Secret, want)
		}
	}
	res, _, stderr := e.run(e.root, "", "pull", "other")
	if res.Code != 1 || res.Secret != nil || !strings.Contains(stderr, "nothing has been pushed") {
		t.Fatalf("pull of an empty environment: %+v, stderr %q", res, stderr)
	}
}

func TestPushStoresMetadataNotValues(t *testing.T) {
	e := newTestEnv(t)
	p := e.project(t, "app", nil)
	if res, _, stderr := e.runLine(e.root, sampleEnv, "push app -m add\x1b[31m api key\n"); res.Code != 0 {
		t.Fatalf("push: %s", stderr)
	}

	v, err := e.st.LatestVersion(context.Background(), p.ID, DefaultEnv)
	if err != nil {
		t.Fatal(err)
	}
	if v.Message != "add[31m api key" {
		t.Errorf("message = %q, want control characters stripped", v.Message)
	}
	if strings.Join(v.KeyNames, ",") != "API_KEY,DB_URL" || v.SizeBytes != int64(len(sampleEnv)) || v.AuthorID != e.root.UserID {
		t.Errorf("version = %+v", v)
	}
	for _, secret := range []string{"postgres://", "sk-123"} {
		if strings.Contains(string(v.Ciphertext), secret) || strings.Contains(strings.Join(v.KeyNames, ""), secret) {
			t.Errorf("stored version contains plaintext %q", secret)
		}
	}
}

func TestPushRefusals(t *testing.T) {
	e := newTestEnv(t)
	p := e.project(t, "app", nil)
	const canary = "CANARY_9f3a1c"
	tests := []struct {
		name   string
		stdin  string
		args   []string
		detail string
		stderr string
	}{
		{"empty", "", []string{"push", "app"}, "invalid .env file", "no variables"},
		{"not an env file", "hello " + canary + "\n", []string{"push", "app"}, "invalid .env file", "line 1: expected KEY=VALUE"},
		{"duplicate", "A=" + canary + "\nA=2\n", []string{"push", "app"}, "invalid .env file", "line 2"},
		{"nul byte", "A=" + canary + "\x00\n", []string{"push", "app"}, "invalid .env file", "NUL"},
		{"invalid utf-8", "A=" + canary + "\xff\n", []string{"push", "app"}, "invalid .env file", "UTF-8"},
		{"too large", "A=" + canary + strings.Repeat("x", envfile.MaxSize), []string{"push", "app"}, "invalid .env file", "larger than 256 KB"},
		{"bad flag", "A=1\n", []string{"push", "app", "--force"}, "bad arguments", "usage: push"},
		{"-m without message", "A=1\n", []string{"push", "app", "-m"}, "bad arguments", "usage: push"},
		{"message too long", "A=1\n", []string{"push", "app", "-m", strings.Repeat("m", maxMessageLen+1)}, "message too long", "longer than 200"},
		{"bad target", "A=1\n", []string{"push", "App:" + canary}, "invalid target", "invalid name"},
		{"no target", "A=1\n", []string{"push"}, "bad arguments", "usage: push"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, out, stderr := e.run(e.root, tt.stdin, tt.args...)
			if res.Code != 1 || res.Outcome != audit.Error || res.Detail != tt.detail || !strings.Contains(stderr, tt.stderr) {
				t.Fatalf("%+v, stderr %q", res, stderr)
			}
			if strings.Contains(out+stderr+res.Target+res.Detail+e.logs.String(), canary) {
				t.Fatal("refused content was echoed, audited or logged")
			}
		})
	}
	if _, err := e.st.LatestVersion(context.Background(), p.ID, DefaultEnv); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a refused push stored a version: err = %v", err)
	}
}

// A file of exactly the maximum size is accepted, and push never reads
// more than one byte past the limit.
func TestPushSizeLimit(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", nil)
	atLimit := "A=" + strings.Repeat("x", envfile.MaxSize-2)
	if res, _, stderr := e.run(e.root, atLimit, "push", "app"); res.Code != 0 {
		t.Fatalf("file at the limit refused: %s", stderr)
	}

	endless := &countingReader{}
	res, _, _ := e.runWith(e.deps, e.root, endless, "push", "app")
	if res.Code != 1 {
		t.Fatal("endless input accepted")
	}
	if endless.n > envfile.MaxSize+1 {
		t.Fatalf("read %d bytes of an oversized file, limit is %d", endless.n, envfile.MaxSize+1)
	}
}

// countingReader produces "x" forever and counts what was consumed.
type countingReader struct{ n int }

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.n += len(p)
	return len(p), nil
}

func TestPushReadErrorStoresNothing(t *testing.T) {
	e := newTestEnv(t)
	p := e.project(t, "app", nil)
	res, _, stderr := e.runWith(e.deps, e.root, io.MultiReader(strings.NewReader("A=1\n"), errReader{}), "push", "app")
	if res.Code != 1 || !strings.Contains(stderr, "could not read") {
		t.Fatalf("%+v, stderr %q", res, stderr)
	}
	if _, err := e.st.LatestVersion(context.Background(), p.ID, DefaultEnv); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("a half-read file was stored")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestPullRefusals(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", nil)
	e.push(t, "app", sampleEnv)
	tests := []struct {
		name   string
		args   []string
		detail string
		stderr string
	}{
		{"missing version", []string{"pull", "app", "--version", "2"}, "no such version", "no such version"},
		{"missing env", []string{"pull", "app:prod"}, "no such environment", "nothing has been pushed"},
		{"missing env and version", []string{"pull", "app:prod", "--version", "1"}, "no such version", "no such version"},
		{"version zero", []string{"pull", "app", "--version", "0"}, "bad arguments", "usage: pull"},
		{"negative version", []string{"pull", "app", "--version", "-1"}, "bad arguments", "usage: pull"},
		{"extra argument", []string{"pull", "app", "extra"}, "bad arguments", "usage: pull"},
		{"no target", []string{"pull"}, "bad arguments", "usage: pull"},
		{"bad target", []string{"pull", "app:"}, "invalid target", "invalid name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, out, stderr := e.run(e.root, "", tt.args...)
			if res.Code != 1 || res.Outcome != audit.Error || res.Detail != tt.detail || !strings.Contains(stderr, tt.stderr) {
				t.Fatalf("%+v, stderr %q", res, stderr)
			}
			if res.Secret != nil || out != "" {
				t.Fatal("a refused pull returned content")
			}
		})
	}
}

// Every role against push and pull, plus the people with no role at all.
func TestProjectRoleEnforcement(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	carol := func(name string) auth.Identity {
		u, err := e.st.CreateUser(ctx, store.NewUser{Name: name}, []store.NewKey{{
			Fingerprint: "SHA256:" + name, PublicKey: "ssh-ed25519 AAAA" + name, KeyType: "ssh-ed25519", Source: store.SourceManual}})
		if err != nil {
			t.Fatal(err)
		}
		return auth.Identity{UserID: u.ID, Name: name}
	}
	reader, writer, owner, outsider := carol("reader"), carol("writer"), carol("owner"), carol("outsider")
	// An admin who is not a member: being a server admin grants nothing.
	admin := carol("admin2")
	admin.IsAdmin = true
	e.project(t, "app", map[auth.Identity]string{reader: store.RoleReader, writer: store.RoleWriter, owner: store.RoleOwner})
	e.push(t, "app", sampleEnv)

	tests := []struct {
		who      auth.Identity
		canPull  bool
		canPush  bool
		denyText string
	}{
		{outsider, false, false, "no such project, or you don't have access"},
		{admin, false, false, "no such project, or you don't have access"},
		{reader, true, false, "your role in app is reader"},
		{writer, true, true, ""},
		{owner, true, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.who.Name, func(t *testing.T) {
			res, _, stderr := e.run(tt.who, "", "pull", "app")
			if got := res.Code == 0 && res.Secret != nil; got != tt.canPull {
				t.Errorf("pull allowed = %v, want %v (%+v)", got, tt.canPull, res)
			}
			if !tt.canPull && (res.Outcome != audit.Denied || res.Secret != nil || res.Target != "app:default" || !strings.Contains(stderr, tt.denyText)) {
				t.Errorf("denied pull: %+v, stderr %q", res, stderr)
			}

			// stdin must not even be read for someone who may not push.
			stdin := &countingReader{}
			var in io.Reader = stdin
			if tt.canPush {
				in = strings.NewReader("BY=" + tt.who.Name + "\n")
			}
			res, _, stderr = e.runWith(e.deps, tt.who, in, "push", "app")
			if got := res.Code == 0; got != tt.canPush {
				t.Errorf("push allowed = %v, want %v (%+v)", got, tt.canPush, res)
			}
			if !tt.canPush && (res.Outcome != audit.Denied || stdin.n != 0 || !strings.Contains(stderr, tt.denyText)) {
				t.Errorf("denied push: %+v, read %d bytes, stderr %q", res, stdin.n, stderr)
			}
		})
	}
}

// Someone with no access must not be able to tell a project that exists
// from one that doesn't.
func TestProjectExistenceIsNotLeaked(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "real", nil)
	e.push(t, "real", sampleEnv)
	for _, cmd := range []string{"pull", "push"} {
		realRes, realOut, realErr := e.run(e.alice, "A=1\n", cmd, "real")
		ghostRes, ghostOut, ghostErr := e.run(e.alice, "A=1\n", cmd, "ghost")
		if realRes.Code != ghostRes.Code || realRes.Outcome != ghostRes.Outcome || realRes.Detail != ghostRes.Detail ||
			realOut != ghostOut || realErr != ghostErr || realRes.Secret != nil || ghostRes.Secret != nil {
			t.Errorf("%s: existing project answered (%+v, %q) but missing one (%+v, %q)", cmd, realRes, realErr, ghostRes, ghostErr)
		}
		if realRes.Outcome != audit.Denied {
			t.Errorf("%s: outcome = %q, want denied", cmd, realRes.Outcome)
		}
	}
}

// swapStore serves another row's ciphertext, as an attacker with write
// access to the database file could arrange.
type swapStore struct {
	Store
	swap func(store.Version) store.Version
}

func (s swapStore) LatestVersion(ctx context.Context, projectID int64, env string) (store.Version, error) {
	v, err := s.Store.LatestVersion(ctx, projectID, env)
	return s.swap(v), err
}

func TestPullRefusesSwappedOrModifiedCiphertext(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	app := e.project(t, "app", nil)
	e.project(t, "other", nil)
	e.push(t, "app", "V=one\n")
	e.push(t, "app", "V=two\n")
	e.push(t, "app:prod", "V=prod\n")
	e.push(t, "other", "V=other\n")

	old, err := e.st.VersionByNumber(ctx, app.ID, DefaultEnv, 1)
	if err != nil {
		t.Fatal(err)
	}
	prod, err := e.st.LatestVersion(ctx, app.ID, "prod")
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.st.LatestVersion(ctx, app.ID+1, DefaultEnv)
	if err != nil {
		t.Fatal(err)
	}
	payload := func(from store.Version) func(store.Version) store.Version {
		return func(v store.Version) store.Version {
			v.Nonce, v.Ciphertext = from.Nonce, from.Ciphertext
			return v
		}
	}
	swaps := map[string]func(store.Version) store.Version{
		"older version, same env (rollback)": payload(old),
		"another env, same project":          payload(prod),
		"another project":                    payload(other),
		"flipped bit": func(v store.Version) store.Version {
			v.Ciphertext = append([]byte{}, v.Ciphertext...)
			v.Ciphertext[len(v.Ciphertext)/2] ^= 0x01
			return v
		},
		"truncated": func(v store.Version) store.Version {
			v.Ciphertext = v.Ciphertext[:len(v.Ciphertext)-1]
			return v
		},
	}
	for name, swap := range swaps {
		t.Run(name, func(t *testing.T) {
			d := e.deps
			d.Store = swapStore{Store: e.st, swap: swap}
			res, out, stderr := e.runWith(d, e.root, strings.NewReader(""), "pull", "app")
			if res.Code != 1 || res.Outcome != audit.Error || res.Secret != nil || out != "" {
				t.Fatalf("tampered data was served: %+v", res)
			}
			if !strings.Contains(stderr, "internal error") || strings.Contains(stderr, "decrypt") {
				t.Errorf("stderr = %q, want only a generic error", stderr)
			}
			if !strings.Contains(e.logs.String(), "decrypt version") {
				t.Errorf("failure not logged: %q", e.logs.String())
			}
		})
	}
	// The untampered path still works.
	if res, _, _ := e.run(e.root, "", "pull", "app"); string(res.Secret) != "V=two\n" {
		t.Fatalf("clean pull = %+v", res)
	}
}

func TestWrongMasterKey(t *testing.T) {
	e := newTestEnv(t)
	e.project(t, "app", nil)
	e.push(t, "app", sampleEnv)

	other, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	d := e.deps
	d.MasterKey = other
	for _, args := range [][]string{{"pull", "app"}, {"push", "app"}} {
		res, _, stderr := e.runWith(d, e.root, strings.NewReader("A=1\n"), args...)
		if res.Code != 1 || res.Outcome != audit.Error || res.Secret != nil || !strings.Contains(stderr, "internal error") {
			t.Fatalf("%v with the wrong master key: %+v, stderr %q", args, res, stderr)
		}
	}
	if !strings.Contains(e.logs.String(), "wrapped with master key") {
		t.Errorf("log does not explain the failure: %q", e.logs.String())
	}
	// Nothing was written under the wrong key.
	if res, _, _ := e.run(e.root, "", "pull", "app"); string(res.Secret) != sampleEnv {
		t.Fatalf("after a wrong-key push, pull = %+v", res)
	}
}

// Output is handed back in Result.Stdout for the caller to send after the
// audit row is written, and Changed marks the commands that saved
// something.
func TestOutputIsReturnedNotSent(t *testing.T) {
	e := newTestEnv(t)
	tests := []struct {
		name    string
		stdin   string
		line    string
		code    int
		stdout  string
		changed bool
	}{
		{"init", "", "init app", 0, "created project app", true},
		{"init again", "", "init app", 1, "", false},
		{"push", "A=1\n", "push app -m it's fixed", 0, "pushed app:default version 1", true},
		{"invalid push", "nope\n", "push app", 1, "", false},
		{"pull", "", "pull app", 0, "", false},
		{"whoami", "", "whoami", 0, "user:        root", false},
		{"unknown", "", "nope", 1, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, out, _ := e.runLine(e.root, tt.stdin, tt.line)
			if res.Code != tt.code || res.Changed != tt.changed || !strings.Contains(out, tt.stdout) || (tt.stdout == "" && out != "") {
				t.Fatalf("%q: code %d, changed %v, stdout %q", tt.line, res.Code, res.Changed, out)
			}
		})
	}
	p, err := e.st.ProjectByName(context.Background(), "app")
	if err != nil {
		t.Fatal(err)
	}
	v, err := e.st.LatestVersion(context.Background(), p.ID, DefaultEnv)
	if err != nil {
		t.Fatal(err)
	}
	if v.Message != "it's fixed" {
		t.Errorf("message = %q, want it stored as typed", v.Message)
	}
}
