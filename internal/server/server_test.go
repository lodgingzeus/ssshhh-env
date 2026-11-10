package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"

	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/crypto"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type testServer struct {
	addr    string
	hostKey gossh.PublicKey
	alice   gossh.Signer // registered as "alice", not an admin
	root    gossh.Signer // registered as "root", a server admin
	users   map[string]store.User
	st      *store.Store
	dbPath  string
	logs    *syncBuffer
}

// audit returns the audit log, oldest first.
func (ts *testServer) audit(t *testing.T) []store.AuditRow {
	t.Helper()
	rows, err := ts.st.ListAudit(context.Background(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	return rows
}

// waitAudit waits for an audit row matching want. Rows for failed
// connections are written after the client has already seen the failure.
func (ts *testServer) waitAudit(t *testing.T, want func(store.AuditRow) bool) store.AuditRow {
	t.Helper()
	var found store.AuditRow
	eventually(t, func() error {
		for _, r := range ts.audit(t) {
			if want(r) {
				found = r
				return nil
			}
		}
		return errors.New("no matching audit row")
	})
	return found
}

func newSigner(t *testing.T) gossh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startServer(t *testing.T, modify func(*Config)) *testServer {
	t.Helper()
	return startServerWithKeys(t, nil, modify)
}

// startServerWithKeys registers a generated "alice" and "root" (the only
// admin) plus extra users by name.
func startServerWithKeys(t *testing.T, extra map[string]gossh.PublicKey, modify func(*Config)) *testServer {
	t.Helper()
	dir := t.TempDir()

	host, _, err := LoadOrCreateHostKey(filepath.Join(dir, "host_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	alice, root := newSigner(t), newSigner(t)
	keys := map[string]gossh.PublicKey{"alice": alice.PublicKey(), "root": root.PublicKey()}
	for name, k := range extra {
		keys[name] = k
	}
	dbPath := filepath.Join(dir, "test.db")
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	users := map[string]store.User{}
	for name, k := range keys {
		nk, err := auth.NewKey(k, store.SourceManual)
		if err != nil {
			t.Fatal(err)
		}
		u, err := st.CreateUser(context.Background(), store.NewUser{Name: name, IsAdmin: name == "root"}, []store.NewKey{nk})
		if err != nil {
			t.Fatal(err)
		}
		users[name] = u
	}

	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}

	logs := &syncBuffer{}
	cfg := DefaultConfig()
	cfg.Addr = ""
	cfg.HostSigner = host
	cfg.Store = st
	cfg.MasterKey = masterKey
	cfg.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg.ConnRate = rate.Inf
	if modify != nil {
		modify(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	return &testServer{addr: ln.Addr().String(), hostKey: host.PublicKey(), alice: alice, root: root, users: users, st: st, dbPath: dbPath, logs: logs}
}

func (ts *testServer) dial(auths ...gossh.AuthMethod) (*gossh.Client, error) {
	return gossh.Dial("tcp", ts.addr, &gossh.ClientConfig{
		User:            "anyone",
		Auth:            auths,
		HostKeyCallback: gossh.FixedHostKey(ts.hostKey),
		Timeout:         5 * time.Second,
	})
}

func (ts *testServer) dialAlice(t *testing.T) *gossh.Client {
	t.Helper()
	c, err := ts.dial(gossh.PublicKeys(ts.alice))
	if err != nil {
		t.Fatalf("dial as alice: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func (ts *testServer) dialRoot(t *testing.T) *gossh.Client {
	t.Helper()
	c, err := ts.dial(gossh.PublicKeys(ts.root))
	if err != nil {
		t.Fatalf("dial as root: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func newSession(t *testing.T, c *gossh.Client) *gossh.Session {
	t.Helper()
	s, err := c.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// runCmd runs cmd and returns stdout, stderr and the exit status.
func runCmd(t *testing.T, c *gossh.Client, cmd string) (string, string, int) {
	t.Helper()
	return runCmdInput(t, c, cmd, "")
}

// runCmdInput is runCmd with stdin.
func runCmdInput(t *testing.T, c *gossh.Client, cmd, stdin string) (string, string, int) {
	t.Helper()
	s := newSession(t, c)
	var out, errb bytes.Buffer
	s.Stdin, s.Stdout, s.Stderr = strings.NewReader(stdin), &out, &errb
	err := s.Run(cmd)
	var exitErr *gossh.ExitError
	switch {
	case err == nil:
		return out.String(), errb.String(), 0
	case errors.As(err, &exitErr):
		return out.String(), errb.String(), exitErr.ExitStatus()
	default:
		t.Fatalf("run %q: %v", cmd, err)
		return "", "", -1
	}
}

func TestWhoami(t *testing.T) {
	ts := startServer(t, nil)
	out, _, code := runCmd(t, ts.dialAlice(t), "whoami")
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "alice") || !strings.Contains(out, auth.Fingerprint(ts.alice.PublicKey())) {
		t.Fatalf("output = %q", out)
	}
	if !strings.Contains(ts.logs.String(), "cmd=whoami") {
		t.Fatalf("session not logged:\n%s", ts.logs.String())
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	ts := startServer(t, nil)
	if c, err := ts.dial(gossh.PublicKeys(newSigner(t))); err == nil {
		c.Close()
		t.Fatal("unregistered key accepted")
	}
}

func TestOnlyPublicKeyAuth(t *testing.T) {
	ts := startServer(t, nil)
	var offered []string
	_, err := ts.dial(
		gossh.Password("password"),
		gossh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
			offered = append(offered, "keyboard-interactive")
			return nil, nil
		}),
	)
	if err == nil {
		t.Fatal("non-publickey auth accepted")
	}
	if len(offered) > 0 {
		t.Fatal("server offered keyboard-interactive")
	}
	// gossh lists the methods the server still allows; password must not be one.
	if !strings.Contains(err.Error(), "no supported methods remain") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUnknownCommandExitsOne(t *testing.T) {
	ts := startServer(t, nil)
	c := ts.dialAlice(t)
	for _, cmd := range []string{"rm -rf /", "bash", `"unterminated`} {
		_, stderr, code := runCmd(t, c, cmd)
		if code != 1 {
			t.Errorf("%q: exit = %d, want 1", cmd, code)
		}
		if !strings.Contains(stderr, "unknown command") {
			t.Errorf("%q: stderr = %q", cmd, stderr)
		}
	}
}

func TestNoCommandPrintsHelp(t *testing.T) {
	ts := startServer(t, nil)
	s := newSession(t, ts.dialAlice(t))
	var out bytes.Buffer
	s.Stdout = &out
	if err := s.Shell(); err != nil {
		t.Fatal(err)
	}
	if err := s.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !strings.Contains(out.String(), "usage:") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestPTYRefused(t *testing.T) {
	ts := startServer(t, nil)
	s := newSession(t, ts.dialAlice(t))
	if err := s.RequestPty("xterm", 24, 80, gossh.TerminalModes{}); err == nil {
		t.Fatal("pty accepted")
	}
}

func TestSessionRequestsRefused(t *testing.T) {
	ts := startServer(t, nil)
	c := ts.dialAlice(t)
	for _, req := range []string{"auth-agent-req@openssh.com", "x11-req", "subsystem"} {
		s := newSession(t, c)
		ok, err := s.SendRequest(req, true, nil)
		if err != nil {
			t.Fatalf("%s: %v", req, err)
		}
		if ok {
			t.Errorf("%s accepted", req)
		}
	}
	s := newSession(t, c)
	if err := s.RequestSubsystem("sftp"); err == nil {
		t.Error("sftp subsystem accepted")
	}
}

func TestLocalForwardRefused(t *testing.T) {
	// A real listener, so a refusal can't be caused by nothing listening.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	ts := startServer(t, nil)
	if conn, err := ts.dialAlice(t).Dial("tcp", target.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("direct-tcpip (ssh -L) accepted")
	}
}

func TestRemoteForwardRefused(t *testing.T) {
	ts := startServer(t, nil)
	if ln, err := ts.dialAlice(t).Listen("tcp", "127.0.0.1:0"); err == nil {
		ln.Close()
		t.Fatal("tcpip-forward (ssh -R) accepted")
	}
}

func TestMaxSessionsPerConn(t *testing.T) {
	ts := startServer(t, func(c *Config) { c.MaxSessionsPerConn = 1 })
	c := ts.dialAlice(t)
	newSession(t, c)
	if s, err := c.NewSession(); err == nil {
		s.Close()
		t.Fatal("second concurrent session accepted")
	}
}

func TestConnRateLimit(t *testing.T) {
	ts := startServer(t, func(c *Config) {
		c.ConnRate = rate.Every(time.Hour)
		c.ConnBurst = 2
	})
	for i := range 2 {
		c, err := ts.dial(gossh.PublicKeys(ts.alice))
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		c.Close()
	}
	if c, err := ts.dial(gossh.PublicKeys(ts.alice)); err == nil {
		c.Close()
		t.Fatal("third connection within burst window accepted")
	}
	if !strings.Contains(ts.logs.String(), "rate limited") {
		t.Fatalf("refusal not logged:\n%s", ts.logs.String())
	}
}

// eventually retries f until it succeeds or the deadline passes. Slots are
// released asynchronously when the server notices a closed connection.
func eventually(t *testing.T, f func() error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := f()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestConnectionCapsReleaseSlots(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*Config)
	}{
		{"global", func(c *Config) { c.MaxConns = 2 }},
		{"per-ip", func(c *Config) { c.MaxConnsPerIP = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := startServer(t, tc.modify)
			var held []*gossh.Client
			for range 2 {
				held = append(held, ts.dialAlice(t))
			}
			if c, err := ts.dial(gossh.PublicKeys(ts.alice)); err == nil {
				c.Close()
				t.Fatal("connection over the cap accepted")
			}
			for _, c := range held {
				c.Close()
			}
			eventually(t, func() error {
				c, err := ts.dial(gossh.PublicKeys(ts.alice))
				if err == nil {
					c.Close()
				}
				return err
			})
		})
	}
}

func TestHandshakeTimeout(t *testing.T) {
	ts := startServer(t, func(c *Config) { c.HandshakeTimeout = 200 * time.Millisecond })
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Never send anything. The server must hang up on its own.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = io.Copy(io.Discard, conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("server kept a silent connection open past the handshake timeout")
	}
}

func TestIdleTimeout(t *testing.T) {
	ts := startServer(t, func(c *Config) { c.IdleTimeout = 200 * time.Millisecond })
	c := ts.dialAlice(t)
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idle connection not closed")
	}
}

func TestRawCommandNeverLogged(t *testing.T) {
	const canary = "CANARY_9f3a1c"
	ts := startServer(t, nil)
	c := ts.dialAlice(t)
	for _, cmd := range []string{canary, "whoami " + canary, "API_KEY=" + canary, `"` + canary} {
		_, _, _ = runCmd(t, c, cmd)
	}
	if strings.Contains(ts.logs.String(), canary) {
		t.Fatalf("raw command line leaked into logs:\n%s", ts.logs.String())
	}
	rows := ts.audit(t)
	if len(rows) != 4 {
		t.Fatalf("audit rows = %d, want 4", len(rows))
	}
	for _, r := range rows {
		if strings.Contains(r.Action+r.Target+r.Detail, canary) {
			t.Fatalf("raw command line leaked into the audit log: %+v", r)
		}
	}
}

// lyingSigner advertises one public key but signs with a different one, so
// the server accepts the key offer and then rejects the signature.
type lyingSigner struct {
	pub  gossh.PublicKey
	sign gossh.Signer
}

func (l lyingSigner) PublicKey() gossh.PublicKey { return l.pub }
func (l lyingSigner) Sign(r io.Reader, data []byte) (*gossh.Signature, error) {
	return l.sign.Sign(r, data)
}

// Offering someone else's (public) key and failing the signature must end
// the connection, even if a valid key would follow. x/crypto does this
// today; the test guards against that changing, because it closes off the
// "offer bob, then authenticate as alice" sequence for standard clients.
func TestBadSignatureEndsConnection(t *testing.T) {
	bob := newSigner(t)
	ts := startServerWithKeys(t, map[string]gossh.PublicKey{"bob": bob.PublicKey()}, nil)

	c, err := ts.dial(gossh.PublicKeys(
		lyingSigner{pub: bob.PublicKey(), sign: newSigner(t)}, // bob's key offered, bad signature
		ts.alice, // valid, but must never be reached
	))
	if err == nil {
		c.Close()
		t.Fatal("connection continued after a bad signature")
	}
}

func TestNewRequiresHostKeyStoreAndMasterKey(t *testing.T) {
	ts := startServer(t, nil)
	full := DefaultConfig()
	full.HostSigner, full.Store = newSigner(t), ts.st
	var err error
	if full.MasterKey, err = crypto.GenerateMasterKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(full); err != nil {
		t.Fatalf("complete config refused: %v", err)
	}
	for name, strip := range map[string]func(*Config){
		"host key":   func(c *Config) { c.HostSigner = nil },
		"store":      func(c *Config) { c.Store = nil },
		"master key": func(c *Config) { c.MasterKey = nil },
	} {
		cfg := full
		strip(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("New without a %s succeeded", name)
		}
	}
}

func TestSessionsAreAudited(t *testing.T) {
	ts := startServer(t, nil)
	c := ts.dialAlice(t)
	fp := auth.Fingerprint(ts.alice.PublicKey())
	for _, cmd := range []string{"whoami", "", "whoami extra", "bash -c id"} {
		if cmd == "" {
			s := newSession(t, c)
			if err := s.Shell(); err != nil {
				t.Fatal(err)
			}
			_ = s.Wait()
			continue
		}
		runCmd(t, c, cmd)
	}

	want := []struct{ action, result string }{
		{"whoami", "ok"}, {"help", "ok"}, {"whoami", "error"}, {"unknown", "error"},
	}
	rows := ts.audit(t)
	if len(rows) != len(want) {
		t.Fatalf("audit rows = %d, want %d: %+v", len(rows), len(want), rows)
	}
	for i, w := range want {
		r := rows[i]
		if r.Action != w.action || r.Result != w.result {
			t.Errorf("row %d = %s/%s, want %s/%s", i, r.Action, r.Result, w.action, w.result)
		}
		if r.UserID != ts.users["alice"].ID || r.KeyFingerprint != fp || r.RemoteAddr != "127.0.0.1" || r.Time == "" {
			t.Errorf("row %d = %+v", i, r)
		}
	}
}

func TestFailedAuthIsAudited(t *testing.T) {
	ts := startServer(t, nil)
	if c, err := ts.dial(gossh.PublicKeys(newSigner(t))); err == nil {
		c.Close()
		t.Fatal("unregistered key accepted")
	}
	r := ts.waitAudit(t, func(r store.AuditRow) bool { return r.Action == "auth" })
	if r.Result != "denied" || r.UserID != 0 || r.RemoteAddr != "127.0.0.1" {
		t.Fatalf("row = %+v", r)
	}
}

// A connection that never tries to authenticate is not an auth failure and
// must not be able to fill the audit log.
func TestSilentConnectionIsNotAudited(t *testing.T) {
	ts := startServer(t, func(c *Config) { c.HandshakeTimeout = 200 * time.Millisecond })
	conn, err := net.Dial("tcp", ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.Copy(io.Discard, conn)
	eventually(t, func() error {
		if !strings.Contains(ts.logs.String(), "connection failed") {
			return errors.New("failure not logged yet")
		}
		return nil
	})
	if rows := ts.audit(t); len(rows) != 0 {
		t.Fatalf("audit rows = %+v, want none", rows)
	}
}

func TestDisabledUserRefused(t *testing.T) {
	bob := newSigner(t)
	ts := startServerWithKeys(t, map[string]gossh.PublicKey{"bob": bob.PublicKey()}, nil)

	// Connect first, then get disabled: the open connection must stop
	// working at the next command.
	c, err := ts.dial(gossh.PublicKeys(bob))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if out, _, code := runCmd(t, c, "whoami"); code != 0 || !strings.Contains(out, "bob") {
		t.Fatalf("before disable: exit %d, out %q", code, out)
	}
	if err := ts.st.DisableUser(context.Background(), ts.users["bob"].ID); err != nil {
		t.Fatal(err)
	}
	out, _, code := runCmd(t, c, "whoami")
	if code == 0 || strings.Contains(out, "bob") {
		t.Fatalf("after disable: exit %d, out %q", code, out)
	}
	r := ts.waitAudit(t, func(r store.AuditRow) bool { return r.Action == "session" })
	if r.Result != "denied" || r.KeyFingerprint != auth.Fingerprint(bob.PublicKey()) {
		t.Fatalf("row = %+v", r)
	}

	// New connections are refused at authentication.
	if c, err := ts.dial(gossh.PublicKeys(bob)); err == nil {
		c.Close()
		t.Fatal("disabled user authenticated")
	}
	ts.waitAudit(t, func(r store.AuditRow) bool { return r.Action == "auth" && r.Result == "denied" })

	// Other users are unaffected.
	if _, _, code := runCmd(t, ts.dialAlice(t), "whoami"); code != 0 {
		t.Fatalf("alice: exit %d", code)
	}
}

func TestLastUsedAtUpdated(t *testing.T) {
	ts := startServer(t, nil)
	fp := auth.Fingerprint(ts.alice.PublicKey())
	k, _, err := ts.st.KeyByFingerprint(context.Background(), fp)
	if err != nil || k.LastUsedAt != "" {
		t.Fatalf("before: last used %q, err %v", k.LastUsedAt, err)
	}
	runCmd(t, ts.dialAlice(t), "whoami")
	k, _, err = ts.st.KeyByFingerprint(context.Background(), fp)
	if err != nil || k.LastUsedAt == "" {
		t.Fatalf("after: last used %q, err %v", k.LastUsedAt, err)
	}
}

// If the audit log can't be written, a command must not report success.
func TestAuditFailureFailsCommand(t *testing.T) {
	ts := startServer(t, nil)
	c := ts.dialAlice(t)
	if _, _, code := runCmd(t, c, "whoami"); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	_ = ts.st.Close()
	s := newSession(t, c)
	if err := s.Run("whoami"); err == nil {
		t.Fatal("command succeeded with the audit log unavailable")
	}
}
