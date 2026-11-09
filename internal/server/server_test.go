package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"

	"github.com/lodgingzeus/ssshhh-env/internal/auth"
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
	alice   gossh.Signer // allowlisted as "alice"
	logs    *syncBuffer
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

// startServerWithKeys allowlists a generated "alice" plus extra keys by name.
func startServerWithKeys(t *testing.T, extra map[string]gossh.PublicKey, modify func(*Config)) *testServer {
	t.Helper()
	dir := t.TempDir()

	host, _, err := LoadOrCreateHostKey(filepath.Join(dir, "host_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	alice := newSigner(t)
	keys := map[string]gossh.PublicKey{"alice": alice.PublicKey()}
	for name, k := range extra {
		keys[name] = k
	}
	var lines strings.Builder
	for name, k := range keys {
		lines.WriteString(strings.TrimSpace(string(gossh.MarshalAuthorizedKey(k))) + " " + name + "\n")
	}
	allowPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(allowPath, []byte(lines.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	allow, err := auth.LoadAllowlist(allowPath)
	if err != nil {
		t.Fatal(err)
	}

	logs := &syncBuffer{}
	cfg := DefaultConfig()
	cfg.Addr = ""
	cfg.HostSigner = host
	cfg.Allowlist = allow
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

	return &testServer{addr: ln.Addr().String(), hostKey: host.PublicKey(), alice: alice, logs: logs}
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
	s := newSession(t, c)
	var out, errb bytes.Buffer
	s.Stdout, s.Stderr = &out, &errb
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

func TestNewRequiresHostKeyAndAllowlist(t *testing.T) {
	if _, err := New(DefaultConfig()); err == nil {
		t.Fatal("New without host key or allowlist succeeded")
	}
}
