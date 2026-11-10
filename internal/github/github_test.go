package github

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/auth"
)

func keyLine(t *testing.T) (string, gossh.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := gossh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return auth.MarshalKey(k), k
}

func serve(t *testing.T, h http.HandlerFunc) Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return Client{BaseURL: srv.URL}
}

func TestKeys(t *testing.T) {
	l1, k1 := keyLine(t)
	l2, k2 := keyLine(t)
	var path string
	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(l1 + "\n" + l2 + "\n"))
	})
	keys, err := c.Keys(context.Background(), "octo-cat")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/octo-cat.keys" {
		t.Errorf("requested %q", path)
	}
	if len(keys) != 2 || auth.Fingerprint(keys[0]) != auth.Fingerprint(k1) || auth.Fingerprint(keys[1]) != auth.Fingerprint(k2) {
		t.Fatalf("got %d keys", len(keys))
	}
}

func TestKeysRejectsInvalidLoginWithoutFetching(t *testing.T) {
	var hits atomic.Int64
	c := serve(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
	for _, login := range []string{
		"", "-lead", "a/b", "../etc", "a.b", "a b", "a?x=1", "a#f", "a@evil.com", "a%2f", "über",
		strings.Repeat("a", 40), "octocat\n", "octocat.keys",
	} {
		if _, err := c.Keys(context.Background(), login); err == nil {
			t.Errorf("login %q accepted", login)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("%d requests made for invalid logins", hits.Load())
	}
	for _, ok := range []string{"a", "octocat", "Octo-Cat-9", strings.Repeat("a", 39)} {
		if !ValidLogin(ok) {
			t.Errorf("login %q refused", ok)
		}
	}
}

func TestKeysErrors(t *testing.T) {
	line, _ := keyLine(t)
	tests := map[string]http.HandlerFunc{
		"not found":    func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) },
		"server error": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) },
		"garbage":      func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>login</html>")) },
		"too big": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(line + "\n" + strings.Repeat("# padding\n", maxBody/10)))
		},
	}
	for name, h := range tests {
		t.Run(name, func(t *testing.T) {
			if keys, err := serve(t, h).Keys(context.Background(), "octocat"); err == nil {
				t.Fatalf("got %d keys, want error", len(keys))
			}
		})
	}

	c := serve(t, func(http.ResponseWriter, *http.Request) {})
	if _, err := c.Keys(context.Background(), "octocat"); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("empty body: err = %v, want ErrNoKeys", err)
	}
}

// A redirect must not be followed, even to a host serving valid keys.
func TestKeysDoesNotFollowRedirects(t *testing.T) {
	line, _ := keyLine(t)
	var hits atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(line + "\n"))
	}))
	defer other.Close()

	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/evil.keys", http.StatusFound)
	})
	if keys, err := c.Keys(context.Background(), "octocat"); err == nil {
		t.Fatalf("followed a redirect and got %d keys", len(keys))
	}
	if hits.Load() != 0 {
		t.Fatal("redirect target was requested")
	}
}

func TestKeysHonoursContext(t *testing.T) {
	release := make(chan struct{})
	c := serve(t, func(http.ResponseWriter, *http.Request) { <-release })
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Keys(ctx, "octocat"); err == nil {
		t.Fatal("cancelled fetch succeeded")
	}
}
