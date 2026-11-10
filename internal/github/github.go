// Package github fetches a user's public SSH keys from GitHub.
//
// The keys it returns are only as trustworthy as the GitHub account: callers
// must show the fingerprints to the operator and pin the keys, never fetch
// them again silently.
package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/auth"
)

const (
	defaultBaseURL = "https://github.com"
	fetchTimeout   = 5 * time.Second
	maxBody        = 64 << 10
)

var loginRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)

// ErrNoKeys means the account exists but has no SSH keys.
var ErrNoKeys = errors.New("github user has no SSH keys")

// ValidLogin reports whether login is a syntactically valid GitHub username.
func ValidLogin(login string) bool { return loginRe.MatchString(login) }

// Client fetches keys. The zero value talks to github.com.
type Client struct {
	// BaseURL overrides https://github.com. For tests only.
	BaseURL string
	// HTTP overrides the transport. For tests only.
	HTTP *http.Client
}

// Keys returns the public keys listed at https://github.com/<login>.keys.
// The request has a 5s timeout and a 64 KB body cap, and redirects are not
// followed. The key policy is not applied here.
func (c Client) Keys(ctx context.Context, login string) ([]gossh.PublicKey, error) {
	if !ValidLogin(login) {
		return nil, errors.New("invalid GitHub username")
	}
	base := c.BaseURL
	if base == "" {
		base = defaultBaseURL
	}
	hc := &http.Client{}
	if c.HTTP != nil {
		hc.Transport = c.HTTP.Transport
	}
	// github.com serves .keys directly. A redirect would mean fetching keys
	// from somewhere else, so it is an error rather than something to follow.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	// login matched loginRe, so it cannot change the path or host.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+login+".keys", nil)
	if err != nil {
		return nil, fmt.Errorf("github: %w", err)
	}
	req.Header.Set("User-Agent", "ssshhh-env")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github: fetch keys for %s: %w", login, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("github: user %s not found", login)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("github: fetch keys for %s: unexpected status %d", login, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("github: fetch keys for %s: %w", login, err)
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("github: keys for %s exceed %d bytes", login, maxBody)
	}
	keys, err := auth.ParsePublicKeys(body)
	if err != nil {
		return nil, fmt.Errorf("github: keys for %s: %w", login, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoKeys, login)
	}
	return keys, nil
}
