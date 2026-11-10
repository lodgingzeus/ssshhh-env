// Package server configures the hardened SSH server.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"charm.land/ssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/time/rate"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/commands"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// Config holds the server settings. Start from DefaultConfig.
type Config struct {
	Addr       string
	HostSigner gossh.Signer
	Store      *store.Store
	Logger     *slog.Logger

	HandshakeTimeout time.Duration // until authentication completes
	IdleTimeout      time.Duration // no traffic
	MaxTimeout       time.Duration // total connection lifetime

	MaxConns           int        // concurrent connections, server-wide
	MaxConnsPerIP      int        // concurrent connections per client IP
	ConnRate           rate.Limit // new connections per second per IP
	ConnBurst          int
	MaxSessionsPerConn int // concurrent session channels per connection
}

// DefaultConfig returns production defaults.
func DefaultConfig() Config {
	return Config{
		Addr:               ":2222",
		Logger:             slog.Default(),
		HandshakeTimeout:   10 * time.Second,
		IdleTimeout:        60 * time.Second,
		MaxTimeout:         5 * time.Minute,
		MaxConns:           100,
		MaxConnsPerIP:      10,
		ConnRate:           rate.Every(time.Second),
		ConnBurst:          10,
		MaxSessionsPerConn: 4,
	}
}

// maxTrackedIPs bounds the rate limiter's memory.
const maxTrackedIPs = 10_000

// auditTimeout bounds one audit write. Audit writes don't use the
// connection's context: they must still happen as it is being torn down.
const auditTimeout = 5 * time.Second

// Session request types refused on every session channel. Most are already
// refused by the library's defaults; filtering them here does not depend on
// those defaults. Agent forwarding is accepted by the library, so this
// filter is the only thing that refuses it.
var deniedSessionRequests = map[string]bool{
	"auth-agent-req@openssh.com": true,
	"x11-req":                    true,
	"pty-req":                    true,
	"subsystem":                  true,
}

type sessionCountKey struct{}

// New builds the SSH server. Only public-key auth against the keys
// registered in the store is accepted, and only "session" channels running allowlisted commands are
// served: no shell, PTY, subsystems or forwarding of any kind.
func New(cfg Config) (*ssh.Server, error) {
	if cfg.HostSigner == nil {
		return nil, errors.New("server: host key required")
	}
	if cfg.Store == nil {
		return nil, errors.New("server: store required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	log := cfg.Logger
	lim := newConnLimiter(cfg.MaxConns, cfg.MaxConnsPerIP, cfg.ConnRate, cfg.ConnBurst, maxTrackedIPs)

	srv := &ssh.Server{
		Addr:        cfg.Addr,
		HostSigners: []ssh.Signer{cfg.HostSigner},
		Version:     "ssshhh-env",

		// Called when a key is offered, before the client proves it holds
		// the private key. It must only answer yes/no: no logging of
		// success, no state. Identity is taken from the session, which only
		// exists after the signature has been verified.
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			_, err := auth.Lookup(ctx, cfg.Store, key)
			if err != nil && !isAuthRefusal(err) {
				log.Error("key lookup failed", "err", err)
			}
			return err == nil
		},
		PtyCallback: func(ssh.Context, ssh.Pty) bool { return false },

		ConnCallback: func(ctx ssh.Context, conn net.Conn) net.Conn {
			ip := remoteIP(conn.RemoteAddr())
			release, reason := lim.acquire(ip)
			if release == nil {
				log.Warn("connection refused", "remote", ip, "reason", reason)
				return nil
			}
			ctx.SetValue(sessionCountKey{}, new(atomic.Int64))
			return &limitedConn{Conn: conn, release: release}
		},
		ConnectionFailedCallback: func(conn net.Conn, err error) {
			ip := remoteIP(conn.RemoteAddr())
			log.Info("connection failed", "remote", ip, "err", err)
			// Only failed authentication is audited; port scans and
			// timeouts are not. Connections are rate limited per IP, which
			// bounds how fast these rows can be written.
			var authErr *gossh.ServerAuthError
			if errors.As(err, &authErr) {
				writeAudit(cfg.Store, log, audit.Event{
					RemoteAddr: ip,
					Action:     "auth",
					Result:     audit.Denied,
					Detail:     "authentication failed",
				})
			}
		},

		HandshakeTimeout: cfg.HandshakeTimeout,
		IdleTimeout:      cfg.IdleTimeout,
		MaxTimeout:       cfg.MaxTimeout,

		// Set explicitly so the library's mutable package-level defaults
		// can't add handlers.
		ChannelHandlers:   map[string]ssh.ChannelHandler{"session": sessionChannelHandler(cfg.MaxSessionsPerConn, log)},
		RequestHandlers:   map[string]ssh.RequestHandler{},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{},

		Handler: sessionHandler(cfg.Store, log),
	}
	return srv, nil
}

// isAuthRefusal reports whether err is an expected "no" from auth.Lookup,
// as opposed to a storage failure.
func isAuthRefusal(err error) bool {
	return errors.Is(err, auth.ErrUnknownKey) || errors.Is(err, auth.ErrUserDisabled) || errors.Is(err, auth.ErrWeakKey)
}

// writeAudit records e and reports whether it was written.
func writeAudit(st *store.Store, log *slog.Logger, e audit.Event) bool {
	ctx, cancel := context.WithTimeout(context.Background(), auditTimeout)
	defer cancel()
	if err := audit.Log(ctx, st, e); err != nil {
		log.Error("audit write failed", "action", e.Action, "err", err)
		return false
	}
	return true
}

func sessionHandler(st *store.Store, log *slog.Logger) ssh.Handler {
	return func(s ssh.Session) {
		ip := remoteIP(s.RemoteAddr())
		// s.PublicKey() is the key whose signature was verified. Looking it
		// up again here, per session, means a user disabled or a key
		// removed after the connection was made is refused straight away.
		id, err := auth.Lookup(s.Context(), st, s.PublicKey())
		if err != nil {
			fp := ""
			if pub := s.PublicKey(); pub != nil {
				fp = auth.Fingerprint(pub)
			}
			if isAuthRefusal(err) {
				log.Warn("session refused", "remote", ip, "fingerprint", fp, "reason", err)
				writeAudit(st, log, audit.Event{KeyFingerprint: fp, RemoteAddr: ip, Action: "session", Result: audit.Denied, Detail: err.Error()})
			} else {
				log.Error("key lookup failed", "remote", ip, "err", err)
				writeAudit(st, log, audit.Event{KeyFingerprint: fp, RemoteAddr: ip, Action: "session", Result: audit.Error, Detail: "key lookup failed"})
			}
			_ = s.Exit(1)
			return
		}
		if err := st.TouchKey(s.Context(), id.KeyID); err != nil {
			log.Error("update last_used_at failed", "err", err)
		}

		args := s.Command()
		if len(args) == 0 && s.RawCommand() != "" {
			args = []string{""} // unparseable command line: treat as unknown
		}
		name := commands.Name(args)
		code, result := commands.Run(args, id, s, s.Stderr())
		// Record the command name only, never the raw command line: it may
		// contain secrets typed by mistake.
		log.Info("session", "user", id.Name, "fingerprint", id.Fingerprint, "remote", ip, "cmd", name, "result", string(result), "exit", code)
		ok := writeAudit(st, log, audit.Event{
			UserID:         id.UserID,
			KeyFingerprint: id.Fingerprint,
			RemoteAddr:     ip,
			Action:         name,
			Result:         result,
		})
		if !ok && code == 0 {
			// An action that could not be audited must not look successful.
			code = 1
		}
		_ = s.Exit(code)
	}
}

func sessionChannelHandler(maxSessions int, log *slog.Logger) ssh.ChannelHandler {
	return func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
		count, _ := ctx.Value(sessionCountKey{}).(*atomic.Int64)
		if count == nil {
			_ = newChan.Reject(gossh.Prohibited, "session not allowed")
			return
		}
		if count.Add(1) > int64(maxSessions) {
			count.Add(-1)
			_ = newChan.Reject(gossh.ResourceShortage, "too many sessions")
			return
		}
		defer count.Add(-1)
		ssh.DefaultSessionHandler(srv, conn, filteredChannel{NewChannel: newChan, log: log}, ctx)
	}
}

// filteredChannel refuses deniedSessionRequests before the library sees them.
type filteredChannel struct {
	gossh.NewChannel
	log *slog.Logger
}

func (c filteredChannel) Accept() (gossh.Channel, <-chan *gossh.Request, error) {
	ch, reqs, err := c.NewChannel.Accept()
	if err != nil {
		return nil, nil, err
	}
	out := make(chan *gossh.Request)
	go func() {
		defer close(out)
		for req := range reqs {
			if deniedSessionRequests[req.Type] {
				c.log.Debug("session request refused", "type", req.Type)
				_ = req.Reply(false, nil)
				continue
			}
			out <- req
		}
	}()
	return ch, out, nil
}
