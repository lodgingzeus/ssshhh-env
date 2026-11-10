package server

import (
	"log/slog"

	"charm.land/ssh"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/auth"
	"github.com/lodgingzeus/ssshhh-env/internal/commands"
	"github.com/lodgingzeus/ssshhh-env/internal/store"
)

// sessionHandler serves one session: identify the user, run one command,
// audit it, exit.
func sessionHandler(deps commands.Deps, st *store.Store) ssh.Handler {
	log := deps.Log
	return func(s ssh.Session) {
		ip := remoteIP(s.RemoteAddr())
		id, ok := identify(s, st, log, ip)
		if !ok {
			_ = s.Exit(1)
			return
		}

		// The raw line, not s.Command(): the library's shell-style split
		// drops its error and returns the words it got so far, so a line
		// with an unclosed quote would run half-parsed.
		line := s.RawCommand()
		name := commands.Name(commands.Split(line))
		res := commands.Run(s.Context(), deps, commands.Request{Line: line, ID: id, Stdin: s, Stderr: s.Stderr()})
		code := res.Code
		// Record the command name and validated target only, never the raw
		// command line: it may contain secrets typed by mistake.
		log.Info("session", "user", id.Name, "fingerprint", id.Fingerprint, "remote", ip,
			"cmd", name, "target", res.Target, "result", string(res.Outcome), "exit", code)
		audited := writeAudit(st, log, audit.Event{
			UserID:         id.UserID,
			KeyFingerprint: id.Fingerprint,
			RemoteAddr:     ip,
			Action:         name,
			Target:         res.Target,
			Result:         res.Outcome,
			Detail:         res.Detail,
		})
		if !audited {
			// An action that could not be audited must not look successful,
			// and a secret that could not be audited is not sent at all. A
			// change that was already saved is reported as such, so the
			// client doesn't make it again.
			if code == 0 {
				code = 1
			}
			msg := "internal error\n"
			if res.Changed {
				msg = "internal error: the change was saved, but recording it in the audit log failed\n"
			}
			_, _ = s.Stderr().Write([]byte(msg))
			_ = s.Exit(code)
			return
		}
		for _, out := range [][]byte{res.Stdout, res.Secret} {
			if len(out) == 0 {
				continue
			}
			if _, err := s.Write(out); err != nil {
				log.Warn("sending output failed", "cmd", name, "target", res.Target, "err", err)
				code = 1
				break
			}
		}
		_ = s.Exit(code)
	}
}

// identify returns the user the session's key belongs to. A session that
// is refused has been logged and audited by the time it returns false.
func identify(s ssh.Session, st *store.Store, log *slog.Logger, ip string) (auth.Identity, bool) {
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
		return auth.Identity{}, false
	}
	if err := st.TouchKey(s.Context(), id.KeyID); err != nil {
		log.Error("update last_used_at failed", "err", err)
	}
	return id, true
}
