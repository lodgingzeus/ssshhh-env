package commands

import (
	"fmt"

	"github.com/lodgingzeus/ssshhh-env/internal/audit"
	"github.com/lodgingzeus/ssshhh-env/internal/authz"
)

// The helpers below build every failing Result, so what a client is told
// and what is audited stay consistent across commands. None of them is
// ever given secret values or raw client input to print.

// ok reports success. detail goes to the audit log.
func (inv *invocation) ok(detail string) Result {
	return Result{Outcome: audit.OK, Target: inv.auditTarget(), Detail: detail}
}

// usageError refuses a command line that does not match the synopsis.
func (inv *invocation) usageError() Result {
	fmt.Fprintf(inv.Stderr, "usage: %s\n", inv.cmd.usage())
	return Result{Code: 1, Outcome: audit.Error, Target: inv.auditTarget(), Detail: "bad arguments"}
}

// refuse rejects a request the client got wrong. detail goes to the audit
// log and message to the client; both must be fixed wording.
func (inv *invocation) refuse(detail, message string) Result {
	fmt.Fprintf(inv.Stderr, "%s: %s\n", inv.cmd.name, message)
	return Result{Code: 1, Outcome: audit.Error, Target: inv.auditTarget(), Detail: detail}
}

// deny refuses a project command the caller has no role for. Someone who is
// not a member is told the same thing whether or not the project exists,
// so project names can't be probed.
func (inv *invocation) deny(role authz.Role) Result {
	if role == authz.RoleNone {
		fmt.Fprintf(inv.Stderr, "%s: no such project, or you don't have access to it\n", inv.cmd.name)
	} else {
		fmt.Fprintf(inv.Stderr, "%s: permission denied: your role in %s is %s\n", inv.cmd.name, inv.target.Project, role)
	}
	return Result{Code: 1, Outcome: audit.Denied, Target: inv.auditTarget()}
}

// internal reports a server-side failure. The cause is logged; the client
// only learns that something went wrong.
func (inv *invocation) internal(d Deps, what string, err error) Result {
	d.Log.Error("command failed", "cmd", inv.cmd.name, "target", inv.auditTarget(), "step", what, "err", err)
	fmt.Fprintf(inv.Stderr, "%s: internal error\n", inv.cmd.name)
	return Result{Code: 1, Outcome: audit.Error, Target: inv.auditTarget(), Detail: "internal error: " + what}
}

// auditTarget is the validated target or user, or "" before one has been
// parsed.
func (inv *invocation) auditTarget() string {
	if inv.user != "" {
		return "user:" + inv.user
	}
	if inv.target == (Target{}) {
		return ""
	}
	if inv.target.Env == "" {
		return inv.target.Project
	}
	return inv.target.String()
}
