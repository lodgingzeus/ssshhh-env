// Package authz holds the single authorization policy. Every command asks
// Can before doing anything; nothing else decides access.
package authz

// Action is something a user can attempt.
type Action string

// Actions. Each command maps to exactly one.
const (
	Help     Action = "help"
	Whoami   Action = "whoami"
	Projects Action = "projects" // list the caller's own projects
	Init     Action = "init"     // create a project
	Push     Action = "push"
	Pull     Action = "pull"
	History  Action = "history"
	Diff     Action = "diff"
	Members  Action = "members"
	Grant    Action = "grant"
	Revoke   Action = "revoke"
	// Account management: user add/list/disable, key add/remove/refresh.
	ManageUsers Action = "manage-users"
)

// Role is a user's role in one project. The zero value means "not a
// member". Roles are ordered: each includes everything below it.
type Role int

// Roles, lowest first.
const (
	RoleNone Role = iota
	RoleReader
	RoleWriter
	RoleOwner
)

// Subject is the authenticated user making the request.
type Subject struct {
	IsAdmin  bool // server admin
	Disabled bool
}

// requirement is what an action needs. Exactly one field is set.
type requirement struct {
	anyUser bool // any registered, enabled user
	admin   bool // server admin
	role    Role // at least this role in the target project
}

// policy lists every action. An action missing from it is denied.
var policy = map[Action]requirement{
	Help:        {anyUser: true},
	Whoami:      {anyUser: true},
	Projects:    {anyUser: true},
	Init:        {admin: true},
	ManageUsers: {admin: true},
	Pull:        {role: RoleReader},
	History:     {role: RoleReader},
	Diff:        {role: RoleReader},
	Members:     {role: RoleReader},
	Push:        {role: RoleWriter},
	Grant:       {role: RoleOwner},
	Revoke:      {role: RoleOwner},
}

// Can reports whether sub may perform action. role is sub's role in the
// project the action targets; pass RoleNone for actions without a project.
//
// It denies by default: disabled users, unknown actions and unknown roles
// are refused. Being a server admin grants no access to project contents;
// an admin must be a member like anyone else.
func Can(sub Subject, action Action, role Role) bool {
	if sub.Disabled {
		return false
	}
	req, ok := policy[action]
	if !ok {
		return false
	}
	switch {
	case req.anyUser:
		return true
	case req.admin:
		return sub.IsAdmin
	case req.role >= RoleReader && req.role <= RoleOwner:
		return role >= req.role && role <= RoleOwner
	default:
		return false
	}
}
