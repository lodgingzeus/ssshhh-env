package authz

import (
	"fmt"
	"testing"
)

// allActions must list every Action constant. TestMatrixCoversPolicy fails
// if the policy gains an action that is missing here.
var allActions = []Action{
	Help, Whoami, Projects, Init, Push, Pull, History, Diff, Members, Grant, Revoke, ManageUsers,
}

var allRoles = []Role{RoleNone, RoleReader, RoleWriter, RoleOwner}

func roleName(r Role) string {
	switch r {
	case RoleNone:
		return "none"
	case RoleReader:
		return "reader"
	case RoleWriter:
		return "writer"
	case RoleOwner:
		return "owner"
	default:
		return fmt.Sprintf("role(%d)", int(r))
	}
}

// The expected outcome for every action × role, for an enabled user who is
// not a server admin (plain) and one who is (admin). Written out in full on
// purpose: it is the specification, independent of how Can is implemented.
//
//	columns: none, reader, writer, owner
var matrix = map[Action]struct{ plain, admin [4]bool }{
	Help:     {plain: [4]bool{true, true, true, true}, admin: [4]bool{true, true, true, true}},
	Whoami:   {plain: [4]bool{true, true, true, true}, admin: [4]bool{true, true, true, true}},
	Projects: {plain: [4]bool{true, true, true, true}, admin: [4]bool{true, true, true, true}},

	// Server-admin actions: project role is irrelevant.
	Init:        {plain: [4]bool{false, false, false, false}, admin: [4]bool{true, true, true, true}},
	ManageUsers: {plain: [4]bool{false, false, false, false}, admin: [4]bool{true, true, true, true}},

	// Project actions: server admin gives nothing extra.
	Pull:    {plain: [4]bool{false, true, true, true}, admin: [4]bool{false, true, true, true}},
	History: {plain: [4]bool{false, true, true, true}, admin: [4]bool{false, true, true, true}},
	Diff:    {plain: [4]bool{false, true, true, true}, admin: [4]bool{false, true, true, true}},
	Members: {plain: [4]bool{false, true, true, true}, admin: [4]bool{false, true, true, true}},
	Push:    {plain: [4]bool{false, false, true, true}, admin: [4]bool{false, false, true, true}},
	Grant:   {plain: [4]bool{false, false, false, true}, admin: [4]bool{false, false, false, true}},
	Revoke:  {plain: [4]bool{false, false, false, true}, admin: [4]bool{false, false, false, true}},
}

func TestCanMatrix(t *testing.T) {
	for _, action := range allActions {
		want, ok := matrix[action]
		if !ok {
			t.Errorf("action %q has no expected outcomes in the matrix", action)
			continue
		}
		for i, role := range allRoles {
			for _, admin := range []bool{false, true} {
				expect := want.plain[i]
				if admin {
					expect = want.admin[i]
				}
				name := fmt.Sprintf("%s/%s/admin=%v", action, roleName(role), admin)
				if got := Can(Subject{IsAdmin: admin}, action, role); got != expect {
					t.Errorf("%s: Can = %v, want %v", name, got, expect)
				}
				// A disabled user can do nothing, whatever else is true.
				if Can(Subject{IsAdmin: admin, Disabled: true}, action, role) {
					t.Errorf("%s: allowed for a disabled user", name)
				}
			}
		}
	}
}

func TestMatrixCoversPolicy(t *testing.T) {
	listed := map[Action]bool{}
	for _, a := range allActions {
		listed[a] = true
	}
	for a := range policy {
		if !listed[a] {
			t.Errorf("policy action %q is not in allActions, so it is untested", a)
		}
	}
	for a := range matrix {
		if !listed[a] {
			t.Errorf("matrix action %q is not in allActions", a)
		}
	}
	if len(policy) != len(allActions) || len(matrix) != len(allActions) {
		t.Errorf("policy has %d actions, matrix %d, allActions %d", len(policy), len(matrix), len(allActions))
	}
}

func TestCanDeniesByDefault(t *testing.T) {
	everyone := []Subject{{}, {IsAdmin: true}}
	for _, sub := range everyone {
		for _, role := range allRoles {
			for _, action := range []Action{"", "shell", "exec", "PULL", "pull ", "admin"} {
				if Can(sub, action, role) {
					t.Errorf("unknown action %q allowed (admin=%v, role=%s)", action, sub.IsAdmin, roleName(role))
				}
			}
		}
		// Out-of-range roles never satisfy a project requirement.
		for _, role := range []Role{-1, RoleOwner + 1, 100} {
			for _, action := range []Action{Pull, Push, Grant, Revoke, History, Diff, Members} {
				if Can(sub, action, role) {
					t.Errorf("%q allowed for invalid %s (admin=%v)", action, roleName(role), sub.IsAdmin)
				}
			}
		}
	}
}

func TestPolicyRequirementsAreWellFormed(t *testing.T) {
	for a, req := range policy {
		set := 0
		if req.anyUser {
			set++
		}
		if req.admin {
			set++
		}
		if req.role != RoleNone {
			set++
		}
		if set != 1 {
			t.Errorf("action %q: exactly one requirement must be set, got %+v", a, req)
		}
	}
}
