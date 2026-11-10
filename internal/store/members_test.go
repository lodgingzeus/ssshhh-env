package store

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
)

func TestMemberRoleChanges(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice, bob := testUser(t, s, "alice"), testUser(t, s, "bob")
	p := testProject(t, s, "app", alice)

	// The only owner can't be demoted or removed.
	if err := s.SetMemberRole(ctx, p.ID, alice.ID, RoleWriter, alice.ID); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("demote last owner: %v", err)
	}
	if err := s.RemoveMember(ctx, p.ID, alice.ID); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("remove last owner: %v", err)
	}
	// Not a member yet.
	if err := s.SetMemberRole(ctx, p.ID, bob.ID, RoleOwner, alice.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("set role of non-member: %v", err)
	}
	if err := s.RemoveMember(ctx, p.ID, bob.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove non-member: %v", err)
	}

	if err := s.AddMember(ctx, p.ID, bob.ID, RoleReader, alice.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMemberRole(ctx, p.ID, bob.ID, RoleOwner, alice.ID); err != nil {
		t.Fatal(err)
	}
	// With two owners, either may step down, but not both.
	if err := s.SetMemberRole(ctx, p.ID, alice.ID, RoleReader, bob.ID); err != nil {
		t.Fatalf("demote one of two owners: %v", err)
	}
	if err := s.RemoveMember(ctx, p.ID, bob.ID); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("remove the remaining owner: %v", err)
	}
	if err := s.RemoveMember(ctx, p.ID, alice.ID); err != nil {
		t.Fatalf("remove a reader: %v", err)
	}
	if _, err := s.MemberRole(ctx, p.ID, alice.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed member still has a role: %v", err)
	}
}

// Two owners revoking each other at the same moment must leave one owner.
func TestConcurrentOwnerRemoval(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice, bob := testUser(t, s, "alice"), testUser(t, s, "bob")
	p := testProject(t, s, "app", alice)
	if err := s.AddMember(ctx, p.ID, bob.ID, RoleOwner, alice.ID); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, u := range []User{alice, bob} {
		wg.Go(func() { errs[i] = s.RemoveMember(ctx, p.ID, u.ID) })
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrLastOwner):
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d removals succeeded, want exactly 1", ok)
	}
	members, err := s.ListMembers(ctx, p.ID)
	if err != nil || len(members) != 1 || members[0].Role != RoleOwner {
		t.Fatalf("members after race: %+v, %v", members, err)
	}
}

func TestListMembersAndProjects(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice, bob, carol := testUser(t, s, "alice"), testUser(t, s, "bob"), testUser(t, s, "carol")
	app := testProject(t, s, "app", alice)
	web := testProject(t, s, "web", bob)
	testProject(t, s, "secret", carol)
	for _, m := range []struct {
		p    Project
		u    User
		role string
	}{{app, carol, RoleReader}, {app, bob, RoleWriter}, {web, alice, RoleReader}} {
		if err := s.AddMember(ctx, m.p.ID, m.u.ID, m.role, alice.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DisableUser(ctx, carol.ID); err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{"prod", "default"} {
		if _, err := s.AppendVersion(ctx, NewVersion{ProjectID: app.ID, EnvName: env, AuthorID: alice.ID}, testSeal); err != nil {
			t.Fatal(err)
		}
	}

	members, err := s.ListMembers(ctx, app.ID)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range members {
		got = append(got, m.Role+":"+m.Name+":"+m.GrantedBy)
	}
	if want := []string{"owner:alice:alice", "writer:bob:alice", "reader:carol:alice"}; !slices.Equal(got, want) {
		t.Errorf("members = %v, want %v", got, want)
	}
	if !members[2].Disabled || members[0].Disabled {
		t.Errorf("disabled flags wrong: %+v", members)
	}

	ms, err := s.ProjectsForUser(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].Project != "app" || ms[0].Role != RoleOwner || !slices.Equal(ms[0].Envs, []string{"default", "prod"}) ||
		ms[1].Project != "web" || ms[1].Role != RoleReader || len(ms[1].Envs) != 0 {
		t.Errorf("alice's projects = %+v", ms)
	}
	envs, err := s.EnvironmentNames(ctx, app.ID)
	if err != nil || !slices.Equal(envs, []string{"default", "prod"}) {
		t.Errorf("environments = %v, %v", envs, err)
	}
}
