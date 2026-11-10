package store

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func githubKey(fp string) NewKey {
	k := testKey(fp)
	k.Source = SourceGitHub
	return k
}

func keyFPs(t *testing.T, s *Store, userID int64) []string {
	t.Helper()
	keys, err := s.KeysForUser(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, k := range keys {
		out = append(out, k.Fingerprint)
	}
	return out
}

func TestCreateUserConflicts(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	testUser(t, s, "alice")
	if _, err := s.CreateUser(ctx, NewUser{Name: "ALICE"}, []NewKey{testKey("SHA256:x")}); !errors.Is(err, ErrExists) {
		t.Errorf("name differing only in case: %v", err)
	}
	if _, err := s.CreateUser(ctx, NewUser{Name: "bob"}, []NewKey{testKey("SHA256:x"), testKey("SHA256:alice")}); !errors.Is(err, ErrKeyInUse) {
		t.Errorf("key of another user: %v", err)
	}
	// Nothing of the refused user was written.
	if _, err := s.UserByName(ctx, "bob"); !errors.Is(err, ErrNotFound) {
		t.Errorf("refused user exists: %v", err)
	}
	if _, _, err := s.KeyByFingerprint(ctx, "SHA256:x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("refused user's key exists: %v", err)
	}
}

func TestUserLookups(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	u, err := s.CreateUser(ctx, NewUser{Name: "Octo", GitHubLogin: "octocat"}, []NewKey{githubKey("SHA256:o"), testKey("SHA256:o2")})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []func() (User, error){
		func() (User, error) { return s.UserByName(ctx, "octo") },
		func() (User, error) { return s.UserByGitHubLogin(ctx, "OctoCat") },
	} {
		got, err := f()
		if err != nil || got.ID != u.ID || got.GitHubLogin != "octocat" {
			t.Errorf("lookup = %+v, %v", got, err)
		}
	}
	if _, err := s.UserByGitHubLogin(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown login: %v", err)
	}
	users, err := s.ListUsers(ctx)
	if err != nil || len(users) != 1 || users[0].Keys != 2 {
		t.Errorf("users = %+v, %v", users, err)
	}
}

func TestAddAndRemoveKeys(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice, bob := testUser(t, s, "alice"), testUser(t, s, "bob")

	added, err := s.AddKeys(ctx, alice.ID, []NewKey{testKey("SHA256:alice"), testKey("SHA256:a2")})
	if err != nil || !slices.Equal(added, []string{"SHA256:a2"}) {
		t.Fatalf("add = %v, %v (a key she has must be skipped)", added, err)
	}
	if _, err := s.AddKeys(ctx, alice.ID, []NewKey{testKey("SHA256:a3"), testKey("SHA256:bob")}); !errors.Is(err, ErrKeyInUse) {
		t.Fatalf("add bob's key: %v", err)
	}
	if got := keyFPs(t, s, alice.ID); !slices.Equal(got, []string{"SHA256:alice", "SHA256:a2"}) {
		t.Fatalf("a refused add changed keys: %v", got)
	}

	if err := s.RemoveKey(ctx, alice.ID, "SHA256:bob"); !errors.Is(err, ErrNotFound) {
		t.Errorf("remove another user's key: %v", err)
	}
	if err := s.RemoveKey(ctx, alice.ID, "SHA256:alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveKey(ctx, alice.ID, "SHA256:a2"); !errors.Is(err, ErrLastKey) {
		t.Errorf("remove last key: %v", err)
	}
	if got := keyFPs(t, s, bob.ID); len(got) != 1 {
		t.Errorf("bob's keys changed: %v", got)
	}
}

func TestReplaceGitHubKeys(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	testUser(t, s, "bob")
	u, err := s.CreateUser(ctx, NewUser{Name: "octo", GitHubLogin: "octo"},
		[]NewKey{githubKey("SHA256:g1"), githubKey("SHA256:g2"), testKey("SHA256:manual")})
	if err != nil {
		t.Fatal(err)
	}

	ch, err := s.ReplaceGitHubKeys(ctx, u.ID, []NewKey{githubKey("SHA256:g2"), githubKey("SHA256:g3"), githubKey("SHA256:manual")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ch.Added, []string{"SHA256:g3"}) || !slices.Equal(ch.Removed, []string{"SHA256:g1"}) {
		t.Errorf("changes = %+v", ch)
	}
	if got := keyFPs(t, s, u.ID); !slices.Equal(got, []string{"SHA256:g2", "SHA256:manual", "SHA256:g3"}) {
		t.Errorf("keys = %v (manual keys must be kept)", got)
	}

	// Unchanged keys: no changes reported.
	ch, err = s.ReplaceGitHubKeys(ctx, u.ID, []NewKey{githubKey("SHA256:g2"), githubKey("SHA256:g3")})
	if err != nil || len(ch.Added)+len(ch.Removed) != 0 {
		t.Errorf("no-op refresh = %+v, %v", ch, err)
	}
	// A key of another user refuses the whole refresh.
	if _, err := s.ReplaceGitHubKeys(ctx, u.ID, []NewKey{githubKey("SHA256:bob")}); !errors.Is(err, ErrKeyInUse) {
		t.Errorf("refresh with bob's key: %v", err)
	}
	if got := keyFPs(t, s, u.ID); len(got) != 3 {
		t.Errorf("a refused refresh changed keys: %v", got)
	}
	if _, err := s.ReplaceGitHubKeys(ctx, u.ID, nil); err == nil {
		t.Error("refresh with no keys accepted")
	}
}

func TestDisableLastAdmin(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	root, err := s.BootstrapAdmin(ctx, "root", "", []NewKey{testKey("SHA256:root")})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DisableUser(ctx, root.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable only admin: %v", err)
	}
	admin2, err := s.CreateUser(ctx, NewUser{Name: "admin2", IsAdmin: true}, []NewKey{testKey("SHA256:a2")})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DisableUser(ctx, root.ID); err != nil {
		t.Fatalf("disable one of two admins: %v", err)
	}
	if err := s.DisableUser(ctx, admin2.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable the remaining admin: %v", err)
	}
	if err := s.DisableUser(ctx, root.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disable twice: %v", err)
	}
}

func TestListVersions(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice := testUser(t, s, "alice")
	p := testProject(t, s, "app", alice)
	if _, err := s.ListVersions(ctx, p.ID, "default", 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no environment: %v", err)
	}
	for i, names := range [][]string{{"A"}, {"A", "B"}, {"B"}} {
		if _, err := s.AppendVersion(ctx, NewVersion{ProjectID: p.ID, EnvName: "default", AuthorID: alice.ID, KeyNames: names, Message: string(rune('x' + i))}, testSeal); err != nil {
			t.Fatal(err)
		}
	}
	vs, err := s.ListVersions(ctx, p.ID, "default", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 || vs[0].Number != 3 || vs[1].Number != 2 || vs[0].Author != "alice" ||
		!slices.Equal(vs[1].KeyNames, []string{"A", "B"}) || vs[0].Message != "z" {
		t.Errorf("versions = %+v", vs)
	}
	if _, err := s.ListVersions(ctx, p.ID, "default", 0); err == nil {
		t.Error("limit 0 accepted")
	}
}
