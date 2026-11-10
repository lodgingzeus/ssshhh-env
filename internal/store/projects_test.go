package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

func testUser(t *testing.T, s *Store, name string) User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), NewUser{Name: name}, []NewKey{testKey("SHA256:" + name)})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// testWrap stands in for the crypto layer: it records the id it was given.
func testWrap(keyID string) func(int64) (WrappedDEK, error) {
	return func(projectID int64) (WrappedDEK, error) {
		return WrappedDEK{Nonce: []byte("nonce"), Ciphertext: fmt.Appendf(nil, "wrapped-for-%d", projectID), MasterKeyID: keyID}, nil
	}
}

func testProject(t *testing.T, s *Store, name string, owner User) Project {
	t.Helper()
	p, err := s.CreateProject(context.Background(), name, owner.ID, testWrap("key1"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCreateProject(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice, bob := testUser(t, s, "alice"), testUser(t, s, "bob")

	p := testProject(t, s, "app", alice)
	if p.ID != 1 || string(p.WrappedDEK) != "wrapped-for-1" || p.MasterKeyID != "key1" {
		t.Fatalf("project = %+v", p)
	}
	got, err := s.ProjectByName(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != p.ID || got.Name != "app" || string(got.WrappedDEK) != "wrapped-for-1" || string(got.DEKNonce) != "nonce" || got.MasterKeyID != "key1" {
		t.Fatalf("read back %+v", got)
	}

	// The creator is the owner; nobody else is a member.
	if role, err := s.MemberRole(ctx, p.ID, alice.ID); err != nil || role != RoleOwner {
		t.Fatalf("creator role = %q, err %v", role, err)
	}
	if _, err := s.MemberRole(ctx, p.ID, bob.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-member: err = %v, want ErrNotFound", err)
	}

	// The wrap callback gets the id the second project really has.
	p2 := testProject(t, s, "other", bob)
	if p2.ID != 2 || string(p2.WrappedDEK) != "wrapped-for-2" {
		t.Fatalf("second project = %+v", p2)
	}
	if _, err := s.MemberRole(ctx, p2.ID, alice.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("owner of one project is a member of another: err = %v", err)
	}
}

func TestCreateProjectRefusals(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice := testUser(t, s, "alice")
	testProject(t, s, "app", alice)

	called := false
	_, err := s.CreateProject(ctx, "app", alice.ID, func(int64) (WrappedDEK, error) {
		called = true
		return WrappedDEK{}, nil
	})
	if !errors.Is(err, ErrExists) || called {
		t.Fatalf("duplicate name: err = %v, wrap called = %v", err, called)
	}

	wrapErr := errors.New("no entropy")
	if _, err := s.CreateProject(ctx, "fails", alice.ID, func(int64) (WrappedDEK, error) { return WrappedDEK{}, wrapErr }); !errors.Is(err, wrapErr) {
		t.Fatalf("wrap failure: err = %v", err)
	}
	for name, dek := range map[string]WrappedDEK{
		"no nonce":      {Ciphertext: []byte("c"), MasterKeyID: "k"},
		"no ciphertext": {Nonce: []byte("n"), MasterKeyID: "k"},
		"no key id":     {Nonce: []byte("n"), Ciphertext: []byte("c")},
	} {
		if _, err := s.CreateProject(ctx, "fails", alice.ID, func(int64) (WrappedDEK, error) { return dek, nil }); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := s.CreateProject(ctx, "ghost", 999, testWrap("key1")); err == nil {
		t.Error("project created by a user that does not exist")
	}
	// Nothing from the failed attempts was kept.
	for _, name := range []string{"fails", "ghost"} {
		if _, err := s.ProjectByName(ctx, name); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", name, err)
		}
	}
}

func TestAddMember(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice, bob := testUser(t, s, "alice"), testUser(t, s, "bob")
	p := testProject(t, s, "app", alice)

	if err := s.AddMember(ctx, p.ID, bob.ID, RoleReader, alice.ID); err != nil {
		t.Fatal(err)
	}
	if role, err := s.MemberRole(ctx, p.ID, bob.ID); err != nil || role != RoleReader {
		t.Fatalf("role = %q, err %v", role, err)
	}
	// Adding again must not quietly change the role.
	if err := s.AddMember(ctx, p.ID, bob.ID, RoleOwner, alice.ID); !errors.Is(err, ErrExists) {
		t.Fatalf("second add: err = %v, want ErrExists", err)
	}
	if role, _ := s.MemberRole(ctx, p.ID, bob.ID); role != RoleReader {
		t.Fatalf("role changed to %q", role)
	}
	for name, add := range map[string]func() error{
		"unknown role":    func() error { return s.AddMember(ctx, p.ID, bob.ID+10, "admin", alice.ID) },
		"unknown user":    func() error { return s.AddMember(ctx, p.ID, 999, RoleReader, alice.ID) },
		"unknown project": func() error { return s.AddMember(ctx, 999, bob.ID, RoleReader, alice.ID) },
	} {
		if err := add(); err == nil || errors.Is(err, ErrExists) {
			t.Errorf("%s: err = %v, want a constraint failure", name, err)
		}
	}
}

func TestMembersRoleIsConstrained(t *testing.T) {
	s, _ := openTest(t)
	alice, bob := testUser(t, s, "alice"), testUser(t, s, "bob")
	p := testProject(t, s, "app", alice)
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO members (project_id, user_id, role, granted_by, granted_at) VALUES (?, ?, 'admin', ?, 'now')`, p.ID, bob.ID, alice.ID)
	if err == nil || !strings.Contains(err.Error(), "CHECK") {
		t.Fatalf("unknown role: err = %v, want a CHECK failure", err)
	}
}

func TestMasterKeyIDs(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice := testUser(t, s, "alice")
	if ids, err := s.MasterKeyIDs(ctx); err != nil || len(ids) != 0 {
		t.Fatalf("empty database: ids = %v, err %v", ids, err)
	}
	for name, keyID := range map[string]string{"a": "key1", "b": "key1", "c": "key2"} {
		if _, err := s.CreateProject(ctx, name, alice.ID, testWrap(keyID)); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := s.MasterKeyIDs(ctx)
	if err != nil || !slices.Equal(ids, []string{"key1", "key2"}) {
		t.Fatalf("ids = %v, err %v", ids, err)
	}
}

func TestConcurrentCreateProject(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice := testUser(t, s, "alice")

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.CreateProject(ctx, fmt.Sprintf("p%d", i), alice.ID, func(id int64) (WrappedDEK, error) {
				return WrappedDEK{Nonce: []byte("n"), Ciphertext: fmt.Appendf(nil, "wrapped-for-%d", id), MasterKeyID: "k"}, nil
			})
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("project %d: %v", i, err)
		}
	}
	// Each data key was wrapped for the id its own row ended up with.
	for i := range n {
		p, err := s.ProjectByName(ctx, fmt.Sprintf("p%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("wrapped-for-%d", p.ID); string(p.WrappedDEK) != want {
			t.Errorf("project %d has data key %q, want %q", p.ID, p.WrappedDEK, want)
		}
	}
}
