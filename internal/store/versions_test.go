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

// testSeal stands in for the crypto layer: it records the ids it was given.
func testSeal(envID, number int64) (SealedVersion, error) {
	return SealedVersion{Nonce: []byte("nonce"), Ciphertext: fmt.Appendf(nil, "sealed-for-%d-%d", envID, number)}, nil
}

func TestAppendAndReadVersions(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice := testUser(t, s, "alice")
	p := testProject(t, s, "app", alice)

	if _, err := s.LatestVersion(ctx, p.ID, "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no versions yet: err = %v, want ErrNotFound", err)
	}

	nv := NewVersion{ProjectID: p.ID, EnvName: "default", AuthorID: alice.ID, Message: "first", KeyNames: []string{"A", "B"}, SizeBytes: 8}
	v1, err := s.AppendVersion(ctx, nv, testSeal)
	if err != nil {
		t.Fatal(err)
	}
	if v1.Number != 1 || v1.EnvID == 0 || v1.CreatedAt == "" {
		t.Fatalf("v1 = %+v", v1)
	}
	nv.Message, nv.KeyNames = "", nil
	v2, err := s.AppendVersion(ctx, nv, testSeal)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Number != 2 || v2.EnvID != v1.EnvID {
		t.Fatalf("v2 = %+v", v2)
	}

	// A second environment has its own numbering.
	nv.EnvName = "prod"
	prod, err := s.AppendVersion(ctx, nv, testSeal)
	if err != nil {
		t.Fatal(err)
	}
	if prod.Number != 1 || prod.EnvID == v1.EnvID {
		t.Fatalf("prod = %+v", prod)
	}

	latest, err := s.LatestVersion(ctx, p.ID, "default")
	if err != nil || latest.Number != 2 || len(latest.KeyNames) != 0 {
		t.Fatalf("latest = %+v, err %v", latest, err)
	}
	got, err := s.VersionByNumber(ctx, p.ID, "default", 1)
	if err != nil {
		t.Fatal(err)
	}
	wantCT := fmt.Sprintf("sealed-for-%d-1", v1.EnvID)
	if got.Number != 1 || string(got.Ciphertext) != wantCT || string(got.Nonce) != "nonce" || got.Message != "first" ||
		got.AuthorID != alice.ID || got.SizeBytes != 8 || !slices.Equal(got.KeyNames, []string{"A", "B"}) {
		t.Fatalf("version 1 = %+v", got)
	}

	for name, lookup := range map[string]func() (Version, error){
		"missing number": func() (Version, error) { return s.VersionByNumber(ctx, p.ID, "default", 3) },
		"zero":           func() (Version, error) { return s.VersionByNumber(ctx, p.ID, "default", 0) },
		"missing env":    func() (Version, error) { return s.LatestVersion(ctx, p.ID, "staging") },
		"other project":  func() (Version, error) { return s.LatestVersion(ctx, p.ID+1, "default") },
	} {
		if _, err := lookup(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", name, err)
		}
	}
}

// Environments with the same name in different projects are separate.
func TestVersionsAreScopedToProject(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice := testUser(t, s, "alice")
	a, b := testProject(t, s, "a", alice), testProject(t, s, "b", alice)

	va, err := s.AppendVersion(ctx, NewVersion{ProjectID: a.ID, EnvName: "default", AuthorID: alice.ID}, testSeal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LatestVersion(ctx, b.ID, "default"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("project b sees project a's version: err = %v", err)
	}
	vb, err := s.AppendVersion(ctx, NewVersion{ProjectID: b.ID, EnvName: "default", AuthorID: alice.ID}, testSeal)
	if err != nil {
		t.Fatal(err)
	}
	if vb.EnvID == va.EnvID || vb.Number != 1 {
		t.Fatalf("a = %+v, b = %+v", va, vb)
	}
}

func TestAppendVersionRefusals(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice := testUser(t, s, "alice")
	p := testProject(t, s, "app", alice)
	nv := NewVersion{ProjectID: p.ID, EnvName: "default", AuthorID: alice.ID}

	sealErr := errors.New("no entropy")
	if _, err := s.AppendVersion(ctx, nv, func(int64, int64) (SealedVersion, error) { return SealedVersion{}, sealErr }); !errors.Is(err, sealErr) {
		t.Fatalf("seal failure: err = %v", err)
	}
	if _, err := s.AppendVersion(ctx, nv, func(int64, int64) (SealedVersion, error) { return SealedVersion{Nonce: []byte("n")}, nil }); err == nil {
		t.Fatal("empty ciphertext accepted")
	}
	bad := nv
	bad.ProjectID = 999
	if _, err := s.AppendVersion(ctx, bad, testSeal); err == nil {
		t.Fatal("version appended to a project that does not exist")
	}
	// A failed push leaves nothing behind, not even the environment.
	var envs int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM environments`).Scan(&envs); err != nil || envs != 0 {
		t.Fatalf("environments = %d, err %v; want 0", envs, err)
	}
	// The next push still gets number 1.
	if v, err := s.AppendVersion(ctx, nv, testSeal); err != nil || v.Number != 1 {
		t.Fatalf("after failures: version %+v, err %v", v, err)
	}
}

func TestVersionsAreAppendOnly(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice := testUser(t, s, "alice")
	p := testProject(t, s, "app", alice)
	if _, err := s.AppendVersion(ctx, NewVersion{ProjectID: p.ID, EnvName: "default", AuthorID: alice.ID}, testSeal); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE versions SET ciphertext = x'00'`, `UPDATE versions SET message = 'x'`, `DELETE FROM versions`} {
		if _, err := s.db.ExecContext(ctx, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: err = %v, want append-only refusal", q, err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO versions (env_id, version, nonce, ciphertext, size_bytes, key_names_json, author_id, created_at)
		SELECT env_id, version, nonce, ciphertext, 0, '[]', author_id, 'now' FROM versions`); err == nil {
		t.Error("duplicate version number accepted")
	}
}

func TestConcurrentAppendVersion(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	alice := testUser(t, s, "alice")
	p := testProject(t, s, "app", alice)

	const n = 16
	var wg sync.WaitGroup
	versions := make([]Version, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			versions[i], errs[i] = s.AppendVersion(ctx, NewVersion{ProjectID: p.ID, EnvName: "default", AuthorID: alice.ID}, testSeal)
		}()
	}
	wg.Wait()

	seen := map[int64]bool{}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("push %d: %v", i, err)
		}
		v := versions[i]
		if v.Number < 1 || v.Number > n || seen[v.Number] {
			t.Fatalf("version numbers are not exactly 1..%d: got %d twice or out of range", n, v.Number)
		}
		seen[v.Number] = true
		// Each payload was sealed for the number its own row ended up with.
		got, err := s.VersionByNumber(ctx, p.ID, "default", v.Number)
		if err != nil {
			t.Fatal(err)
		}
		if want := fmt.Sprintf("sealed-for-%d-%d", v.EnvID, v.Number); string(got.Ciphertext) != want {
			t.Errorf("version %d holds %q, want %q", v.Number, got.Ciphertext, want)
		}
	}
}
