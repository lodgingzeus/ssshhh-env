package crypto

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMasterKeyEncodeParse(t *testing.T) {
	k := newKey(t)
	enc := k.Encode()
	if len(enc) != 44 {
		t.Fatalf("encoded key is %d chars, want 44", len(enc))
	}
	for _, in := range []string{enc, enc + "\n", "  " + enc + "\r\n"} {
		got, err := ParseMasterKey(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		if got.key != k.key || got.ID() != k.ID() {
			t.Fatal("parsed key differs")
		}
	}
}

func TestMasterKeyID(t *testing.T) {
	a, b := newKey(t), newKey(t)
	if a.ID() == b.ID() {
		t.Fatal("different keys share an id")
	}
	if len(a.ID()) != 16 {
		t.Fatalf("id = %q, want 16 hex chars", a.ID())
	}
	if strings.Contains(a.Encode(), a.ID()) {
		t.Fatal("id appears in the encoded key")
	}
}

func TestParseMasterKeyRefusals(t *testing.T) {
	enc := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	short := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	long := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 33)))
	const canary = "CANARY_not_a_key!"
	for name, in := range map[string]string{
		"empty":      "",
		"not base64": canary,
		"16 bytes":   short,
		"33 bytes":   long,
		"all zeros":  enc(KeySize),
		"two keys":   newKey(t).Encode() + "\n" + newKey(t).Encode(),
		"hex":        strings.Repeat("ab", KeySize),
	} {
		_, err := ParseMasterKey(in)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), canary) || (in != "" && strings.Contains(err.Error(), in)) {
			t.Errorf("%s: error echoes the input: %v", name, err)
		}
	}
}

func TestLoadMasterKeyFile(t *testing.T) {
	k := newKey(t)
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		// WriteFile's mode is filtered by the umask.
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}

	for _, mode := range []os.FileMode{0o600, 0o400} {
		got, err := LoadMasterKeyFile(write("ok", k.Encode()+"\n", mode))
		if err != nil {
			t.Fatalf("mode %04o: %v", mode, err)
		}
		if got.key != k.key {
			t.Fatalf("mode %04o: loaded key differs", mode)
		}
	}

	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660, 0o777} {
		_, err := LoadMasterKeyFile(write("open", k.Encode(), mode))
		if err == nil || !strings.Contains(err.Error(), "too open") {
			t.Errorf("mode %04o: err = %v, want a permissions error", mode, err)
		}
	}

	refused := map[string]string{
		"missing":   filepath.Join(dir, "missing"),
		"directory": dir,
		"garbage":   write("garbage", "not a key\n", 0o600),
		"empty":     write("empty", "", 0o600),
		"too large": write("large", strings.Repeat("A", maxKeyFile+1), 0o600),
	}
	for name, path := range refused {
		if _, err := LoadMasterKeyFile(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// A symlink is judged by the file it points at.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(write("target", k.Encode(), 0o644), link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMasterKeyFile(link); err == nil {
		t.Error("symlink to a world-readable key accepted")
	}
}
