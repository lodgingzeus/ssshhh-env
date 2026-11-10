package envfile

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestDiff(t *testing.T) {
	older := "# comment\nKEEP=1\nCHANGE=old\nGONE=x\nQUOTED=\"line1\nline2\" # note\nSPACING = a\n"
	newer := "KEEP=1\nCHANGE=new\nNEW=y\nQUOTED=\"line1\nline2\"   # other note\nexport SPACING=a\n"
	ch, err := Diff([]byte(older), []byte(newer))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(ch.Added, []string{"NEW"}) || !slices.Equal(ch.Removed, []string{"GONE"}) || !slices.Equal(ch.Changed, []string{"CHANGE"}) {
		t.Errorf("changes = %+v", ch)
	}

	tests := []struct {
		name    string
		a, b    string
		changed bool
	}{
		{"same", "A=1\n", "A=1\n", false},
		{"different value", "A=1\n", "A=2\n", true},
		{"quoting differs", "A=1\n", "A=\"1\"\n", true},
		{"multi-line value differs on a later line", "A=\"x\ny\"\n", "A=\"x\nz\"\n", true},
		{"multi-line value same", "A='x\ny'\n", "A='x\ny'  \n", false},
		{"escaped quote", `A="a\"b"` + "\n", `A="a\"c"` + "\n", true},
		{"comment after unquoted value is part of it", "A=1 # x\n", "A=1\n", true},
		{"CRLF line ending on unquoted value", "A=1\r\n", "A=1\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch, err := Diff([]byte(tt.a), []byte(tt.b))
			if err != nil {
				t.Fatal(err)
			}
			if got := len(ch.Changed) == 1; got != tt.changed || len(ch.Added)+len(ch.Removed) != 0 {
				t.Errorf("changes = %+v, want changed=%v", ch, tt.changed)
			}
		})
	}
}

func TestDiffRefusesInvalidFiles(t *testing.T) {
	if _, err := Diff([]byte("A=1\n"), []byte("not an env file\n")); err == nil {
		t.Error("invalid newer file accepted")
	}
	if _, err := Diff([]byte(""), []byte("A=1\n")); !errors.Is(err, ErrEmpty) {
		t.Errorf("empty older file: %v", err)
	}
}

func TestNameChanges(t *testing.T) {
	ch := NameChanges([]string{"A", "B", "C"}, []string{"D", "B", "A"})
	if !slices.Equal(ch.Added, []string{"D"}) || !slices.Equal(ch.Removed, []string{"C"}) || ch.Changed != nil {
		t.Errorf("changes = %+v", ch)
	}
}

// Diff must never return a value, whatever the input.
func FuzzDiff(f *testing.F) {
	f.Add([]byte("A=1\nB=\"x\ny\"\n"), []byte("A=2\nC='z'\n"))
	f.Add([]byte("A=\"\\\"\"\n"), []byte("A=\"\\\\\"\n"))
	f.Fuzz(func(t *testing.T, a, b []byte) {
		ch, err := Diff(a, b)
		if err != nil {
			return
		}
		namesA, errA := Parse(a)
		namesB, errB := Parse(b)
		if errA != nil || errB != nil {
			t.Fatalf("Diff accepted files Parse refuses: %v, %v", errA, errB)
		}
		for _, list := range [][]string{ch.Added, ch.Removed, ch.Changed} {
			for _, n := range list {
				if !slices.Contains(namesA, n) && !slices.Contains(namesB, n) {
					t.Fatalf("Diff returned %q, which is not a variable name", n)
				}
				if strings.ContainsAny(n, "=\"'\n") {
					t.Fatalf("Diff returned non-name text %q", n)
				}
			}
		}
	})
}
