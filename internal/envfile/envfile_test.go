package envfile

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"one", "A=1\n", []string{"A"}},
		{"no trailing newline", "A=1", []string{"A"}},
		{"sorted", "ZED=1\nALPHA=2\nmid=3\n", []string{"ALPHA", "ZED", "mid"}},
		{"comments and blanks", "# top\n\n  # indented\nA=1\n\n", []string{"A"}},
		{"empty value", "A=\n", []string{"A"}},
		{"value with equals", "URL=postgres://u:p@h/db?x=1&y=2\n", []string{"URL"}},
		{"value with hash", "A=abc#def\n", []string{"A"}},
		{"export", "export A=1\nexport\tB=2\n", []string{"A", "B"}},
		{"named like export", "exported=1\nexport_x=2\n", []string{"export_x", "exported"}},
		{"spaces around equals", "A = 1\n  B=2  \n", []string{"A", "B"}},
		{"crlf", "A=1\r\nB=2\r\n", []string{"A", "B"}},
		{"name characters", "_a=1\nA.b-c_9=2\n", []string{"A.b-c_9", "_a"}},
		{"double quoted", `A="hello world"` + "\n", []string{"A"}},
		{"single quoted", "A='hello world'\n", []string{"A"}},
		{"quoted then comment", `A="x" # note` + "\n", []string{"A"}},
		{"escaped quote", `A="say \"hi\""` + "\nB=2\n", []string{"A", "B"}},
		{"escaped backslash", `A="ends with \\"` + "\nB=2\n", []string{"A", "B"}},
		{"single quotes have no escapes", `A='c:\dir\'` + "\nB=2\n", []string{"A", "B"}},
		{"multi-line double", "KEY=\"-----BEGIN-----\nabc=def\nnot a var\n-----END-----\"\nB=2\n", []string{"B", "KEY"}},
		{"multi-line single", "KEY='line one\n\n# not a comment\nlast'\nB=2\n", []string{"B", "KEY"}},
		{"quote inside unquoted value", "A=it's fine\nB=say \"hi\n", []string{"A", "B"}},
		{"unicode value", "A=héllo ✓\n", []string{"A"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse([]byte(tt.in))
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("names = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSyntaxErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
		line int
	}{
		{"no equals", "A=1\njust some text\n", 2},
		{"empty name", "=value\n", 1},
		{"name starts with digit", "1A=1\n", 1},
		{"name with space", "MY KEY=1\n", 1},
		{"name with unicode", "ключ=1\n", 1},
		{"name with control char", "A\x1b[31m=1\n", 1},
		{"export without name", "export =1\n", 1},
		{"bare export", "export\n", 1},
		{"duplicate", "A=1\nB=2\nA=3\n", 3},
		{"duplicate via export", "A=1\nexport A=2\n", 2},
		{"unterminated double", "A=1\nB=\"never closed\nC=3\n", 2},
		{"unterminated single", "A='never closed", 1},
		{"text after quote", `A="x" y` + "\n", 1},
		{"text after multi-line quote", "A=\"x\ny\" z\n", 2},
		{"name too long", strings.Repeat("A", maxNameLen+1) + "=1\n", 1},
		{"shell command", "A=1\nrm -rf /\n", 2},
		{"yaml", "key: value\n", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.in))
			var se *SyntaxError
			if !errors.As(err, &se) {
				t.Fatalf("err = %v, want a SyntaxError", err)
			}
			if se.Line != tt.line {
				t.Fatalf("line = %d, want %d (%v)", se.Line, tt.line, err)
			}
		})
	}
}

func TestParseRefusesWholeFile(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrEmpty},
		{"only comments", []byte("# nothing\n\n"), ErrEmpty},
		{"nul", []byte("A=1\x00\n"), ErrNUL},
		{"invalid utf-8", []byte("A=\xff\xfe\n"), ErrNotUTF8},
		{"byte order mark", []byte("\xEF\xBB\xBFA=1\n"), ErrBOM},
		{"byte order mark before a comment", []byte("\xEF\xBB\xBF# x\nA=1\n"), ErrBOM},
		{"too large", append([]byte("A="), make([]byte, MaxSize)...), ErrTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.in); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseSizeLimitIsInclusive(t *testing.T) {
	data := []byte("A=" + strings.Repeat("x", MaxSize-2))
	if _, err := Parse(data); err != nil {
		t.Fatalf("file of exactly MaxSize bytes refused: %v", err)
	}
	if _, err := Parse(append(data, 'x')); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("MaxSize+1 bytes: err = %v, want ErrTooLarge", err)
	}
}

// Errors go to a terminal and may be logged, so they must never repeat
// anything from the file.
func TestErrorsNeverContainContent(t *testing.T) {
	const canary = "CANARY_9f3a1c"
	for _, in := range []string{
		canary + "\n",
		canary + " = x = y\n" + canary + " oops\n",
		"A=1\n" + canary + "\n",
		"A=\"" + canary + "\n",
		"A=\"x\" " + canary + "\n",
		"1" + canary + "=1\n",
		canary + "=1\n" + canary + "=2\n",
		"A=" + canary + "\x00",
		"A=" + canary + "\xff",
	} {
		_, err := Parse([]byte(in))
		if err == nil {
			t.Errorf("%q: accepted", in)
			continue
		}
		if strings.Contains(err.Error(), canary) {
			t.Errorf("error repeats file content: %v", err)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"A=1\n", "export A=1\nB='x'\n", "A=\"multi\nline\"\nB=2\n", "# c\n\nA = 1\r\n",
		"A=\"\\", "A='", "=", "export", "A=1\nA=2\n", "A=\"x\" y", "\x00", "\xff",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		names, err := Parse(data)
		if err != nil {
			if names != nil {
				t.Fatal("names returned with an error")
			}
			return
		}
		if len(names) == 0 {
			t.Fatal("accepted a file with no variables")
		}
		if !slices.IsSorted(names) {
			t.Fatalf("names not sorted: %q", names)
		}
		for i, n := range names {
			if !validName([]byte(n)) {
				t.Fatalf("invalid name %q accepted", n)
			}
			if i > 0 && names[i-1] == n {
				t.Fatalf("duplicate name %q", n)
			}
			if !strings.Contains(string(data), n) {
				t.Fatalf("name %q is not in the input", n)
			}
		}
	})
}
