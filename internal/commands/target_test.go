package commands

import (
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	long := strings.Repeat("a", 63)
	valid := map[string]Target{
		"app":             {"app", DefaultEnv},
		"app:prod":        {"app", "prod"},
		"my-app-2:stg-1":  {"my-app-2", "stg-1"},
		"0":               {"0", DefaultEnv},
		long + ":" + long: {long, long},
		"app:default":     {"app", "default"},
	}
	for in, want := range valid {
		got, err := ParseTarget(in)
		if err != nil || got != want {
			t.Errorf("ParseTarget(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}

	invalid := []string{
		"", ":", "app:", ":prod", "app:prod:extra", "App", "app:Prod", "-app", "app:-x",
		"my_app", "my.app", "app/prod", "../etc", "app prod", " app", "app\n", "app\x00",
		"app\x1b[31m", "äpp", long + "a", "app:" + long + "a", "app;rm", "$(id)", "*",
	}
	for _, in := range invalid {
		if got, err := ParseTarget(in); err == nil {
			t.Errorf("ParseTarget(%q) = %+v, want an error", in, got)
		}
	}
}

func TestTargetString(t *testing.T) {
	if got := (Target{Project: "app", Env: "prod"}).String(); got != "app:prod" {
		t.Fatalf("String = %q", got)
	}
}

func TestParsePushArgs(t *testing.T) {
	tests := []struct {
		rest []string
		msg  string
		ok   bool
	}{
		{nil, "", true},
		{[]string{"-m", "fix"}, "fix", true},
		{[]string{"-m", "rotate", "db", "password"}, "rotate db password", true},
		{[]string{"-m", "-m"}, "-m", true},
		{[]string{"-m"}, "", false},
		{[]string{"fix"}, "", false},
		{[]string{"--message", "fix"}, "", false},
		{[]string{"-mfix"}, "", false},
		{[]string{"extra", "-m", "fix"}, "", false},
	}
	for _, tt := range tests {
		msg, ok := parsePushArgs(tt.rest)
		if msg != tt.msg || ok != tt.ok {
			t.Errorf("parsePushArgs(%q) = %q, %v; want %q, %v", tt.rest, msg, ok, tt.msg, tt.ok)
		}
	}
}

func TestParsePullArgs(t *testing.T) {
	tests := []struct {
		rest    []string
		version int64
		ok      bool
	}{
		{nil, 0, true},
		{[]string{"--version", "1"}, 1, true},
		{[]string{"--version", "42"}, 42, true},
		{[]string{"--version", "9223372036854775807"}, 9223372036854775807, true},
		{[]string{"--version"}, 0, false},
		{[]string{"--version", "0"}, 0, false},
		{[]string{"--version", "-1"}, 0, false},
		{[]string{"--version", "+1"}, 0, false},
		{[]string{"--version", "1.0"}, 0, false},
		{[]string{"--version", "0x10"}, 0, false},
		{[]string{"--version", " 1"}, 0, false},
		{[]string{"--version", "latest"}, 0, false},
		{[]string{"--version", "9223372036854775808"}, 0, false},
		{[]string{"--version", "1", "2"}, 0, false},
		{[]string{"-v", "1"}, 0, false},
		{[]string{"1"}, 0, false},
	}
	for _, tt := range tests {
		version, ok := parsePullArgs(tt.rest)
		if version != tt.version || ok != tt.ok {
			t.Errorf("parsePullArgs(%q) = %d, %v; want %d, %v", tt.rest, version, ok, tt.version, tt.ok)
		}
	}
}

func FuzzParseTarget(f *testing.F) {
	for _, seed := range []string{"app", "app:prod", "", ":", "a:b:c", "App", "app\n", "\x00", "-"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got, err := ParseTarget(in)
		if err != nil {
			if got != (Target{}) {
				t.Fatalf("ParseTarget(%q) returned %+v with an error", in, got)
			}
			return
		}
		// An accepted target is plain lowercase text and round-trips.
		for _, name := range []string{got.Project, got.Env} {
			if name == "" || len(name) > 63 || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
				t.Fatalf("ParseTarget(%q) accepted name %q", in, name)
			}
		}
		if in != got.String() && in != got.Project {
			t.Fatalf("ParseTarget(%q) = %+v does not round-trip", in, got)
		}
	})
}

// The argument parsers take raw client input: they must never panic, and
// what they accept must be well-formed.
func FuzzParseArgs(f *testing.F) {
	for _, seed := range []string{"", "-m fix", "-m", "--version 3", "--version", "--version -1", "x y z"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		rest := strings.Fields(line)
		if msg, ok := parsePushArgs(rest); ok && len(rest) > 0 && (rest[0] != "-m" || msg == "") {
			t.Fatalf("parsePushArgs(%q) accepted with message %q", rest, msg)
		}
		if v, ok := parsePullArgs(rest); ok && (v < 0 || (len(rest) > 0 && v == 0)) {
			t.Fatalf("parsePullArgs(%q) accepted version %d", rest, v)
		}
	})
}
