// Package envfile validates .env files and extracts their variable names.
//
// It never interprets values and never changes the file: what is pushed is
// stored and pulled back byte for byte. Its errors name a line number and a
// fixed reason only, never any of the file's content.
package envfile

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"unicode/utf8"
)

// MaxSize is the largest .env file accepted, in bytes.
const MaxSize = 256 << 10

// maxNameLen caps the length of a variable name.
const maxNameLen = 256

// Errors for files refused as a whole.
var (
	ErrTooLarge = fmt.Errorf("file is larger than %d KB", MaxSize>>10)
	ErrNotUTF8  = errors.New("file is not valid UTF-8 text")
	ErrNUL      = errors.New("file contains a NUL byte")
	ErrEmpty    = errors.New("file has no variables")
	ErrBOM      = errors.New("file starts with a UTF-8 byte order mark (BOM); save it as UTF-8 without BOM")
)

// bom is the UTF-8 byte order mark some editors put at the start of a file.
var bom = []byte("\xEF\xBB\xBF")

// SyntaxError reports a line that is not a comment, blank or KEY=VALUE.
type SyntaxError struct {
	Line   int // 1-based
	Reason string
}

func (e *SyntaxError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Reason) }

// Parse validates data as an .env file and returns its variable names,
// sorted. Accepted lines are blank lines, # comments and KEY=VALUE, with an
// optional leading "export". A value that starts with a quote runs to the
// matching closing quote, which may be on a later line. Anything else is
// refused, as are duplicate names and files with no variables at all.
func Parse(data []byte) ([]string, error) {
	entries, err := scan(data)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.name)
	}
	slices.Sort(names)
	return names, nil
}

// entry is one variable: its name and the raw text of its value. A quoted
// value includes its quotes; trailing comments after them are not part of
// it.
type entry struct {
	name  string
	value []byte
}

// scan validates data and returns its variables in file order. It is the
// only parser: Parse and Diff both use it.
func scan(data []byte) ([]entry, error) {
	switch {
	case len(data) > MaxSize:
		return nil, ErrTooLarge
	case bytes.IndexByte(data, 0) >= 0:
		return nil, ErrNUL
	case !utf8.Valid(data):
		return nil, ErrNotUTF8
	case bytes.HasPrefix(data, bom):
		// Refused, not stripped: bytes are stored verbatim, and a BOM
		// pulled into another tool would corrupt the first variable name.
		return nil, ErrBOM
	}

	lines := bytes.Split(data, []byte("\n"))
	seen := map[string]bool{}
	var entries []entry
	for i := 0; i < len(lines); i++ {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		name, value, ok := splitAssignment(line)
		if !ok {
			return nil, &SyntaxError{Line: i + 1, Reason: "expected KEY=VALUE"}
		}
		if !validName(name) {
			return nil, &SyntaxError{Line: i + 1, Reason: "invalid variable name"}
		}
		if seen[string(name)] {
			return nil, &SyntaxError{Line: i + 1, Reason: "variable is set more than once"}
		}
		seen[string(name)] = true

		if len(value) > 0 && (value[0] == '"' || value[0] == '\'') {
			end, quoted, err := skipQuoted(lines, i, value)
			if err != nil {
				return nil, err
			}
			i, value = end, quoted
		}
		entries = append(entries, entry{name: string(name), value: value})
	}
	if len(entries) == 0 {
		return nil, ErrEmpty
	}
	return entries, nil
}

// splitAssignment splits a trimmed line into the name and the value, with
// the whitespace around "=" removed.
func splitAssignment(line []byte) (name, value []byte, ok bool) {
	if rest, found := bytes.CutPrefix(line, []byte("export")); found && len(rest) > 0 && isBlank(rest[0]) {
		line = bytes.TrimLeft(rest, " \t")
	}
	name, value, ok = bytes.Cut(line, []byte("="))
	if !ok {
		return nil, nil, false
	}
	return bytes.TrimRight(name, " \t"), bytes.TrimLeft(value, " \t"), true
}

// validName reports whether b is a variable name: a letter or underscore,
// then letters, digits, '_', '.' or '-'.
func validName(b []byte) bool {
	if len(b) == 0 || len(b) > maxNameLen {
		return false
	}
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c == '_':
		case i > 0 && (c >= '0' && c <= '9' || c == '.' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// skipQuoted finds the end of a quoted value that starts on lines[start]
// with value. It returns the index of the line holding the closing quote
// and the value's text from the opening quote to the closing one. Inside
// double quotes a backslash escapes the next character; single quotes have
// no escapes. Only a comment may follow the closing quote.
func skipQuoted(lines [][]byte, start int, value []byte) (int, []byte, error) {
	quote := value[0]
	rest := value[1:]
	for i := start; ; i++ {
		if i > start {
			rest = lines[i]
		}
		if end := closingQuote(rest, quote); end >= 0 {
			tail := bytes.TrimSpace(rest[end+1:])
			if len(tail) > 0 && tail[0] != '#' {
				return 0, nil, &SyntaxError{Line: i + 1, Reason: "unexpected text after the closing quote"}
			}
			return i, quotedText(lines, start, i, value, end), nil
		}
		if i == len(lines)-1 {
			return 0, nil, &SyntaxError{Line: start + 1, Reason: "quote is never closed"}
		}
	}
}

// quotedText joins a quoted value that opens on lines[start] (as value)
// and closes at index end of lines[last] (index end+1 of value if last is
// start, since value still holds the opening quote).
func quotedText(lines [][]byte, start, last int, value []byte, end int) []byte {
	if last == start {
		return value[:end+2]
	}
	parts := [][]byte{value}
	parts = append(parts, lines[start+1:last]...)
	parts = append(parts, lines[last][:end+1])
	return bytes.Join(parts, []byte("\n"))
}

// closingQuote returns the index of the first unescaped quote in b, or -1.
// A backslash at the end of b escapes the line break, so the value goes on.
func closingQuote(b []byte, quote byte) int {
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '\\' && quote == '"':
			i++
		case b[i] == quote:
			return i
		}
	}
	return -1
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }
