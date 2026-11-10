// Package sanitize makes client-supplied text safe to store and to print
// to someone else's terminal.
package sanitize

import (
	"strings"
	"unicode"
)

// Text removes invalid UTF-8, control characters (including newlines and
// terminal escapes) and invisible format characters from s, then cuts the
// result to at most max runes.
func Text(s string, max int) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == max {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
