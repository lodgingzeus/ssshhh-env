package sanitize

import "testing"

func TestText(t *testing.T) {
	tests := []struct {
		in   string
		max  int
		want string
	}{
		{"plain", 10, "plain"},
		{"too long", 3, "too"},
		{"line1\nline2\r\tend", 50, "line1line2end"},
		{"\x1b[31mred\x1b[0m", 50, "[31mred[0m"},
		{"nul\x00byte", 50, "nulbyte"},
		{"bad\xffutf8", 50, "badutf8"},
		{"rtl\u202eoverride", 50, "rtloverride"},
		{"héllo wörld", 5, "héllo"},
		{"", 5, ""},
	}
	for _, tt := range tests {
		if got := Text(tt.in, tt.max); got != tt.want {
			t.Errorf("Text(%q, %d) = %q, want %q", tt.in, tt.max, got, tt.want)
		}
	}
}
