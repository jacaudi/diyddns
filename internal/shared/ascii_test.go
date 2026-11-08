package shared

import (
	"strings"
	"testing"
)

func TestPrintableASCII(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		maxLen int
		want   bool
	}{
		{"empty", "", 128, true},
		{"printable edges", " ~", 128, true},
		{"at the bound", strings.Repeat("a", 128), 128, true},
		{"over the bound", strings.Repeat("a", 129), 128, false},
		{"control byte", "a\x1fb", 128, false},
		{"DEL", "a\x7fb", 128, false},
		{"CR LF", "a\r\nb", 128, false},
		{"non-ASCII", "café", 128, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PrintableASCII(tt.s, tt.maxLen); got != tt.want {
				t.Errorf("PrintableASCII(%q, %d) = %v, want %v", tt.s, tt.maxLen, got, tt.want)
			}
		})
	}
}
