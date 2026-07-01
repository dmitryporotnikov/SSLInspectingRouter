package tests

import (
	"testing"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/blocklist"
)

func TestBlockListMatches(t *testing.T) {
	bl := blocklist.NewBlockList([]string{"example.com", "test.com"})
	if bl == nil {
		t.Fatal("block list is nil")
	}

	tests := map[string]bool{
		"example.com":         true,
		"www.example.com":     true,
		"sub.www.example.com": true,
		"test.com":            true,
		"api.test.com":        true,
		"notexample.com":      false,
		"example.org":         false,
	}

	for host, expected := range tests {
		if got := bl.Matches(host); got != expected {
			t.Fatalf("Matches(%q) = %v, want %v", host, got, expected)
		}
	}
}
