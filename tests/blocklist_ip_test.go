package tests

import (
	"testing"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/blocklist"
)

func TestBlockListIPs(t *testing.T) {
	// Mixed list: domains, exact IPv4, exact IPv6, CIDR
	entries := []string{
		"example.com",
		"192.168.1.5",
		"10.0.0.0/24",
		"2001:db8::1",
	}

	bl := blocklist.NewBlockList(entries)
	if bl == nil {
		t.Fatal("NewBlockList returned nil")
	}

	tests := []struct {
		input    string
		expected bool
	}{
		// Domain checks
		{"example.com", true},
		{"sub.example.com", true},
		{"google.com", false},

		// IP checks
		{"192.168.1.5", true},  // Exact match
		{"192.168.1.6", false}, // Miss
		{"10.0.0.50", true},    // CIDR match
		{"10.0.0.1", true},     // CIDR match
		{"10.0.1.1", false},    // CIDR miss
		{"2001:db8::1", true},  // IPv6 exact match
		{"2001:db8::2", false}, // IPv6 miss
		{"127.0.0.1", false},   // Loopback miss
	}

	for _, tc := range tests {
		if got := bl.Matches(tc.input); got != tc.expected {
			t.Errorf("Matches(%q) = %v; want %v", tc.input, got, tc.expected)
		}
	}
}
