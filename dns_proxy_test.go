package main

import "testing"

func TestNormalizeFQDN(t *testing.T) {
	cases := map[string]string{
		"Example.COM.": "example.com",
		" test.com ":   "test.com",
		"":             "",
	}
	for input, expected := range cases {
		if got := normalizeFQDN(input); got != expected {
			t.Fatalf("normalizeFQDN(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestParseDropList(t *testing.T) {
	got := parseDropList("Example.COM., ,test.com")
	if len(got) != 2 {
		t.Fatalf("parseDropList length = %d, want 2", len(got))
	}
	if got[0] != "example.com" || got[1] != "test.com" {
		t.Fatalf("parseDropList = %#v", got)
	}
}
