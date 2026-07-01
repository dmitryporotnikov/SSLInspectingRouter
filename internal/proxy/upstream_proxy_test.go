package proxy

import (
	"testing"
	"time"
)

func TestNormalizeSOCKS5Address(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "ipv4",
			input: "127.0.0.1:9050",
			want:  "127.0.0.1:9050",
		},
		{
			name:  "ipv6",
			input: "[::1]:9050",
			want:  "[::1]:9050",
		},
		{
			name:    "missing port",
			input:   "127.0.0.1",
			wantErr: true,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeSOCKS5Address(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (value=%q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildSOCKS5Dialer(t *testing.T) {
	dialer, addr, err := buildSOCKS5Dialer("127.0.0.1:9050", 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dialer == nil {
		t.Fatal("dialer is nil")
	}
	if addr != "127.0.0.1:9050" {
		t.Fatalf("address = %q, want %q", addr, "127.0.0.1:9050")
	}
}
