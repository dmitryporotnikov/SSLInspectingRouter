package main

import (
	"reflect"
	"testing"
)

func TestParseAdditionalPorts(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{
			name:  "empty",
			input: "",
			want:  nil,
		},
		{
			name:  "valid sorted unique",
			input: "9443, 8443,9443,443,80, 10443",
			want:  []int{8443, 9443, 10443},
		},
		{
			name:    "invalid token",
			input:   "8443,abc",
			wantErr: true,
		},
		{
			name:    "out of range",
			input:   "70000",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAdditionalPorts(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (ports=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ports = %v, want %v", got, tc.want)
			}
		})
	}
}
