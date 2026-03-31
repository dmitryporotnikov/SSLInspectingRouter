package dashboard

import (
	"testing"
)

func TestParseBoundedInt(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		fallback int
		min      int
		max      int
		want     int
	}{
		{
			name:     "valid string within bounds",
			raw:      "5",
			fallback: 0,
			min:      1,
			max:      10,
			want:     5,
		},
		{
			name:     "valid string below min",
			raw:      "0",
			fallback: 5,
			min:      1,
			max:      10,
			want:     1,
		},
		{
			name:     "valid string above max",
			raw:      "11",
			fallback: 5,
			min:      1,
			max:      10,
			want:     10,
		},
		{
			name:     "empty string with fallback within bounds",
			raw:      "",
			fallback: 5,
			min:      1,
			max:      10,
			want:     5,
		},
		{
			name:     "invalid string with fallback within bounds",
			raw:      "abc",
			fallback: 5,
			min:      1,
			max:      10,
			want:     5,
		},
		{
			name:     "empty string with fallback below min",
			raw:      "",
			fallback: 0,
			min:      1,
			max:      10,
			want:     1,
		},
		{
			name:     "empty string with fallback above max",
			raw:      "",
			fallback: 11,
			min:      1,
			max:      10,
			want:     10,
		},
		{
			name:     "invalid string with fallback below min",
			raw:      "abc",
			fallback: 0,
			min:      1,
			max:      10,
			want:     1,
		},
		{
			name:     "invalid string with fallback above max",
			raw:      "abc",
			fallback: 11,
			min:      1,
			max:      10,
			want:     10,
		},
		{
			name:     "at min boundary",
			raw:      "1",
			fallback: 5,
			min:      1,
			max:      10,
			want:     1,
		},
		{
			name:     "at max boundary",
			raw:      "10",
			fallback: 5,
			min:      1,
			max:      10,
			want:     10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBoundedInt(tt.raw, tt.fallback, tt.min, tt.max)
			if got != tt.want {
				t.Errorf("parseBoundedInt(%q, %d, %d, %d) = %d; want %d", tt.raw, tt.fallback, tt.min, tt.max, got, tt.want)
			}
		})
	}
}
