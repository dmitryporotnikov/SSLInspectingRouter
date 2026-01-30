package main

import (
	"net"
	"strings"
)

type BlockList struct {
	set map[string]struct{}
}

func NewBlockList(entries []string) *BlockList {
	set := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		normalized := normalizeFQDN(entry)
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	return &BlockList{set: set}
}

func (b *BlockList) Count() int {
	if b == nil {
		return 0
	}
	return len(b.set)
}

func (b *BlockList) Matches(name string) bool {
	if b == nil {
		return false
	}
	normalized := normalizeFQDN(name)
	if normalized == "" {
		return false
	}
	if _, ok := b.set[normalized]; ok {
		return true
	}

	for {
		idx := strings.IndexByte(normalized, '.')
		if idx == -1 {
			break
		}
		normalized = normalized[idx+1:]
		if _, ok := b.set[normalized]; ok {
			return true
		}
	}

	return false
}

func parseDropList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := normalizeFQDN(part)
		if normalized == "" {
			continue
		}
		out = append(out, normalized)
	}
	return out
}

func normalizeFQDN(name string) string {
	trimmed := strings.TrimSpace(strings.ToLower(name))
	trimmed = strings.TrimSuffix(trimmed, ".")

	if trimmed == "" {
		return ""
	}

	if strings.Contains(trimmed, ":") && !strings.Contains(trimmed, "]") {
		if host, _, err := net.SplitHostPort(trimmed); err == nil {
			trimmed = host
		}
	}

	return trimmed
}
