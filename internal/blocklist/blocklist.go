package blocklist

import (
	"net"
	"strings"
)

type BlockList struct {
	domains map[string]struct{}
	ips     map[string]struct{}
	cidrs   []*net.IPNet
}

func NewBlockList(entries []string) *BlockList {
	domains := make(map[string]struct{})
	ips := make(map[string]struct{})
	var cidrs []*net.IPNet

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// Check for CIDR
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err == nil {
				cidrs = append(cidrs, ipNet)
				continue
			}
		}

		// Check for specific IP
		if ip := net.ParseIP(entry); ip != nil {
			// Store IP as string representation for exact matching
			ips[ip.String()] = struct{}{}
			continue
		}

		// Fallback to domain
		normalized := NormalizeFQDN(entry)
		if normalized != "" {
			domains[normalized] = struct{}{}
		}
	}

	if len(domains) == 0 && len(ips) == 0 && len(cidrs) == 0 {
		return nil
	}

	return &BlockList{
		domains: domains,
		ips:     ips,
		cidrs:   cidrs,
	}
}

func (b *BlockList) GetIPs() []string {
	if b == nil {
		return nil
	}
	out := make([]string, 0, len(b.ips))
	for ip := range b.ips {
		out = append(out, ip)
	}
	return out
}

func (b *BlockList) GetCIDRs() []string {
	if b == nil {
		return nil
	}
	out := make([]string, 0, len(b.cidrs))
	for _, cidr := range b.cidrs {
		out = append(out, cidr.String())
	}
	return out
}

func (b *BlockList) Count() int {
	if b == nil {
		return 0
	}
	return len(b.domains) + len(b.ips) + len(b.cidrs)
}

func (b *BlockList) Matches(name string) bool {
	if b == nil {
		return false
	}

	// Check if input is an IP
	if ip := net.ParseIP(name); ip != nil {
		// 1. Exact IP match
		if _, ok := b.ips[ip.String()]; ok {
			return true
		}
		// 2. CIDR match
		for _, subnet := range b.cidrs {
			if subnet.Contains(ip) {
				return true
			}
		}
		// If it's an IP, we don't check domain rules
		return false
	}

	// Domain matching
	normalized := NormalizeFQDN(name)
	if normalized == "" {
		return false
	}
	if _, ok := b.domains[normalized]; ok {
		return true
	}

	for {
		idx := strings.IndexByte(normalized, '.')
		if idx == -1 {
			break
		}
		normalized = normalized[idx+1:]
		if _, ok := b.domains[normalized]; ok {
			return true
		}
	}

	return false
}

func ParseDropList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := NormalizeFQDN(part)
		if normalized == "" {
			continue
		}
		out = append(out, normalized)
	}
	return out
}

func NormalizeFQDN(name string) string {
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
