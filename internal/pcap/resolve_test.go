package pcap

import (
	"testing"
)

func TestResolveFakeIP(t *testing.T) {
	fqdn := "example.com"
	ip1 := resolveFakeIP(fqdn)
	ip2 := resolveFakeIP(fqdn)

	if !ip1.Equal(ip2) {
		t.Errorf("Expected consistent IP for %s, got %v and %v", fqdn, ip1, ip2)
	}

	// ip1.To4() ensures we are dealing with 4-byte representation if it's an IPv4
	ip4 := ip1.To4()
	if ip4 == nil {
		t.Fatalf("Expected IPv4 address, got %v", ip1)
	}

	if ip4[0] != 10 || ip4[1] != 200 {
		t.Errorf("Expected IP in 10.200.0.0/16 range, got %v", ip4)
	}

	fqdn2 := "google.com"
	ip3 := resolveFakeIP(fqdn2)
	if ip1.Equal(ip3) {
		t.Errorf("Expected different IPs for %s and %s, both got %v", fqdn, fqdn2, ip1)
	}
}
