package cert

import (
	"net"
	"os"
	"testing"
)

func TestGetCertificateForHostAddsIPSANForIPAddress(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	tempDir := t.TempDir()
	if err := os.Chdir(tempDir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})

	cm, err := NewCertManager(true)
	if err != nil {
		t.Fatalf("NewCertManager failed: %v", err)
	}

	targetIP := net.ParseIP("188.225.32.161")
	if targetIP == nil {
		t.Fatal("failed to parse test IP")
	}

	pair, err := cm.GetCertificateForHost(targetIP.String())
	if err != nil {
		t.Fatalf("GetCertificateForHost failed: %v", err)
	}

	if len(pair.Cert.IPAddresses) != 1 || !pair.Cert.IPAddresses[0].Equal(targetIP) {
		t.Fatalf("IP SANs = %v, want [%s]", pair.Cert.IPAddresses, targetIP.String())
	}
	if len(pair.Cert.DNSNames) != 0 {
		t.Fatalf("DNS SANs = %v, want empty", pair.Cert.DNSNames)
	}
}
