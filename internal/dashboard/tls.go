package dashboard

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	defaultDashboardCertFilename = "dashboard-cert.pem"
	defaultDashboardKeyFilename  = "dashboard-key.pem"
)

func ensureDashboardTLSCert(certFile, keyFile string) (string, string, error) {
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)

	if certFile == "" {
		certFile = resolveDashboardTLSPath(defaultDashboardCertFilename)
	}
	if keyFile == "" {
		keyFile = resolveDashboardTLSPath(defaultDashboardKeyFilename)
	}

	if fileExists(certFile) && fileExists(keyFile) {
		return certFile, keyFile, nil
	}

	if err := generateDashboardSelfSignedCert(certFile, keyFile); err != nil {
		return "", "", err
	}

	return certFile, keyFile, nil
}

func resolveDashboardTLSPath(fileName string) string {
	path := filepath.Join("logs", fileName)
	if exePath, err := os.Executable(); err == nil {
		path = filepath.Join(filepath.Dir(exePath), "logs", fileName)
	}
	return path
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func generateDashboardSelfSignedCert(certFile, keyFile string) error {
	if err := os.MkdirAll(filepath.Dir(certFile), 0755); err != nil {
		return fmt.Errorf("create dashboard cert dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0755); err != nil {
		return fmt.Errorf("create dashboard key dir: %w", err)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate dashboard key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate dashboard serial: %w", err)
	}

	dnsNames, ipSANs := collectDashboardSANs()
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "SSLInspectingRouter Dashboard",
			Organization: []string{"SSLInspectingRouter"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ipSANs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("create dashboard certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("write dashboard certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal dashboard key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("write dashboard key: %w", err)
	}

	return nil
}

func collectDashboardSANs() ([]string, []net.IP) {
	dnsSet := map[string]struct{}{
		"localhost": {},
	}
	ipSet := map[string]net.IP{}

	for _, literalIP := range []string{"127.0.0.1", "::1"} {
		if ip := net.ParseIP(literalIP); ip != nil {
			ipSet[ip.String()] = ip
		}
	}

	if hostname, err := os.Hostname(); err == nil {
		hostname = strings.TrimSpace(hostname)
		if hostname != "" && net.ParseIP(hostname) == nil {
			dnsSet[hostname] = struct{}{}
		}
	}

	if interfaces, err := net.Interfaces(); err == nil {
		for _, iface := range interfaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch value := addr.(type) {
				case *net.IPNet:
					ip = value.IP
				case *net.IPAddr:
					ip = value.IP
				}
				if ip == nil {
					continue
				}
				ip = ip.To16()
				if ip == nil {
					continue
				}
				ipSet[ip.String()] = ip
			}
		}
	}

	dnsNames := make([]string, 0, len(dnsSet))
	for host := range dnsSet {
		dnsNames = append(dnsNames, host)
	}
	sort.Strings(dnsNames)

	ips := make([]net.IP, 0, len(ipSet))
	for _, ip := range ipSet {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return bytesCompare(ips[i], ips[j]) < 0
	})

	return dnsNames, ips
}

func bytesCompare(a, b []byte) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
