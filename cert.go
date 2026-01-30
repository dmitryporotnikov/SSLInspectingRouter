package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// CertManager handles the creation and storage of the Root CA and dynamic host certificates.
type CertManager struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	certCache  map[string]*CertPair
	cacheMutex sync.RWMutex
}

// CertPair contains a public certificate and its corresponding private key.
type CertPair struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// NewCertManager initializes the Certificate Authority (CA) and prepares the certificate cache.
// If forceNew is true, a new CA is generated and replaces any existing files.
func NewCertManager(forceNew bool) (*CertManager, error) {
	cm := &CertManager{
		certCache: make(map[string]*CertPair),
	}

	if !forceNew {
		if err := cm.loadCA("ca-cert.pem", "ca-key.pem"); err == nil {
			LogInfo("Loaded existing CA certificate and key.")
			LogInfo("Install ca-cert.pem to your system trust store to prevent browser warnings.")
			return cm, nil
		}
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %v", err)
	}

	caKeyID, err := subjectKeyID(&caKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute CA key id: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SSL Proxy CA"},
			CommonName:   "SSL Proxy Root CA",
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		SubjectKeyId:          caKeyID,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	cm.caCert = caCert
	cm.caKey = caKey

	if err := cm.SaveCACert("ca-cert.pem"); err != nil {
		return nil, fmt.Errorf("failed to save CA certificate: %v", err)
	}
	if err := cm.SaveCAKey("ca-key.pem"); err != nil {
		return nil, fmt.Errorf("failed to save CA key: %v", err)
	}

	LogInfo("CA certificate generated: ca-cert.pem")
	LogInfo("CA private key stored: ca-key.pem")
	LogInfo("Install this to your system trust store to prevent browser warnings.")

	return cm, nil
}

// SaveCACert writes the CA certificate to disk in PEM format.
func (cm *CertManager) SaveCACert(filename string) error {
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cm.caCert.Raw,
	})
	return os.WriteFile(filename, data, 0644)
}

// SaveCAKey writes the CA private key to disk in PEM format.
func (cm *CertManager) SaveCAKey(filename string) error {
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cm.caKey),
	})
	return os.WriteFile(filename, data, 0600)
}

func (cm *CertManager) loadCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("invalid CA key PEM")
	}
	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}

	cm.caCert = caCert
	cm.caKey = caKey
	return nil
}

// GetCertificateForHost returns a valid certificate for the specific hostname.
// If one exists in cache, it is returned. Otherwise, a new one is dynamically signed by the internal CA.
func (cm *CertManager) GetCertificateForHost(hostname string) (*CertPair, error) {
	cm.cacheMutex.RLock()
	if certPair, exists := cm.certCache[hostname]; exists {
		cm.cacheMutex.RUnlock()
		return certPair, nil
	}
	cm.cacheMutex.RUnlock()

	cm.cacheMutex.Lock()
	defer cm.cacheMutex.Unlock()

	// Double-checked locking
	if certPair, exists := cm.certCache[hostname]; exists {
		return certPair, nil
	}

	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate host key: %v", err)
	}

	hostKeyID, err := subjectKeyID(&hostKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute host key id: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %v", err)
	}

	hostTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SSL Proxy"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
		SubjectKeyId:          hostKeyID,
		AuthorityKeyId:        cm.caCert.SubjectKeyId,
	}

	hostCertDER, err := x509.CreateCertificate(rand.Reader, hostTemplate, cm.caCert, &hostKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create host certificate: %v", err)
	}

	hostCert, err := x509.ParseCertificate(hostCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host certificate: %v", err)
	}

	certPair := &CertPair{
		Cert: hostCert,
		Key:  hostKey,
	}

	cm.certCache[hostname] = certPair
	LogDebug(fmt.Sprintf("Certificate generated for: %s", hostname))

	return certPair, nil
}

func (cm *CertManager) GetCACert() *x509.Certificate {
	return cm.caCert
}

func (cm *CertManager) GetCAKey() *rsa.PrivateKey {
	return cm.caKey
}

func subjectKeyID(pub *rsa.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki)
	return sum[:], nil
}
