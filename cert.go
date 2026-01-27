package main

import (
	"crypto/rand"
	"crypto/rsa"
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
// A new CA is generated on every startup for security simplicity in this implementation.
func NewCertManager() (*CertManager, error) {
	cm := &CertManager{
		certCache: make(map[string]*CertPair),
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"SSL Proxy CA"},
			CommonName:   "SSL Proxy Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
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

	LogInfo("CA certificate generated: ca-cert.pem")
	LogInfo("Install this to your system trust store to prevent browser warnings.")

	return cm, nil
}

// SaveCACert writes the CA certificate to disk in PEM format.
func (cm *CertManager) SaveCACert(filename string) error {
	certFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer certFile.Close()

	return pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cm.caCert.Raw,
	})
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
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
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
