package tests

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/cert"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/proxy"
)

// TestTLSHandshakeFix verifies that the server can complete a TLS handshake
// even after extractSNI has consumed the ClientHello.
func TestTLSHandshakeFix(t *testing.T) {
	// 1. Setup CertManager
	cm, err := cert.NewCertManager(true)
	if err != nil {
		t.Fatalf("Failed to create CertManager: %v", err)
	}

	// 2. Setup HTTPSHandler
	handler := proxy.NewHTTPSHandler(cm, nil, nil)

	// 3. Start a listener to simulate the transparent proxy intercept
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	serverErrChan := make(chan error, 1)

	// 4. Run HandleConnection in a goroutine
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErrChan <- fmt.Errorf("Accept failed: %v", err)
			return
		}
		// We can't easily hook into HandleConnection's internal errors or success without changing code,
		// but if the handshake fails, the client will see it.
		// If the handshake succeeds, the client will get a connection.
		// However, HandleConnection will try to connect upstream.
		// We can mock the upstream connection failure, but we primarily care about the handshake part.
		// If handshake fails, the client sees an EOF or alert.
		handler.HandleConnection(conn)
		serverErrChan <- nil
	}()

	// 5. Client connects to the listener
	// We use a real TLS client to send ClientHello with SNI
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	clientConfig := &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true, // We validate the handshake, not the certificate trust chain
	}
	tlsConn := tls.Client(conn, clientConfig)

	// 6. Perform Handshake
	// If the fix works, this should succeed.
	// If the fix is broken (bytes consumed and not replayed), this will hang or fail.
	// Set a deadline to avoid hanging forever
	tlsConn.SetDeadline(time.Now().Add(2 * time.Second))

	err = tlsConn.Handshake()
	if err != nil {
		if strings.Contains(err.Error(), "EOF") {
			t.Fatalf("Handshake failed with EOF (Likely the SNI consumption bug): %v", err)
		}
		t.Fatalf("Handshake failed: %v", err)
	}

	t.Log("TLS Handshake successful!")
	tlsConn.Close()
}
