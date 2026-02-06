package proxy

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

func TestExtractSNIReturnsReplayBytesWhenSNIAbsent(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientErr := make(chan error, 1)
	go func() {
		tlsConn := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
		_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
		clientErr <- tlsConn.Handshake()
	}()

	handler := &HTTPSHandler{}
	hostname, replay, err := handler.extractSNI(serverConn)
	if !errors.Is(err, errNoSNI) {
		t.Fatalf("extractSNI error = %v, want %v", err, errNoSNI)
	}
	if hostname != "" {
		t.Fatalf("hostname = %q, want empty", hostname)
	}
	if len(replay) == 0 {
		t.Fatal("replay bytes are empty")
	}

	_ = serverConn.Close()
	select {
	case <-clientErr:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for client handshake to finish")
	}
}
