package proxy

import (
	"database/sql"
	"io"
	"net"
	"testing"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
	_ "modernc.org/sqlite"
)

func setupProxyTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE Requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			fqdn TEXT NOT NULL,
			request TEXT NOT NULL,
			content TEXT
		);
	`); err != nil {
		t.Fatalf("create requests table: %v", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE Responses (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			fqdn TEXT NOT NULL,
			response TEXT NOT NULL,
			content TEXT
		);
	`); err != nil {
		t.Fatalf("create responses table: %v", err)
	}

	original := logger.DB
	logger.DB = db
	t.Cleanup(func() {
		logger.DB = original
		_ = db.Close()
	})

	return db
}

func TestHandleBypassedTLSPausedLogsPausedStatus(t *testing.T) {
	db := setupProxyTestDB(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	upstreamDone := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 5)
		if _, readErr := io.ReadFull(conn, buf); readErr != nil {
			return
		}
		upstreamDone <- buf
	}()

	h := &HTTPSHandler{}
	clientConn, proxyConn := net.Pipe()

	reqID := logger.LogInspectionPausedRequest("10.2.3.4", "example.com")
	port := listener.Addr().(*net.TCPAddr).Port

	handlerDone := make(chan struct{})
	go func() {
		h.handleBypassedTLS(proxyConn, "example.com", "10.2.3.4", []byte("hello"), reqID, "127.0.0.1", port, tunnelLogInspectionPaused)
		close(handlerDone)
	}()

	_ = clientConn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = clientConn.Read(make([]byte, 1))
	_ = clientConn.Close()

	select {
	case data := <-upstreamDone:
		if string(data) != "hello" {
			t.Fatalf("peeked bytes = %q, want %q", string(data), "hello")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for upstream data")
	}

	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler completion")
	}

	var responseLine string
	if err := db.QueryRow(`SELECT response FROM Responses WHERE id = ?`, reqID).Scan(&responseLine); err != nil {
		t.Fatalf("read response row: %v", err)
	}
	if responseLine != "INSPECTION PAUSED" {
		t.Fatalf("response log = %q, want %q", responseLine, "INSPECTION PAUSED")
	}
}

func TestHandleBypassedTLSSNIOnlyLogsSNIStatus(t *testing.T) {
	db := setupProxyTestDB(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	upstreamDone := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 5)
		if _, readErr := io.ReadFull(conn, buf); readErr != nil {
			return
		}
		upstreamDone <- buf
	}()

	h := &HTTPSHandler{}
	clientConn, proxyConn := net.Pipe()

	metadata := "TLS Version (client): 0x0303\n"
	reqID := logger.LogSNIRequest("10.2.3.4", "example.com", metadata)
	port := listener.Addr().(*net.TCPAddr).Port

	handlerDone := make(chan struct{})
	go func() {
		h.handleBypassedTLS(proxyConn, "example.com", "10.2.3.4", []byte("hello"), reqID, "127.0.0.1", port, tunnelLogSNIOnly)
		close(handlerDone)
	}()

	_ = clientConn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = clientConn.Read(make([]byte, 1))
	_ = clientConn.Close()

	select {
	case data := <-upstreamDone:
		if string(data) != "hello" {
			t.Fatalf("peeked bytes = %q, want %q", string(data), "hello")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for upstream data")
	}

	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for handler completion")
	}

	var requestLine, responseLine, storedContent string
	if err := db.QueryRow(`SELECT r.request, COALESCE(res.response, ''), r.content FROM Requests r LEFT JOIN Responses res ON r.id = res.id WHERE r.id = ?`, reqID).Scan(&requestLine, &responseLine, &storedContent); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if requestLine != "SNI-ONLY" {
		t.Fatalf("request = %q, want %q", requestLine, "SNI-ONLY")
	}
	if responseLine != "SNI-ONLY" {
		t.Fatalf("response = %q, want %q", responseLine, "SNI-ONLY")
	}
	if storedContent != metadata {
		t.Fatalf("stored metadata = %q, want %q", storedContent, metadata)
	}
}
