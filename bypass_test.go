package main

import (
	"crypto/tls"
	"database/sql"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func setupInMemoryTrafficDB(t *testing.T) *sql.DB {
	t.Helper()

	testDB, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}

	if _, err := testDB.Exec(`
		CREATE TABLE Requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			fqdn TEXT NOT NULL,
			request TEXT NOT NULL,
			content TEXT
		);
	`); err != nil {
		t.Fatalf("failed to create Requests table: %v", err)
	}

	if _, err := testDB.Exec(`
		CREATE TABLE Responses (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			fqdn TEXT NOT NULL,
			response TEXT NOT NULL,
			content TEXT
		);
	`); err != nil {
		t.Fatalf("failed to create Responses table: %v", err)
	}

	previous := db
	db = testDB
	t.Cleanup(func() {
		db = previous
		testDB.Close()
	})

	return testDB
}

func TestHTTPBypassLogsBypassed(t *testing.T) {
	testDB := setupInMemoryTrafficDB(t)

	handler := NewHTTPHandler(nil, NewBlockList([]string{"example.com"}))
	handler.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/test", strings.NewReader("payload"))
	req.RemoteAddr = "10.2.3.4:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusOK)
	}

	var requestLine string
	if err := testDB.QueryRow(`SELECT request FROM Requests ORDER BY id DESC LIMIT 1`).Scan(&requestLine); err != nil {
		t.Fatalf("failed to read request log row: %v", err)
	}
	if requestLine != "BYPASSED" {
		t.Fatalf("request log = %q, want BYPASSED", requestLine)
	}

	var responseLine string
	if err := testDB.QueryRow(`SELECT response FROM Responses ORDER BY id DESC LIMIT 1`).Scan(&responseLine); err != nil {
		t.Fatalf("failed to read response log row: %v", err)
	}
	if responseLine != "BYPASSED" {
		t.Fatalf("response log = %q, want BYPASSED", responseLine)
	}
}

func TestHTTPSBypassSkipsCertGeneration(t *testing.T) {
	cm := &CertManager{
		certCache: make(map[string]*CertPair),
	}

	handler := NewHTTPSHandler(cm, nil, NewBlockList([]string{"localhost"}))
	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})

	go func() {
		handler.HandleConnection(serverConn)
		close(done)
	}()

	tlsConn := tls.Client(clientConn, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = tlsConn.Handshake()
	_ = tlsConn.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for bypass handler")
	}

	if len(cm.certCache) != 0 {
		t.Fatalf("cert cache size = %d, want 0", len(cm.certCache))
	}
}
