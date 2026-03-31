package logger

import (
	"net/http"
	"testing"
)

func TestTrafficLoggingToggleSkipsDBWrites(t *testing.T) {
	db := openTestSQLite(t)

	schema := []string{
		`CREATE TABLE Requests (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, fqdn TEXT, request TEXT, content TEXT)`,
		`CREATE TABLE Responses (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, fqdn TEXT, response TEXT, content TEXT)`,
	}
	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	originalDB := DB
	originalLogging := IsTrafficLoggingEnabled()
	DB = db
	SetTrafficLogging(true)
	t.Cleanup(func() {
		DB = originalDB
		SetTrafficLogging(originalLogging)
	})

	reqID := LogHTTPRequest("192.0.2.10", "example.com", "GET", "http://example.com/", http.Header{}, []byte("hello"))
	if reqID <= 0 {
		t.Fatalf("request id = %d, want > 0", reqID)
	}
	LogHTTPResponse(ResponseLogEntry{
		ReqID:       reqID,
		SourceIP:    "192.0.2.10",
		FQDN:        "example.com",
		Status:      "200 OK",
		Headers:     http.Header{},
		BodyPreview: []byte("ok"),
		Truncated:   false,
	})

	if got := countRows(t, db, "Requests"); got != 1 {
		t.Fatalf("requests rows = %d, want 1", got)
	}
	if got := countRows(t, db, "Responses"); got != 1 {
		t.Fatalf("responses rows = %d, want 1", got)
	}

	SetTrafficLogging(false)
	disabledReqID := LogHTTPRequest("192.0.2.11", "example.org", "GET", "http://example.org/", http.Header{}, []byte("hello"))
	if disabledReqID != 0 {
		t.Fatalf("request id with logging disabled = %d, want 0", disabledReqID)
	}
	LogHTTPResponse(ResponseLogEntry{
		ReqID:       disabledReqID,
		SourceIP:    "192.0.2.11",
		FQDN:        "example.org",
		Status:      "200 OK",
		Headers:     http.Header{},
		BodyPreview: []byte("ok"),
		Truncated:   false,
	})
	LogBypassedRequest("192.0.2.12", "bypass.test")
	LogBypassedResponse(0, "192.0.2.12", "bypass.test")

	if got := countRows(t, db, "Requests"); got != 1 {
		t.Fatalf("requests rows after disabled logging = %d, want 1", got)
	}
	if got := countRows(t, db, "Responses"); got != 1 {
		t.Fatalf("responses rows after disabled logging = %d, want 1", got)
	}
}
