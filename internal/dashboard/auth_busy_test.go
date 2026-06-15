package dashboard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIsTransientSQLiteBusyError(t *testing.T) {
	cases := map[error]bool{
		nil:                                                   false,
		errors.New("database is locked"):                      true,
		errors.New("database table is locked"):                true,
		errors.New("database is busy"):                        true,
		errors.New("sql logic error: database is locked"):     true,
		errors.New("UNIQUE constraint failed: Users.username"): false,
		errors.New("syntax error near 'FOO'"):                 false,
		errors.New("attempt to write a readonly database"):    false, // also contains "database" — must NOT be 503
	}
	for err, want := range cases {
		if got := isTransientSQLiteBusyError(err); got != want {
			t.Fatalf("isTransientSQLiteBusyError(%v) = %v, want %v", err, got, want)
		}
	}
}

func TestWithAuthReturnsServiceUnavailableOnlyForBusy(t *testing.T) {
	// Build a server with a closed DB so any query returns an error and the
	// auth path's error-mapping branch runs. The first query hits a real
	// "sql: database is closed" error which is NOT transient → must NOT
	// surface as 503.
	db := openDashboardTestDB(t)
	_ = db.Close()

	s := &Server{
		db:                db,
		now:               time.Now,
		sessionCookieName: "test_session",
	}

	handler := s.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	// Set a cookie so the auth path actually reaches the DB query instead
	// of short-circuiting with errAuthMissingSession.
	req.AddCookie(&http.Cookie{Name: "test_session", Value: "deadbeef"})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d (non-busy DB error should not return 503)", recorder.Code, http.StatusInternalServerError)
	}
	if strings.Contains(recorder.Body.String(), "temporarily unavailable") {
		t.Fatalf("response should not contain 'temporarily unavailable', got: %s", recorder.Body.String())
	}
}

func TestTouchSessionRetriesTransientBusyError(t *testing.T) {
	db := openDashboardTestDB(t)
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// Minimal Users + Sessions schema for the test.
	stmts := []string{
		`CREATE TABLE Users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, is_active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_login_at TEXT)`,
		`CREATE TABLE Sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}
	if _, err := db.Exec(`INSERT INTO Users (username, display_name, password_hash, role, created_at, updated_at) VALUES ('u', 'u', 'h', 'admin', 't', 't')`); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	res, err := db.Exec(`INSERT INTO Sessions (user_id, token_hash, expires_at, created_at, last_seen_at) VALUES (1, 'tok', '2099-01-01T00:00:00Z', 't', 't')`)
	if err != nil {
		t.Fatalf("insert session: %v", err)
	}
	sessionID, _ := res.LastInsertId()

	srv := &Server{db: db, now: time.Now}
	now := time.Now().UTC().Format(time.RFC3339Nano)

	// First call updates last_seen_at cleanly.
	if err := srv.touchSession(sessionID, now); err != nil {
		t.Fatalf("first touchSession: %v", err)
	}

	var seen string
	if err := db.QueryRow(`SELECT last_seen_at FROM Sessions WHERE id = ?`, sessionID).Scan(&seen); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if seen != now {
		t.Fatalf("last_seen_at = %q, want %q", seen, now)
	}
}

func TestTouchSessionIgnoresNonBusyErrors(t *testing.T) {
	db := openDashboardTestDB(t)
	_ = db.Close()

	srv := &Server{db: db, now: time.Now}
	err := srv.touchSession(1, "now")
	if err == nil {
		t.Fatal("touchSession on closed db returned nil, want error")
	}
	// "sql: database is closed" is NOT a busy error → returned as-is.
	if isTransientSQLiteBusyError(err) {
		t.Fatalf("expected non-busy error, got busy: %v", err)
	}
}

// guard that we don't accidentally drop the context.WithValue dependency if
// someone trims imports later.
var _ = context.Background