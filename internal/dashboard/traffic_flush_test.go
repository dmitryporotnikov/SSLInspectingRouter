package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openDashboardTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "dashboard.db")
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL", dbPath))
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})
	if err := db.Ping(); err != nil {
		t.Fatalf("ping sqlite db: %v", err)
	}
	return db
}

func seedTrafficTables(t *testing.T, db *sql.DB) {
	t.Helper()

	stmts := []string{
		`CREATE TABLE Requests (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, fqdn TEXT, request TEXT, content TEXT)`,
		`CREATE TABLE Responses (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, fqdn TEXT, response TEXT, content TEXT)`,
		`CREATE TABLE Users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL)`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	if _, err := db.Exec(`INSERT INTO Requests (timestamp, source_ip, fqdn, request, content) VALUES ('t1', '192.0.2.5', 'example.com', 'GET /', 'req')`); err != nil {
		t.Fatalf("insert request: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO Responses (timestamp, source_ip, fqdn, response, content) VALUES ('t1', '192.0.2.5', 'example.com', '200 OK', 'res')`); err != nil {
		t.Fatalf("insert response: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO Users (username) VALUES ('admin')`); err != nil {
		t.Fatalf("insert user: %v", err)
	}
}

func dashboardCountRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()

	var count int
	if err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count); err != nil {
		t.Fatalf("count rows in %s: %v", table, err)
	}
	return count
}

func TestHandleTrafficDeleteRequiresAdmin(t *testing.T) {
	db := openDashboardTestDB(t)
	seedTrafficTables(t, db)

	s := &Server{db: db}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/traffic", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextUserKey, &DashboardUser{
		ID:   2,
		Role: "viewer",
	}))
	recorder := httptest.NewRecorder()

	s.handleTraffic(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if got := dashboardCountRows(t, db, "Requests"); got != 1 {
		t.Fatalf("requests rows = %d, want 1", got)
	}
	if got := dashboardCountRows(t, db, "Responses"); got != 1 {
		t.Fatalf("responses rows = %d, want 1", got)
	}
}

func TestHandleTrafficDeleteFlushesTraffic(t *testing.T) {
	db := openDashboardTestDB(t)
	seedTrafficTables(t, db)

	s := &Server{db: db}
	s.lastRequestCount.Store(10)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/traffic", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextUserKey, &DashboardUser{
		ID:   1,
		Role: "admin",
	}))
	recorder := httptest.NewRecorder()

	s.handleTraffic(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if ok, _ := payload["ok"].(bool); !ok {
		t.Fatalf("response ok flag = %v, want true", payload["ok"])
	}

	if got := dashboardCountRows(t, db, "Requests"); got != 0 {
		t.Fatalf("requests rows = %d, want 0", got)
	}
	if got := dashboardCountRows(t, db, "Responses"); got != 0 {
		t.Fatalf("responses rows = %d, want 0", got)
	}
	if got := dashboardCountRows(t, db, "Users"); got != 1 {
		t.Fatalf("users rows = %d, want 1", got)
	}
	if got := s.lastRequestCount.Load(); got != 0 {
		t.Fatalf("lastRequestCount = %d, want 0", got)
	}
}
