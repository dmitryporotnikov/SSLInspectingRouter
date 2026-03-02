package logger

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func openTestSQLite(t *testing.T) *sql.DB {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "traffic.db")
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

func countRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()

	var count int
	if err := db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count); err != nil {
		t.Fatalf("count rows in %s: %v", table, err)
	}
	return count
}

func TestWipeTrafficTablesPreservesNonTrafficTables(t *testing.T) {
	db := openTestSQLite(t)

	schema := []string{
		`CREATE TABLE Requests (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, fqdn TEXT, request TEXT, content TEXT)`,
		`CREATE TABLE Responses (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, source_ip TEXT, fqdn TEXT, response TEXT, content TEXT)`,
		`CREATE TABLE Users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL)`,
		`CREATE TABLE Sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash TEXT NOT NULL)`,
	}
	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("create schema: %v", err)
		}
	}

	if _, err := db.Exec(`INSERT INTO Requests (timestamp, source_ip, fqdn, request, content) VALUES ('t1', '10.0.0.2', 'example.com', 'GET /', 'req')`); err != nil {
		t.Fatalf("insert request: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO Responses (timestamp, source_ip, fqdn, response, content) VALUES ('t1', '10.0.0.2', 'example.com', '200 OK', 'res')`); err != nil {
		t.Fatalf("insert response: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO Users (username) VALUES ('admin')`); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO Sessions (token_hash) VALUES ('hash')`); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	if err := WipeTrafficTables(db); err != nil {
		t.Fatalf("wipe traffic tables: %v", err)
	}

	if got := countRows(t, db, "Requests"); got != 0 {
		t.Fatalf("requests rows = %d, want 0", got)
	}
	if got := countRows(t, db, "Responses"); got != 0 {
		t.Fatalf("responses rows = %d, want 0", got)
	}
	if got := countRows(t, db, "Users"); got != 1 {
		t.Fatalf("users rows = %d, want 1", got)
	}
	if got := countRows(t, db, "Sessions"); got != 1 {
		t.Fatalf("sessions rows = %d, want 1", got)
	}
}

func TestWipeTrafficTablesMissingTrafficTables(t *testing.T) {
	db := openTestSQLite(t)

	if _, err := db.Exec(`CREATE TABLE Users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL)`); err != nil {
		t.Fatalf("create users table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO Users (username) VALUES ('operator')`); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	if err := WipeTrafficTables(db); err != nil {
		t.Fatalf("wipe traffic tables with missing traffic schema: %v", err)
	}

	if got := countRows(t, db, "Users"); got != 1 {
		t.Fatalf("users rows = %d, want 1", got)
	}
}
