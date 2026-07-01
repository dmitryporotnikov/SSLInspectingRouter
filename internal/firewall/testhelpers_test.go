package firewall

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// openTestDB returns a per-test in-memory SQLite database. The package
// uses modernc.org/sqlite so tests do not require CGO or a system
// sqlite3 binary. The DSN uses a per-test name and `cache=shared` so
// every connection in the pool sees the same database (a plain
// `:memory:` is per-connection and breaks async goroutine writes).
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// Each test gets a uniquely named shared in-memory database; closing
	// the *sql.DB releases the lock so the next test can reuse the name.
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// waitForStoredOutboundPorts polls the firewall_config table for the
// outbound_ports row and invokes the predicate with the decoded list
// until it returns true or the timeout elapses.
func waitForStoredOutboundPorts(t *testing.T, db *sql.DB, timeout time.Duration, predicate func([]OutboundPortEntry) bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []OutboundPortEntry
	for time.Now().Before(deadline) {
		var raw string
		err := db.QueryRow("SELECT value FROM firewall_config WHERE key = ?", firewallConfigKeyOutboundPorts).Scan(&raw)
		if err == nil {
			var entries []OutboundPortEntry
			if json.Unmarshal([]byte(raw), &entries) == nil {
				last = entries
				if predicate(entries) {
					return
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("outbound_ports not persisted within %s (last: %+v)", timeout, last)
}
