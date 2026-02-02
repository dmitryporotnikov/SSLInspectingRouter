package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	logMutex     sync.Mutex
	consoleMutex sync.Mutex
	db           *sql.DB
)

const (
	logDBFile       = "traffic.db"
	maxContentBytes = 4096
	consoleRequestsOnly = true
)

var truncateLogs bool

func SetLogTruncation(enabled bool) {
	truncateLogs = enabled
}

func logBodyLimit() int {
	if truncateLogs {
		return maxContentBytes
	}
	return -1
}

func init() {
	if consoleRequestsOnly {
		log.SetOutput(io.Discard)
	}
}

// InitLogger sets up SQLite logging for HTTP and HTTPS traffic in the software directory.
func InitLogger() error {
	var err error
	dbPath := resolveDBPath()
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %v", err)
	}
	db, err = sql.Open("sqlite", fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL", dbPath))
	if err != nil {
		return fmt.Errorf("failed to open sqlite db: %v", err)
	}
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping sqlite db: %v", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS Requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			fqdn TEXT NOT NULL,
			request TEXT NOT NULL,
			content TEXT
		);
	`); err != nil {
		return fmt.Errorf("failed to create Requests table: %v", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS Responses (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT NOT NULL,
			source_ip TEXT NOT NULL,
			fqdn TEXT NOT NULL,
			response TEXT NOT NULL,
			content TEXT
		);
	`); err != nil {
		return fmt.Errorf("failed to create Responses table: %v", err)
	}

	// Suppress default logger output; console logs are restricted to FQDN + source IP.
	if consoleRequestsOnly {
		log.SetOutput(io.Discard)
	}
	log.SetFlags(log.LstdFlags)

	return nil
}

func resolveDBPath() string {
	dbPath := filepath.Join("logs", logDBFile)
	if exePath, err := os.Executable(); err == nil {
		dbPath = filepath.Join(filepath.Dir(exePath), "logs", logDBFile)
	}
	return dbPath
}

func WipeLogDB() error {
	dbPath := resolveDBPath()
	for _, path := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func CloseLogger() {
	if db != nil {
		db.Close()
	}
}

func LogInfo(message string) {
	log.Printf("[INFO] %s\n", message)
}

func LogError(message string) {
	log.Printf("[ERROR] %s\n", message)
}

func LogDebug(message string) {
	log.Printf("[DEBUG] %s\n", message)
}

// LogConsoleRequest prints only the source IP and FQDN to the console.
func LogConsoleRequest(sourceIP, fqdn string) {
	if sourceIP == "" || fqdn == "" {
		return
	}
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Printf("%s %s\n", sourceIP, fqdn)
}

// LogHTTPRequest writes HTTP request details to SQLite.
func LogHTTPRequest(sourceIP, fqdn, method, url string, headers http.Header, body []byte) {
	LogConsoleRequest(sourceIP, fqdn)
	requestLine := fmt.Sprintf("%s %s", method, url)
	content := formatContent(headers, body)
	insertRequest(sourceIP, fqdn, requestLine, content)
}

// LogHTTPSRequest writes HTTPS request details to SQLite.
func LogHTTPSRequest(sourceIP, fqdn, method, url string, headers http.Header, body []byte) {
	LogConsoleRequest(sourceIP, fqdn)
	requestLine := fmt.Sprintf("%s %s", method, url)
	content := formatContent(headers, body)
	insertRequest(sourceIP, fqdn, requestLine, content)
}

// LogHTTPResponse writes HTTP response details to SQLite.
func LogHTTPResponse(sourceIP, fqdn, status string, headers http.Header, bodyPreview []byte, truncated bool) {
	content := formatContentWithLimit(headers, bodyPreview, truncated)
	insertResponse(sourceIP, fqdn, status, content)
}

// LogHTTPSResponse writes HTTPS response details to SQLite.
func LogHTTPSResponse(sourceIP, fqdn, status string, headers http.Header, bodyPreview []byte, truncated bool) {
	content := formatContentWithLimit(headers, bodyPreview, truncated)
	insertResponse(sourceIP, fqdn, status, content)
}

// LogDNSRequest writes DNS request details to SQLite.
func LogDNSRequest(sourceIP, fqdn, queryType string) {
	LogConsoleRequest(sourceIP, fqdn)
	requestLine := fmt.Sprintf("DNS QUERY %s", queryType)
	insertRequest(sourceIP, fqdn, requestLine, "")
}

// LogDNSResponse writes DNS response details to SQLite.
func LogDNSResponse(sourceIP, fqdn, summary, content string) {
	insertResponse(sourceIP, fqdn, summary, content)
}

// LogTLSRequest logs a non-HTTP TLS request (e.g. blocked by SNI) to SQLite.
func LogTLSRequest(sourceIP, fqdn, note string) {
	LogConsoleRequest(sourceIP, fqdn)
	insertRequest(sourceIP, fqdn, note, "")
}

// LogBypassedRequest records a bypassed request without storing payload details.
func LogBypassedRequest(sourceIP, fqdn string) {
	LogConsoleRequest(sourceIP, fqdn)
	insertRequest(sourceIP, fqdn, "BYPASSED", "")
}

// LogBypassedResponse records a bypassed response without storing payload details.
func LogBypassedResponse(sourceIP, fqdn string) {
	insertResponse(sourceIP, fqdn, "BYPASSED", "")
}

func insertRequest(sourceIP, fqdn, requestLine, content string) {
	if db == nil {
		return
	}
	logMutex.Lock()
	defer logMutex.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = db.Exec(`INSERT INTO Requests (timestamp, source_ip, fqdn, request, content) VALUES (?, ?, ?, ?, ?)`,
		timestamp, sourceIP, fqdn, requestLine, content)
}

func insertResponse(sourceIP, fqdn, responseLine, content string) {
	if db == nil {
		return
	}
	logMutex.Lock()
	defer logMutex.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = db.Exec(`INSERT INTO Responses (timestamp, source_ip, fqdn, response, content) VALUES (?, ?, ?, ?, ?)`,
		timestamp, sourceIP, fqdn, responseLine, content)
}

func formatContent(headers http.Header, body []byte) string {
	preview, truncated := truncateBytes(body, maxContentBytes)
	return formatContentWithLimit(headers, preview, truncated)
}

func formatContentWithLimit(headers http.Header, body []byte, truncated bool) string {
	var logEntry strings.Builder
	if len(headers) > 0 {
		logEntry.WriteString("Headers:\n")
		for name, values := range headers {
			for _, value := range values {
				logEntry.WriteString(fmt.Sprintf("  %s: %s\n", name, value))
			}
		}
	}

	if len(body) > 0 {
		logEntry.WriteString(fmt.Sprintf("Body Preview (%d bytes):\n%s\n", len(body), string(body)))
		if truncated {
			logEntry.WriteString("... (truncated)\n")
		}
	}

	return logEntry.String()
}

func truncateBytes(body []byte, max int) ([]byte, bool) {
	if !truncateLogs {
		return body, false
	}
	if len(body) <= max {
		return body, false
	}
	return body[:max], true
}

type limitedBuffer struct {
	buf       []byte
	max       int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.max < 0 {
		b.buf = append(b.buf, p...)
		return len(p), nil
	}
	if b.max == 0 {
		b.truncated = b.truncated || len(p) > 0
		return len(p), nil
	}
	remaining := b.max - len(b.buf)
	if remaining > 0 {
		if len(p) <= remaining {
			b.buf = append(b.buf, p...)
		} else {
			b.buf = append(b.buf, p[:remaining]...)
			b.truncated = true
		}
	} else {
		b.truncated = true
	}
	return len(p), nil
}

func (b *limitedBuffer) Bytes() []byte {
	return b.buf
}

func (b *limitedBuffer) Truncated() bool {
	return b.truncated
}

// ReadBody safely reads the request body without closing it, returning the bytes.
func ReadBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil
	}
	return body
}
