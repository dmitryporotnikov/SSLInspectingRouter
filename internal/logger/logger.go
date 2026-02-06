package logger

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
	"sync/atomic"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/pcap"
	_ "modernc.org/sqlite"
)

var (
	logMutex     sync.Mutex
	consoleMutex sync.Mutex
	consoleLogs  atomic.Bool
	DB           *sql.DB
)

const (
	logDBFile           = "traffic.db"
	MaxContentBytes     = 4096
	consoleRequestsOnly = true
)

var truncateLogs bool

func SetLogTruncation(enabled bool) {
	truncateLogs = enabled
}

func LogBodyLimit() int {
	if truncateLogs {
		return MaxContentBytes
	}
	return -1
}

func init() {
	consoleLogs.Store(true)
	if consoleRequestsOnly {
		log.SetOutput(io.Discard)
	}
}

func SetConsoleRequestLogging(enabled bool) {
	consoleLogs.Store(enabled)
}

// SetVerbose enables or disables standard application logging to stderr.
func SetVerbose(enabled bool) {
	if enabled {
		log.SetOutput(os.Stderr)
	} else {
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
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL", dbPath))
	if err != nil {
		return fmt.Errorf("failed to open sqlite db: %v", err)
	}
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping sqlite db: %v", err)
	}
	DB = db

	if _, err := DB.Exec(`
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

	if _, err := DB.Exec(`
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
	if DB != nil {
		DB.Close()
	}
}

// GetTrafficDBSize returns the size of the SQLite database file in bytes.
func GetTrafficDBSize() (int64, error) {
	dbPath := resolveDBPath()
	info, err := os.Stat(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return info.Size(), nil
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
	if !consoleLogs.Load() {
		return
	}
	if sourceIP == "" || fqdn == "" {
		return
	}
	consoleMutex.Lock()
	defer consoleMutex.Unlock()
	fmt.Printf("%s %s\n", sourceIP, fqdn)
}

// LogHTTPRequest writes HTTP request details to SQLite.
func LogHTTPRequest(sourceIP, fqdn, method, url string, headers http.Header, body []byte) int64 {
	LogConsoleRequest(sourceIP, fqdn)
	requestLine := fmt.Sprintf("%s %s", method, url)
	content := formatContent(headers, body)
	id, _ := insertRequest(sourceIP, fqdn, requestLine, content)

	if pcap.GlobalManager != nil {
		reqDump := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", method, url, fqdn)
		for k, v := range headers {
			for _, val := range v {
				reqDump += fmt.Sprintf("%s: %s\r\n", k, val)
			}
		}
		reqDump += "\r\n"
		fullReq := append([]byte(reqDump), body...)
		pcap.GlobalManager.WriteRequest(id, sourceIP, fqdn, fullReq)
	}

	return id
}

// LogHTTPSRequest writes HTTPS request details to SQLite.
func LogHTTPSRequest(sourceIP, fqdn, method, url string, headers http.Header, body []byte) int64 {
	LogConsoleRequest(sourceIP, fqdn)
	requestLine := fmt.Sprintf("%s %s", method, url)
	content := formatContent(headers, body)
	id, _ := insertRequest(sourceIP, fqdn, requestLine, content)

	if pcap.GlobalManager != nil {
		reqDump := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", method, url, fqdn)
		for k, v := range headers {
			for _, val := range v {
				reqDump += fmt.Sprintf("%s: %s\r\n", k, val)
			}
		}
		reqDump += "\r\n"
		fullReq := append([]byte(reqDump), body...)
		pcap.GlobalManager.WriteRequest(id, sourceIP, fqdn, fullReq)
	}

	return id
}

// LogHTTPResponse writes HTTP response details to SQLite.
func LogHTTPResponse(reqID int64, sourceIP, fqdn, status string, headers http.Header, bodyPreview []byte, truncated bool) {
	content := formatContentWithLimit(headers, bodyPreview, truncated)
	insertResponse(reqID, sourceIP, fqdn, status, content)

	if pcap.GlobalManager != nil {
		resDump := fmt.Sprintf("HTTP/1.1 %s\r\n", status)
		for k, v := range headers {
			for _, val := range v {
				resDump += fmt.Sprintf("%s: %s\r\n", k, val)
			}
		}
		resDump += "\r\n"
		fullRes := append([]byte(resDump), bodyPreview...)
		pcap.GlobalManager.WriteResponse(reqID, sourceIP, fqdn, fullRes)
	}
}

// LogHTTPSResponse writes HTTPS response details to SQLite.
func LogHTTPSResponse(reqID int64, sourceIP, fqdn, status string, headers http.Header, bodyPreview []byte, truncated bool) {
	content := formatContentWithLimit(headers, bodyPreview, truncated)
	insertResponse(reqID, sourceIP, fqdn, status, content)

	if pcap.GlobalManager != nil {
		resDump := fmt.Sprintf("HTTP/1.1 %s\r\n", status)
		for k, v := range headers {
			for _, val := range v {
				resDump += fmt.Sprintf("%s: %s\r\n", k, val)
			}
		}
		resDump += "\r\n"
		fullRes := append([]byte(resDump), bodyPreview...)
		pcap.GlobalManager.WriteResponse(reqID, sourceIP, fqdn, fullRes)
	}
}

// LogDNSRequest writes DNS request details to SQLite.
func LogDNSRequest(sourceIP, fqdn, queryType string) int64 {
	LogConsoleRequest(sourceIP, fqdn)
	requestLine := fmt.Sprintf("DNS QUERY %s", queryType)
	id, _ := insertRequest(sourceIP, fqdn, requestLine, "")
	return id
}

// LogDNSResponse writes DNS response details to SQLite.
func LogDNSResponse(reqID int64, sourceIP, fqdn, summary, content string) {
	insertResponse(reqID, sourceIP, fqdn, summary, content)
}

// LogTLSRequest logs a non-HTTP TLS request (e.g. blocked by SNI) to SQLite.
func LogTLSRequest(sourceIP, fqdn, note string) int64 {
	LogConsoleRequest(sourceIP, fqdn)
	id, _ := insertRequest(sourceIP, fqdn, note, "")
	return id
}

// LogBypassedRequest records a bypassed request without storing payload details.
func LogBypassedRequest(sourceIP, fqdn string) int64 {
	LogConsoleRequest(sourceIP, fqdn)
	id, _ := insertRequest(sourceIP, fqdn, "BYPASSED", "")
	return id
}

// LogBypassedResponse records a bypassed response without storing payload details.
func LogBypassedResponse(reqID int64, sourceIP, fqdn string) {
	insertResponse(reqID, sourceIP, fqdn, "BYPASSED", "")
}

func insertRequest(sourceIP, fqdn, requestLine, content string) (int64, error) {
	if DB == nil {
		return 0, nil
	}
	logMutex.Lock()
	defer logMutex.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := DB.Exec(`INSERT INTO Requests (timestamp, source_ip, fqdn, request, content) VALUES (?, ?, ?, ?, ?)`,
		timestamp, sourceIP, fqdn, requestLine, content)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func insertResponse(id int64, sourceIP, fqdn, responseLine, content string) {
	if DB == nil {
		return
	}
	logMutex.Lock()
	defer logMutex.Unlock()

	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	// Force ID to match the request ID
	_, _ = DB.Exec(`INSERT INTO Responses (id, timestamp, source_ip, fqdn, response, content) VALUES (?, ?, ?, ?, ?, ?)`,
		id, timestamp, sourceIP, fqdn, responseLine, content)
}

func formatContent(headers http.Header, body []byte) string {
	preview, truncated := truncateBytes(body, MaxContentBytes)
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

type LimitedBuffer struct {
	Buf         []byte
	Max         int
	IsTruncated bool
}

func (b *LimitedBuffer) Write(p []byte) (int, error) {
	if b.Max < 0 {
		b.Buf = append(b.Buf, p...)
		return len(p), nil
	}
	if b.Max == 0 {
		b.IsTruncated = b.IsTruncated || len(p) > 0
		return len(p), nil
	}
	remaining := b.Max - len(b.Buf)
	if remaining > 0 {
		if len(p) <= remaining {
			b.Buf = append(b.Buf, p...)
		} else {
			b.Buf = append(b.Buf, p[:remaining]...)
			b.IsTruncated = true
		}
	} else {
		b.IsTruncated = true
	}
	return len(p), nil
}

func (b *LimitedBuffer) Bytes() []byte {
	return b.Buf
}

func (b *LimitedBuffer) Truncated() bool {
	return b.IsTruncated
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
