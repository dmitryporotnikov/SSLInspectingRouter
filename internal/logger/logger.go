package logger

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/pcap"
	_ "modernc.org/sqlite"
)

var (
	logMutex     sync.Mutex
	consoleMutex sync.Mutex
	consoleLogs  atomic.Bool
	DB           *sql.DB

	bodyArtifactMu      sync.RWMutex
	bodyArtifactEnabled bool
	bodyArtifactDir     string
)

const (
	logDBFile             = "traffic.db"
	MaxContentBytes       = 4096
	consoleRequestsOnly   = true
	bodyArtifactSubfolder = "body-artifacts"
)

var truncateLogs atomic.Bool
var trafficLoggingEnabled atomic.Bool

type RequestLogEntry struct {
	SourceIP string
	FQDN     string
	Method   string
	URL      string
	Headers  http.Header
	Body     []byte
}

type ResponseLogEntry struct {
	ReqID       int64
	SourceIP    string
	FQDN        string
	Status      string
	Headers     http.Header
	BodyPreview []byte
	Truncated   bool
}

type bodyPreviewAnalysis struct {
	ShowAsText      bool
	Reason          string
	ContentType     string
	ContentEncoding string
}

func SetLogTruncation(enabled bool) {
	truncateLogs.Store(enabled)
}

func IsLogTruncationEnabled() bool {
	return truncateLogs.Load()
}

// SetTrafficLogging enables or disables capture logging to SQLite/artifacts.
func SetTrafficLogging(enabled bool) {
	trafficLoggingEnabled.Store(enabled)
}

// IsTrafficLoggingEnabled reports current capture logging state.
func IsTrafficLoggingEnabled() bool {
	return trafficLoggingEnabled.Load()
}

func SetBinaryBodyArtifactStorage(enabled bool, dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		dir = resolveBodyArtifactDir()
	}

	if enabled {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create body artifact directory: %w", err)
		}
	}

	bodyArtifactMu.Lock()
	bodyArtifactEnabled = enabled
	bodyArtifactDir = dir
	bodyArtifactMu.Unlock()
	return nil
}

func BinaryBodyArtifactStorage() (enabled bool, dir string) {
	bodyArtifactMu.RLock()
	defer bodyArtifactMu.RUnlock()
	return bodyArtifactEnabled, bodyArtifactDir
}

func LogBodyLimit() int {
	if truncateLogs.Load() {
		return MaxContentBytes
	}
	return -1
}

func init() {
	consoleLogs.Store(true)
	trafficLoggingEnabled.Store(true)
	bodyArtifactDir = resolveBodyArtifactDir()
	if consoleRequestsOnly {
		log.SetOutput(io.Discard)
	}
}

func resolveBodyArtifactDir() string {
	dir := filepath.Join("logs", bodyArtifactSubfolder)
	if exePath, err := os.Executable(); err == nil {
		dir = filepath.Join(filepath.Dir(exePath), "logs", bodyArtifactSubfolder)
	}
	return dir
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

// WipeTrafficDB removes captured traffic rows while preserving non-traffic tables.
// If the SQLite file does not exist yet, this is a no-op.
func WipeTrafficDB() error {
	dbPath := resolveDBPath()
	if _, err := os.Stat(dbPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL", dbPath))
	if err != nil {
		return fmt.Errorf("failed to open sqlite db: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping sqlite db: %v", err)
	}

	return WipeTrafficTables(db)
}

// WipeTrafficTables removes captured traffic rows from Requests/Responses.
func WipeTrafficTables(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("database handle is nil")
	}

	logMutex.Lock()
	defer logMutex.Unlock()

	const maxAttempts = 5
	backoff := 50 * time.Millisecond

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := wipeTrafficTablesOnce(db); err != nil {
			lastErr = err
			if isSQLiteBusyError(err) && attempt < maxAttempts {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			return err
		}
		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("failed to wipe traffic tables")
}

func wipeTrafficTablesOnce(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.Exec(`DELETE FROM Responses`); err != nil && !isSQLiteNoSuchTableError(err) {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM Requests`); err != nil && !isSQLiteNoSuchTableError(err) {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM sqlite_sequence WHERE name IN ('Requests', 'Responses')`); err != nil && !isSQLiteNoSuchTableError(err) {
		return err
	}

	return tx.Commit()
}

func isSQLiteNoSuchTableError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such table")
}

func isSQLiteBusyError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") ||
		strings.Contains(message, "database table is locked") ||
		strings.Contains(message, "database is busy") ||
		strings.Contains(message, "sql logic error: database is locked")
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

func WipeBodyArtifacts(customDir string) error {
	dirs := []string{resolveBodyArtifactDir()}
	customDir = strings.TrimSpace(customDir)
	if customDir != "" {
		customDir = filepath.Clean(customDir)
		if customDir != dirs[0] {
			dirs = append(dirs, customDir)
		}
	}

	for _, dir := range dirs {
		if dir == "" || dir == "." || dir == string(filepath.Separator) {
			return fmt.Errorf("refusing to wipe unsafe artifact path: %q", dir)
		}
		if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
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
	if !trafficLoggingEnabled.Load() {
		return
	}
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
func LogHTTPRequest(entry RequestLogEntry) int64 {
	if !trafficLoggingEnabled.Load() {
		return 0
	}
	LogConsoleRequest(entry.SourceIP, entry.FQDN)
	requestLine := fmt.Sprintf("%s %s", entry.Method, entry.URL)
	content := formatContent(entry.Headers, entry.Body)
	id, _ := insertRequest(entry.SourceIP, entry.FQDN, requestLine, content)

	if pcap.GlobalManager != nil {
		var sb strings.Builder
		sb.WriteString(entry.Method)
		sb.WriteString(" ")
		sb.WriteString(entry.URL)
		sb.WriteString(" HTTP/1.1\r\nHost: ")
		sb.WriteString(entry.FQDN)
		sb.WriteString("\r\n")
		for k, v := range entry.Headers {
			for _, val := range v {
				sb.WriteString(k)
				sb.WriteString(": ")
				sb.WriteString(val)
				sb.WriteString("\r\n")
			}
		}
		sb.WriteString("\r\n")
		fullReq := append([]byte(sb.String()), entry.Body...)
		pcap.GlobalManager.WriteRequest(id, entry.SourceIP, entry.FQDN, fullReq)
	}

	return id
}

// LogHTTPSRequest writes HTTPS request details to SQLite.
func LogHTTPSRequest(entry RequestLogEntry) int64 {
	if !trafficLoggingEnabled.Load() {
		return 0
	}
	LogConsoleRequest(entry.SourceIP, entry.FQDN)
	requestLine := fmt.Sprintf("%s %s", entry.Method, entry.URL)
	content := formatContent(entry.Headers, entry.Body)
	id, _ := insertRequest(entry.SourceIP, entry.FQDN, requestLine, content)

	if pcap.GlobalManager != nil {
		var sb strings.Builder
		sb.WriteString(entry.Method)
		sb.WriteString(" ")
		sb.WriteString(entry.URL)
		sb.WriteString(" HTTP/1.1\r\nHost: ")
		sb.WriteString(entry.FQDN)
		sb.WriteString("\r\n")
		for k, v := range entry.Headers {
			for _, val := range v {
				sb.WriteString(k)
				sb.WriteString(": ")
				sb.WriteString(val)
				sb.WriteString("\r\n")
			}
		}
		sb.WriteString("\r\n")
		fullReq := append([]byte(sb.String()), entry.Body...)
		pcap.GlobalManager.WriteRequest(id, entry.SourceIP, entry.FQDN, fullReq)
	}

	return id
}

// LogHTTPResponse writes HTTP response details to SQLite.
func LogHTTPResponse(entry ResponseLogEntry) {
	if !trafficLoggingEnabled.Load() {
		return
	}
	analysis := analyzeBodyPreview(entry.Headers, entry.BodyPreview)
	artifactPath := maybeStoreBodyArtifact(ArtifactStoreParams{
		Direction: "http_response",
		ReqID:     entry.ReqID,
		SourceIP:  entry.SourceIP,
		FQDN:      entry.FQDN,
		Analysis:  analysis,
		Body:      entry.BodyPreview,
		Truncated: entry.Truncated,
	})
	content := formatContentWithAnalysis(entry.Headers, entry.BodyPreview, entry.Truncated, analysis, artifactPath)
	insertResponse(entry.ReqID, entry.SourceIP, entry.FQDN, entry.Status, content)

	if pcap.GlobalManager != nil {
		var sb strings.Builder
		sb.WriteString("HTTP/1.1 ")
		sb.WriteString(entry.Status)
		sb.WriteString("\r\n")
		for k, v := range entry.Headers {
			for _, val := range v {
				sb.WriteString(k)
				sb.WriteString(": ")
				sb.WriteString(val)
				sb.WriteString("\r\n")
			}
		}
		sb.WriteString("\r\n")
		fullRes := append([]byte(sb.String()), entry.BodyPreview...)
		pcap.GlobalManager.WriteResponse(entry.ReqID, entry.SourceIP, entry.FQDN, fullRes)
	}
}

// LogHTTPSResponse writes HTTPS response details to SQLite.
func LogHTTPSResponse(entry ResponseLogEntry) {
	if !trafficLoggingEnabled.Load() {
		return
	}
	analysis := analyzeBodyPreview(entry.Headers, entry.BodyPreview)
	artifactPath := maybeStoreBodyArtifact(ArtifactStoreParams{
		Direction: "https_response",
		ReqID:     entry.ReqID,
		SourceIP:  entry.SourceIP,
		FQDN:      entry.FQDN,
		Analysis:  analysis,
		Body:      entry.BodyPreview,
		Truncated: entry.Truncated,
	})
	content := formatContentWithAnalysis(entry.Headers, entry.BodyPreview, entry.Truncated, analysis, artifactPath)
	insertResponse(entry.ReqID, entry.SourceIP, entry.FQDN, entry.Status, content)

	if pcap.GlobalManager != nil {
		var sb strings.Builder
		sb.WriteString("HTTP/1.1 ")
		sb.WriteString(entry.Status)
		sb.WriteString("\r\n")
		for k, v := range entry.Headers {
			for _, val := range v {
				sb.WriteString(k)
				sb.WriteString(": ")
				sb.WriteString(val)
				sb.WriteString("\r\n")
			}
		}
		sb.WriteString("\r\n")
		fullRes := append([]byte(sb.String()), entry.BodyPreview...)
		pcap.GlobalManager.WriteResponse(entry.ReqID, entry.SourceIP, entry.FQDN, fullRes)
	}
}

// LogDNSRequest writes DNS request details to SQLite.
func LogDNSRequest(sourceIP, fqdn, queryType string) int64 {
	if !trafficLoggingEnabled.Load() {
		return 0
	}
	LogConsoleRequest(sourceIP, fqdn)
	requestLine := fmt.Sprintf("DNS QUERY %s", queryType)
	id, _ := insertRequest(sourceIP, fqdn, requestLine, "")
	return id
}

// LogDNSResponse writes DNS response details to SQLite.
func LogDNSResponse(reqID int64, sourceIP, fqdn, summary, content string) {
	if !trafficLoggingEnabled.Load() {
		return
	}
	insertResponse(reqID, sourceIP, fqdn, summary, content)
}

// LogTLSRequest logs a non-HTTP TLS request (e.g. blocked by SNI) to SQLite.
func LogTLSRequest(sourceIP, fqdn, note string) int64 {
	if !trafficLoggingEnabled.Load() {
		return 0
	}
	LogConsoleRequest(sourceIP, fqdn)
	id, _ := insertRequest(sourceIP, fqdn, note, "")
	return id
}

// LogBypassedRequest records a bypassed request without storing payload details.
func LogBypassedRequest(sourceIP, fqdn string) int64 {
	if !trafficLoggingEnabled.Load() {
		return 0
	}
	LogConsoleRequest(sourceIP, fqdn)
	id, _ := insertRequest(sourceIP, fqdn, "BYPASSED", "")
	return id
}

// LogBypassedResponse records a bypassed response without storing payload details.
func LogBypassedResponse(reqID int64, sourceIP, fqdn string) {
	if !trafficLoggingEnabled.Load() {
		return
	}
	insertResponse(reqID, sourceIP, fqdn, "BYPASSED", "")
}

// LogInspectionPausedRequest records a tunnelled TLS request while active inspection is paused.
func LogInspectionPausedRequest(sourceIP, fqdn string) int64 {
	if !trafficLoggingEnabled.Load() {
		return 0
	}
	LogConsoleRequest(sourceIP, fqdn)
	id, _ := insertRequest(sourceIP, fqdn, "INSPECTION PAUSED", "")
	return id
}

// LogInspectionPausedResponse records a tunnelled TLS response while active inspection is paused.
func LogInspectionPausedResponse(reqID int64, sourceIP, fqdn string) {
	if !trafficLoggingEnabled.Load() {
		return
	}
	insertResponse(reqID, sourceIP, fqdn, "INSPECTION PAUSED", "")
}

// LogSNIRequest records a tunnelled TLS request under SNI-only mode.
// The metadata text (TLS version, ciphers, ALPN, extensions, etc.) is stored
// in the request content column so the dashboard can display it without a
// schema change.
func LogSNIRequest(sourceIP, fqdn, metadata string) int64 {
	if !trafficLoggingEnabled.Load() {
		return 0
	}
	LogConsoleRequest(sourceIP, fqdn)
	id, _ := insertRequest(sourceIP, fqdn, "SNI-ONLY", metadata)
	return id
}

// LogSNIResponse records a tunnelled TLS response under SNI-only mode.
func LogSNIResponse(reqID int64, sourceIP, fqdn, summary string) {
	if !trafficLoggingEnabled.Load() {
		return
	}
	insertResponse(reqID, sourceIP, fqdn, "SNI-ONLY", summary)
}

func insertRequest(sourceIP, fqdn, requestLine, content string) (int64, error) {
	if DB == nil || !trafficLoggingEnabled.Load() {
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
	if DB == nil || id <= 0 || !trafficLoggingEnabled.Load() {
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
	analysis := analyzeBodyPreview(headers, preview)
	return formatContentWithAnalysis(headers, preview, truncated, analysis, "")
}

func formatContentWithLimit(headers http.Header, body []byte, truncated bool) string {
	analysis := analyzeBodyPreview(headers, body)
	return formatContentWithAnalysis(headers, body, truncated, analysis, "")
}

func formatContentWithAnalysis(headers http.Header, body []byte, truncated bool, analysis bodyPreviewAnalysis, artifactPath string) string {
	var logEntry strings.Builder
	if len(headers) > 0 {
		logEntry.WriteString("Headers:\n")
		for name, values := range headers {
			for _, value := range values {
				logEntry.WriteString("  ")
				logEntry.WriteString(name)
				logEntry.WriteString(": ")
				logEntry.WriteString(value)
				logEntry.WriteString("\n")
			}
		}
	}

	if len(body) > 0 {
		if analysis.ShowAsText {
			logEntry.WriteString(fmt.Sprintf("Body Preview (%d bytes):\n%s\n", len(body), string(body)))
		} else {
			logEntry.WriteString(fmt.Sprintf("Body Preview skipped (%d bytes)\n", len(body)))
			if analysis.Reason != "" {
				logEntry.WriteString(fmt.Sprintf("Reason: %s\n", analysis.Reason))
			}
			if analysis.ContentType != "" {
				logEntry.WriteString(fmt.Sprintf("Detected Content-Type: %s\n", analysis.ContentType))
			}
			if analysis.ContentEncoding != "" {
				logEntry.WriteString(fmt.Sprintf("Detected Content-Encoding: %s\n", analysis.ContentEncoding))
			}
			if artifactPath != "" {
				logEntry.WriteString(fmt.Sprintf("Body Artifact: %s\n", artifactPath))
			}
		}
		if truncated {
			logEntry.WriteString("... (truncated)\n")
		}
	}

	return logEntry.String()
}

func analyzeBodyPreview(headers http.Header, body []byte) bodyPreviewAnalysis {
	analysis := bodyPreviewAnalysis{
		ShowAsText:      true,
		ContentType:     normalizedContentType(headers.Get("Content-Type")),
		ContentEncoding: normalizedContentEncoding(headers.Get("Content-Encoding")),
	}

	if len(body) == 0 {
		return analysis
	}

	if analysis.ContentEncoding != "" && analysis.ContentEncoding != "identity" {
		analysis.ShowAsText = false
		analysis.Reason = "compressed response body"
		return analysis
	}

	if analysis.ContentType != "" && !isLikelyTextContentType(analysis.ContentType) {
		analysis.ShowAsText = false
		analysis.Reason = "binary content type"
		return analysis
	}

	if !isLikelyTextBytes(body) {
		analysis.ShowAsText = false
		analysis.Reason = "body bytes are not valid text"
	}
	return analysis
}

func normalizedContentType(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(raw)
	if err == nil {
		return strings.ToLower(strings.TrimSpace(mediaType))
	}
	if idx := strings.Index(raw, ";"); idx >= 0 {
		raw = raw[:idx]
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func normalizedContentEncoding(raw string) string {
	for _, part := range strings.Split(strings.ToLower(raw), ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			return part
		}
	}
	return ""
}

func isLikelyTextContentType(contentType string) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	if contentType == "" {
		return false
	}
	if strings.HasPrefix(contentType, "text/") {
		return true
	}
	if strings.HasSuffix(contentType, "+json") || strings.HasSuffix(contentType, "+xml") || strings.HasSuffix(contentType, "+yaml") {
		return true
	}

	switch contentType {
	case "application/json",
		"application/xml",
		"application/x-www-form-urlencoded",
		"application/javascript",
		"application/x-javascript",
		"application/ecmascript",
		"application/graphql",
		"application/yaml",
		"application/x-yaml",
		"application/problem+json",
		"image/svg+xml":
		return true
	default:
		return false
	}
}

func isLikelyTextBytes(body []byte) bool {
	if len(body) == 0 {
		return true
	}
	sample := body
	if len(sample) > MaxContentBytes {
		sample = sample[:MaxContentBytes]
	}

	if !utf8.Valid(sample) {
		return false
	}

	var controls int
	for _, r := range string(sample) {
		if r == 0 {
			return false
		}
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			controls++
		}
	}

	return controls*100 <= len(sample)*5
}

type ArtifactStoreParams struct {
	Direction string
	ReqID     int64
	SourceIP  string
	FQDN      string
	Analysis  bodyPreviewAnalysis
	Body      []byte
	Truncated bool
}

func maybeStoreBodyArtifact(params ArtifactStoreParams) string {
	if len(params.Body) == 0 || params.Analysis.ShowAsText {
		return ""
	}

	enabled, dir := BinaryBodyArtifactStorage()
	if !enabled || strings.TrimSpace(dir) == "" {
		return ""
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		LogError(fmt.Sprintf("Body artifact directory unavailable: %v", err))
		return ""
	}

	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	fileName := fmt.Sprintf("%s_req%d_%s_%s_%s%s",
		stamp,
		params.ReqID,
		sanitizeFilenameToken(params.Direction),
		sanitizeFilenameToken(params.FQDN),
		sanitizeFilenameToken(params.SourceIP),
		bodyArtifactExt(params.Analysis.ContentType, params.Analysis.ContentEncoding),
	)
	path := filepath.Join(dir, fileName)

	if err := os.WriteFile(path, params.Body, 0640); err != nil {
		LogError(fmt.Sprintf("Failed writing body artifact %s: %v", path, err))
		return ""
	}

	if params.Truncated {
		metaPath := path + ".meta.txt"
		_ = os.WriteFile(metaPath, []byte("This artifact contains a truncated body preview due to active log truncation limits.\n"), 0640)
	}

	return path
}

func sanitizeFilenameToken(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}

	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
		case r == ':':
			b.WriteRune('-')
		default:
			b.WriteRune('_')
		}
	}

	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return "unknown"
	}
	if len(out) > 80 {
		return out[:80]
	}
	return out
}

func bodyArtifactExt(contentType, contentEncoding string) string {
	switch contentEncoding {
	case "gzip":
		return ".gz"
	case "br":
		return ".br"
	case "deflate":
		return ".deflate"
	}

	switch contentType {
	case "application/json":
		return ".json"
	case "text/html":
		return ".html"
	case "text/plain":
		return ".txt"
	case "application/xml", "text/xml", "image/svg+xml":
		return ".xml"
	case "application/javascript", "application/x-javascript", "application/ecmascript":
		return ".js"
	case "image/png":
		return ".png"
	case "image/jpeg":
		return ".jpg"
	case "image/gif":
		return ".gif"
	case "application/pdf":
		return ".pdf"
	case "application/zip":
		return ".zip"
	default:
		return ".bin"
	}
}

func truncateBytes(body []byte, max int) ([]byte, bool) {
	if !truncateLogs.Load() {
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
