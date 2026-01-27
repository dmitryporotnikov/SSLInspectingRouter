package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	logMutex     sync.Mutex
	httpLogFile  *os.File
	httpsLogFile *os.File
)

// InitLogger sets up file logging for HTTP and HTTPS traffic in the 'logs' directory.
func InitLogger() error {
	var err error

	if err := os.MkdirAll("logs", 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %v", err)
	}

	httpLogFile, err = os.OpenFile("logs/http.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open HTTP log file: %v", err)
	}

	httpsLogFile, err = os.OpenFile("logs/https.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open HTTPS log file: %v", err)
	}

	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags)

	LogInfo("Logger initialized.")
	return nil
}

func CloseLogger() {
	if httpLogFile != nil {
		httpLogFile.Close()
	}
	if httpsLogFile != nil {
		httpsLogFile.Close()
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

// LogHTTPRequest writes the HTTP request details to the HTTP log file and stdout.
func LogHTTPRequest(sourceIP, method, url string, headers http.Header, body []byte) {
	logMutex.Lock()
	defer logMutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	var logEntry strings.Builder
	logEntry.WriteString("\n========== HTTP REQUEST ==========\n")
	logEntry.WriteString(fmt.Sprintf("Timestamp: %s\n", timestamp))
	logEntry.WriteString(fmt.Sprintf("Source IP: %s\n", sourceIP))
	logEntry.WriteString(fmt.Sprintf("Method: %s\n", method))
	logEntry.WriteString(fmt.Sprintf("URL: %s\n", url))
	logEntry.WriteString("Headers:\n")
	
	for name, values := range headers {
		for _, value := range values {
			logEntry.WriteString(fmt.Sprintf("  %s: %s\n", name, value))
		}
	}
	
	if len(body) > 0 {
		preview := body
		if len(body) > 500 {
			preview = body[:500]
		}
		logEntry.WriteString(fmt.Sprintf("Body Preview (%d bytes):\n%s\n", len(body), string(preview)))
		if len(body) > 500 {
			logEntry.WriteString(fmt.Sprintf("... (truncated, total %d bytes)\n", len(body)))
		}
	}
	
	logEntry.WriteString("==================================\n")

	entry := logEntry.String()
	if httpLogFile != nil {
		httpLogFile.WriteString(entry)
	}
	fmt.Print(entry)
}

// LogHTTPSRequest writes decrypted HTTPS request details to the HTTPS log file and stdout.
func LogHTTPSRequest(sourceIP, method, url string, headers http.Header, body []byte) {
	logMutex.Lock()
	defer logMutex.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	var logEntry strings.Builder
	logEntry.WriteString("\n========== HTTPS REQUEST (DECRYPTED) ==========\n")
	logEntry.WriteString(fmt.Sprintf("Timestamp: %s\n", timestamp))
	logEntry.WriteString(fmt.Sprintf("Source IP: %s\n", sourceIP))
	logEntry.WriteString(fmt.Sprintf("Method: %s\n", method))
	logEntry.WriteString(fmt.Sprintf("URL: %s\n", url))
	logEntry.WriteString("Headers:\n")
	
	for name, values := range headers {
		for _, value := range values {
			logEntry.WriteString(fmt.Sprintf("  %s: %s\n", name, value))
		}
	}
	
	if len(body) > 0 {
		preview := body
		if len(body) > 500 {
			preview = body[:500]
		}
		logEntry.WriteString(fmt.Sprintf("Body Preview (%d bytes):\n%s\n", len(body), string(preview)))
		if len(body) > 500 {
			logEntry.WriteString(fmt.Sprintf("... (truncated, total %d bytes)\n", len(body)))
		}
	}
	
	logEntry.WriteString("===============================================\n")

	entry := logEntry.String()
	if httpsLogFile != nil {
		httpsLogFile.WriteString(entry)
	}
	fmt.Print(entry)
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
