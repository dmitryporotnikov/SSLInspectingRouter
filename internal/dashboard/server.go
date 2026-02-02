package dashboard

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	db   *sql.DB
	addr string
}

func Start(db *sql.DB, addr string) error {
	s := &Server{
		db:   db,
		addr: addr,
	}

	mux := http.NewServeMux()

	// Serve static files
	fsys, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(fsys)))

	// API endpoints
	mux.HandleFunc("/api/traffic", s.handleTraffic)

	logger.LogInfo(fmt.Sprintf("Dashboard listening on http://localhost%s", addr))
	return http.ListenAndServe(addr, mux)
}

type TrafficEntry struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	SourceIP  string `json:"source_ip"`
	Host      string `json:"host"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Status    string `json:"status"` // From response
}

type TrafficDetail struct {
	TrafficEntry
	RequestFull  string `json:"request_full"`
	RequestBody  string `json:"request_body"`
	ResponseFull string `json:"response_full"`
	ResponseBody string `json:"response_body"`
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	// Check for ID parameter to return details
	idParam := r.URL.Query().Get("id")
	if idParam != "" {
		s.handleTrafficDetail(w, idParam)
		return
	}

	// Simple query: Get latest 50 requests
	rows, err := s.db.Query(`
		SELECT 
			r.id, r.timestamp, r.source_ip, r.fqdn, r.request,
			COALESCE(res.response, '') as response_line
		FROM Requests r
		LEFT JOIN Responses res ON r.id = res.id
		ORDER BY r.id DESC LIMIT 50
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var entries []TrafficEntry
	for rows.Next() {
		var e TrafficEntry
		var reqLine []byte
		var resLine []byte

		// Scan raw bytes to handle potential NULLs or blobs gracefully
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.SourceIP, &e.Host, &reqLine, &resLine); err != nil {
			continue
		}

		// Helper to extract first line
		firstLine := func(b []byte) string {
			for i, c := range b {
				if c == '\n' || c == '\r' {
					return string(b[:i])
				}
			}
			return string(b)
		}

		// Basic parsing of request line "METHOD URL ..."
		req := firstLine(reqLine)
		var method, url string
		fmt.Sscanf(req, "%s %s", &method, &url)
		e.Method = method
		e.URL = url

		// Basic parsing of response line "Protocol Status ..."
		e.Status = firstLine(resLine)

		entries = append(entries, e)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func (s *Server) handleTrafficDetail(w http.ResponseWriter, id string) {
	// Fetch full details
	var d TrafficDetail
	var reqBlob, resBlob, reqBodyBlob, resBodyBlob []byte

	// Query Requests table
	err := s.db.QueryRow(`
		SELECT id, timestamp, source_ip, fqdn, request, content
		FROM Requests WHERE id = ?
	`, id).Scan(&d.ID, &d.Timestamp, &d.SourceIP, &d.Host, &reqBlob, &reqBodyBlob)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Not found", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	d.RequestFull = string(reqBlob)
	d.RequestBody = string(reqBodyBlob)

	// Query Responses table (optional, might not exist yet)
	err = s.db.QueryRow(`
		SELECT response, content
		FROM Responses WHERE id = ?
	`, id).Scan(&resBlob, &resBodyBlob)

	if err == nil {
		d.ResponseFull = string(resBlob)
		d.ResponseBody = string(resBodyBlob)
	}

	// Parse method/status for the summary part of Detail (optional, but good for consistency)
	// (Skipping deep parsing here as frontend can use raw full text or we can reuse logic)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d)
}
