package dashboard

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/wireguard"
)

// TrafficEntry is a summarized view of captured traffic rows.
type TrafficEntry struct {
	ID          int64  `json:"id"`
	Timestamp   string `json:"timestamp"`
	SourceIP    string `json:"source_ip"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Status      string `json:"status"`
	Mode        string `json:"mode"`
	RequestLine string `json:"request_line"`
}

// TrafficDetail is a full request/response record for one ID.
type TrafficDetail struct {
	TrafficEntry
	RequestFull  string `json:"request_full"`
	RequestBody  string `json:"request_body"`
	ResponseFull string `json:"response_full"`
	ResponseBody string `json:"response_body"`
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		s.handleTrafficFlush(w, r)
		return
	}

	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet, http.MethodDelete)
		return
	}

	limit := parseBoundedInt(r.URL.Query().Get("limit"), 50, 1, 500)
	offset := parseBoundedInt(r.URL.Query().Get("offset"), 0, 0, 1_000_000)
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	hostFilter := strings.TrimSpace(r.URL.Query().Get("host"))
	sourceFilter := strings.TrimSpace(r.URL.Query().Get("source_ip"))
	methodFilter := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("method")))
	modeFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))

	conditions := make([]string, 0, 6)
	args := make([]any, 0, 10)

	if search != "" {
		like := "%" + search + "%"
		conditions = append(conditions, `(r.fqdn LIKE ? OR r.source_ip LIKE ? OR r.request LIKE ? OR COALESCE(res.response, '') LIKE ?)`)
		args = append(args, like, like, like, like)
	}
	if hostFilter != "" {
		conditions = append(conditions, `r.fqdn LIKE ?`)
		args = append(args, "%"+hostFilter+"%")
	}
	if sourceFilter != "" {
		conditions = append(conditions, `r.source_ip LIKE ?`)
		args = append(args, "%"+sourceFilter+"%")
	}
	if methodFilter != "" {
		conditions = append(conditions, `r.request LIKE ?`)
		args = append(args, methodFilter+" %")
	}
	if modeCondition, ok := trafficModeCondition(modeFilter); ok {
		conditions = append(conditions, modeCondition)
	}

	fromClause := ` FROM Requests r LEFT JOIN Responses res ON r.id = res.id `
	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int
	countQuery := `SELECT COUNT(*)` + fromClause + whereClause
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to count traffic")
		return
	}

	query := `
		SELECT
			r.id,
			r.timestamp,
			r.source_ip,
			r.fqdn,
			r.request,
			COALESCE(res.response, '')
	` + fromClause + whereClause + `
		ORDER BY r.id DESC
		LIMIT ? OFFSET ?
	`

	queryArgs := append(args, limit, offset)
	rows, err := s.db.Query(query, queryArgs...)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load traffic")
		return
	}
	defer rows.Close()

	entries := make([]TrafficEntry, 0, limit)
	for rows.Next() {
		var (
			entry        TrafficEntry
			requestLine  string
			responseLine string
		)
		if err := rows.Scan(&entry.ID, &entry.Timestamp, &entry.SourceIP, &entry.Host, &requestLine, &responseLine); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to parse traffic row")
			return
		}

		entry.RequestLine = requestLine
		entry.Status = firstLine(responseLine)
		entry.Mode = detectTrafficMode(requestLine, responseLine)
		entry.Method, entry.URL = parseRequestLine(requestLine)
		entries = append(entries, entry)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":  entries,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

func (s *Server) handleTrafficDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

	id, err := parsePathID(r.URL.Path, "/api/v1/traffic/")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	var (
		detail                    TrafficDetail
		requestLine               string
		responseLine              sql.NullString
		requestBody, responseBody sql.NullString
	)

	err = s.db.QueryRow(`
		SELECT
			r.id,
			r.timestamp,
			r.source_ip,
			r.fqdn,
			r.request,
			r.content,
			res.response,
			res.content
		FROM Requests r
		LEFT JOIN Responses res ON r.id = res.id
		WHERE r.id = ?
		LIMIT 1
	`, id).Scan(
		&detail.ID,
		&detail.Timestamp,
		&detail.SourceIP,
		&detail.Host,
		&requestLine,
		&requestBody,
		&responseLine,
		&responseBody,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSONError(w, http.StatusNotFound, "traffic entry not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to load traffic entry")
		return
	}

	detail.RequestLine = requestLine
	detail.RequestFull = requestLine
	if requestBody.Valid {
		detail.RequestBody = requestBody.String
	}
	if responseLine.Valid {
		detail.ResponseFull = responseLine.String
		detail.Status = firstLine(responseLine.String)
	}
	if responseBody.Valid {
		detail.ResponseBody = responseBody.String
	}
	if detail.Status == "" {
		detail.Status = "-"
	}
	detail.Mode = detectTrafficMode(requestLine, detail.ResponseFull)
	detail.Method, detail.URL = parseRequestLine(requestLine)

	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) handleTrafficFlush(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	if user == nil || user.Role != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin role required")
		return
	}

	if err := logger.WipeTrafficTables(s.db); err != nil {
		logger.LogError(fmt.Sprintf("dashboard traffic flush failed: %v", err))
		writeJSONError(w, http.StatusInternalServerError, "failed to flush traffic")
		return
	}

	s.lastRequestCount.Store(0)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		status := s.currentStatusPayload()
		writeJSON(w, http.StatusOK, status)
	case http.MethodPost, http.MethodPut:
		user := userFromContext(r.Context())
		if user == nil || user.Role != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin role required")
			return
		}

		var payload struct {
			InspectionEnabled         *bool   `json:"inspection_enabled"`
			BodyArtifactsEnabled      *bool   `json:"body_artifacts_enabled"`
			BodyArtifactsDirectoryRaw string  `json:"body_artifacts_directory"`
			TruncateLogEnabled        *bool   `json:"truncate_log_enabled"`
			WireGuardEnabled          *bool   `json:"wireguard_enabled"`
			WireGuardConfigRaw        *string `json:"wireguard_config"`
		}
		if err := decodeJSONBody(r, &payload); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
			return
		}

		if payload.InspectionEnabled == nil &&
			payload.BodyArtifactsEnabled == nil &&
			strings.TrimSpace(payload.BodyArtifactsDirectoryRaw) == "" &&
			payload.TruncateLogEnabled == nil &&
			payload.WireGuardEnabled == nil &&
			payload.WireGuardConfigRaw == nil {
			writeJSONError(w, http.StatusBadRequest, "at least one setting field is required")
			return
		}

		if payload.InspectionEnabled != nil && s.httpsHandler != nil {
			s.httpsHandler.SetInspection(*payload.InspectionEnabled)
		}

		if payload.BodyArtifactsEnabled != nil || strings.TrimSpace(payload.BodyArtifactsDirectoryRaw) != "" {
			currentEnabled, currentDir := logger.BinaryBodyArtifactStorage()
			enabled := currentEnabled
			dir := currentDir
			if payload.BodyArtifactsEnabled != nil {
				enabled = *payload.BodyArtifactsEnabled
			}
			if trimmedDir := strings.TrimSpace(payload.BodyArtifactsDirectoryRaw); trimmedDir != "" {
				dir = trimmedDir
			}
			if err := logger.SetBinaryBodyArtifactStorage(enabled, dir); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "failed to update body artifact settings")
				return
			}
		}

		if payload.TruncateLogEnabled != nil {
			logger.SetLogTruncation(*payload.TruncateLogEnabled)
			s.truncateLog.Store(*payload.TruncateLogEnabled)
		}

		if payload.WireGuardConfigRaw != nil {
			if s.wireguardRuntime == nil {
				writeJSONError(w, http.StatusServiceUnavailable, "wireguard runtime unavailable")
				return
			}
			if _, err := s.wireguardRuntime.SaveConfig(*payload.WireGuardConfigRaw); err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		}

		if payload.WireGuardEnabled != nil {
			if err := s.applyWireGuardState(*payload.WireGuardEnabled); err != nil {
				statusCode := http.StatusInternalServerError
				if errors.Is(err, wireguard.ErrConfigNotFound) || errors.Is(err, wireguard.ErrConfigEmpty) {
					statusCode = http.StatusBadRequest
				}
				writeJSONError(w, statusCode, err.Error())
				return
			}
		}

		status := s.currentStatusPayload()
		writeJSON(w, http.StatusOK, status)
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPost)
	}
}

func (s *Server) currentStatusPayload() map[string]any {
	dbSize, _ := logger.GetTrafficDBSize()
	inspectionEnabled := true
	if s.httpsHandler != nil {
		inspectionEnabled = s.httpsHandler.IsInspectionEnabled()
	}

	requestCount := s.lastRequestCount.Load()
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM Requests`).Scan(&requestCount); err != nil {
		logger.LogDebug(fmt.Sprintf("dashboard status request count query failed: %v", err))
	} else {
		s.lastRequestCount.Store(requestCount)
	}

	activeSessions := s.lastActiveSession.Load()
	now := s.now().UTC().Format(time.RFC3339Nano)
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM Sessions WHERE expires_at > ?`, now).Scan(&activeSessions); err != nil {
		logger.LogDebug(fmt.Sprintf("dashboard status active sessions query failed: %v", err))
	} else {
		s.lastActiveSession.Store(activeSessions)
	}

	bodyArtifactsEnabled, bodyArtifactsDirectory := logger.BinaryBodyArtifactStorage()
	ports := append([]int(nil), s.additionalTLSPorts...)
	inspectOnly := append([]string(nil), s.inspectOnlySources...)
	wireGuardEnabled := false
	wireGuardInterface := ""
	wireGuardConfigPresent := false
	wireGuardConfigPath := ""
	if s.wireguardRuntime != nil {
		wireGuardStatus, err := s.wireguardRuntime.Status()
		if err != nil {
			logger.LogDebug(fmt.Sprintf("dashboard status wireguard query failed: %v", err))
		} else {
			wireGuardEnabled = wireGuardStatus.Enabled
			wireGuardInterface = wireGuardStatus.Interface
			wireGuardConfigPresent = wireGuardStatus.ConfigPresent
			wireGuardConfigPath = wireGuardStatus.ConfigPath
		}
	}
	egressInterface := ""
	defaultEgressInterface := ""
	if s.egressRuntime != nil {
		egressInterface = strings.TrimSpace(s.egressRuntime.EgressInterface())
		defaultEgressInterface = strings.TrimSpace(s.egressRuntime.DefaultEgressInterface())
	}

	return map[string]any{
		"db_size_bytes":            dbSize,
		"inspection_enabled":       inspectionEnabled,
		"truncate_log_enabled":     s.truncateLog.Load(),
		"request_count":            requestCount,
		"active_sessions":          activeSessions,
		"session_ttl_seconds":      int64(s.sessionTTL.Seconds()),
		"server_time":              s.now().UTC().Format(time.RFC3339Nano),
		"body_artifacts_enabled":   bodyArtifactsEnabled,
		"body_artifacts_directory": bodyArtifactsDirectory,
		"allow_quic":               s.allowQUIC,
		"additional_tls_ports":     ports,
		"inspect_only_sources":     inspectOnly,
		"pcap_path":                s.pcapPath,
		"wireguard_enabled":        wireGuardEnabled,
		"wireguard_interface":      wireGuardInterface,
		"wireguard_config_present": wireGuardConfigPresent,
		"wireguard_config_path":    wireGuardConfigPath,
		"egress_interface":         egressInterface,
		"default_egress_interface": defaultEgressInterface,
	}
}

func (s *Server) applyWireGuardState(enabled bool) error {
	if s.wireguardRuntime == nil {
		return fmt.Errorf("wireguard runtime unavailable")
	}

	if enabled {
		status, err := s.wireguardRuntime.Enable()
		if err != nil {
			return err
		}

		if s.egressRuntime != nil {
			iface := strings.TrimSpace(status.Interface)
			if iface == "" {
				return fmt.Errorf("wireguard enabled but interface name is empty")
			}
			if err := s.egressRuntime.SetEgressInterface(iface); err != nil {
				_, _ = s.wireguardRuntime.Disable()
				return fmt.Errorf("wireguard enabled but failed to switch egress interface: %w", err)
			}
		}
		return nil
	}

	if _, err := s.wireguardRuntime.Disable(); err != nil {
		return err
	}
	if s.egressRuntime == nil {
		return nil
	}

	restoreInterface := strings.TrimSpace(s.egressRuntime.DefaultEgressInterface())
	if restoreInterface == "" {
		restoreInterface = strings.TrimSpace(s.egressRuntime.EgressInterface())
	}
	if restoreInterface == "" {
		return nil
	}
	if err := s.egressRuntime.SetEgressInterface(restoreInterface); err != nil {
		return fmt.Errorf("wireguard disabled but failed to restore egress interface: %w", err)
	}
	return nil
}

func parseRequestLine(requestLine string) (method, url string) {
	line := strings.TrimSpace(firstLine(requestLine))
	if line == "" {
		return "-", "-"
	}
	if line == "BYPASSED" {
		return "BYPASS", "-"
	}
	if line == "INSPECTION PAUSED" {
		return "TUNNEL", "-"
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "-", "-"
	}
	method = strings.ToUpper(parts[0])
	if len(parts) > 1 {
		url = parts[1]
	} else {
		url = "-"
	}
	return method, url
}

func firstLine(value string) string {
	for i, r := range value {
		if r == '\n' || r == '\r' {
			return value[:i]
		}
	}
	return value
}

func detectTrafficMode(requestLine, responseLine string) string {
	req := strings.TrimSpace(firstLine(requestLine))
	res := strings.TrimSpace(firstLine(responseLine))

	if req == "BYPASSED" || res == "BYPASSED" {
		return "bypassed"
	}
	if req == "INSPECTION PAUSED" || res == "INSPECTION PAUSED" {
		return "paused"
	}
	if strings.EqualFold(res, "BLOCKED") || strings.HasPrefix(res, "403") {
		return "blocked"
	}
	return "inspected"
}

func trafficModeCondition(mode string) (string, bool) {
	switch mode {
	case "":
		return "", false
	case "bypassed":
		return `(r.request = 'BYPASSED' OR COALESCE(res.response, '') = 'BYPASSED')`, true
	case "paused":
		return `(r.request = 'INSPECTION PAUSED' OR COALESCE(res.response, '') = 'INSPECTION PAUSED')`, true
	case "blocked":
		return `(COALESCE(res.response, '') = 'BLOCKED' OR COALESCE(res.response, '') LIKE '403 %')`, true
	case "inspected":
		return `NOT (r.request = 'BYPASSED' OR COALESCE(res.response, '') = 'BYPASSED' OR r.request = 'INSPECTION PAUSED' OR COALESCE(res.response, '') = 'INSPECTION PAUSED')`, true
	default:
		return "", false
	}
}
