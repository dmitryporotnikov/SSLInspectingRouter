package dashboard

import (
	"net/http"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/firewall"
)

func (s *Server) handleFirewallStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

	fm := firewall.GetManager()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": fm.IsEnabled(),
	})
}

func (s *Server) handleFirewallRules(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	if user == nil || user.Role != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin role required")
		return
	}

	fm := firewall.GetManager()

	switch r.Method {
	case http.MethodGet:
		rules := fm.GetRules()
		writeJSON(w, http.StatusOK, map[string]any{
			"rules": rules,
			"total": len(rules),
		})
	case http.MethodPut:
		var payload struct {
			Enabled bool `json:"enabled"`
		}
		if err := decodeJSONBody(r, &payload); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
			return
		}
		fm.SetEnabled(payload.Enabled)
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled": fm.IsEnabled(),
		})
	case http.MethodPost:
		var rule firewall.Rule
		if err := decodeJSONBody(r, &rule); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
			return
		}
		if rule.Action == "" || (rule.Action != "block" && rule.Action != "bypass" && rule.Action != "inspect") {
			writeJSONError(w, http.StatusBadRequest, "action must be 'block', 'bypass', or 'inspect'")
			return
		}
		if rule.Action == "block" && rule.BlockMode == "" {
			rule.BlockMode = firewall.BlockModeDisplayPage
		}
		added := fm.AddRule(rule)
		writeJSON(w, http.StatusCreated, map[string]any{
			"rule": added,
		})
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPost, http.MethodPut)
	}
}

func (s *Server) handleFirewallRuleByID(w http.ResponseWriter, r *http.Request) {
	user := userFromContext(r.Context())
	if user == nil || user.Role != "admin" {
		writeJSONError(w, http.StatusForbidden, "admin role required")
		return
	}

	fm := firewall.GetManager()

	idToken, err := parsePathID(r.URL.Path, "/api/v1/firewall/rules/")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	switch r.Method {
	case http.MethodGet:
		rule := fm.GetRuleByID(idToken)
		if rule == nil {
			writeJSONError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"rule": rule,
		})
	case http.MethodPut:
		var updates firewall.Rule
		if err := decodeJSONBody(r, &updates); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
			return
		}
		updated := fm.UpdateRule(idToken, updates)
		if updated == nil {
			writeJSONError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"rule": updated,
		})
	case http.MethodDelete:
		if !fm.DeleteRule(idToken) {
			writeJSONError(w, http.StatusNotFound, "rule not found")
			return
		}
		writeJSON(w, http.StatusNoContent, nil)
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodDelete)
	}
}