package dashboard

import (
	"net/http"
	"sort"
	"strings"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/blocklist"
)

func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.currentPolicyPayload())
	case http.MethodPost, http.MethodPut:
		user := userFromContext(r.Context())
		if user == nil || user.Role != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin role required")
			return
		}

		var payload struct {
			DropList   []string `json:"drop_list"`
			BypassList []string `json:"bypass_list"`
		}
		if err := decodeJSONBody(r, &payload); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
			return
		}
		if payload.DropList == nil && payload.BypassList == nil {
			writeJSONError(w, http.StatusBadRequest, "at least one policy list is required")
			return
		}

		if payload.DropList != nil {
			dropEntries := normalizePolicyEntries(payload.DropList)
			dropList := blocklist.NewBlockList(dropEntries)
			if s.httpHandler != nil {
				s.httpHandler.SetBlockList(dropList)
			}
			if s.httpsHandler != nil {
				s.httpsHandler.SetBlockList(dropList)
			}
			if s.dnsProxy != nil {
				s.dnsProxy.SetBlockList(dropList)
			}
		}

		if payload.BypassList != nil {
			bypassEntries := normalizePolicyEntries(payload.BypassList)
			bypassList := blocklist.NewBlockList(bypassEntries)
			if s.httpHandler != nil {
				s.httpHandler.SetBypassList(bypassList)
			}
			if s.httpsHandler != nil {
				s.httpsHandler.SetBypassList(bypassList)
			}
		}

		writeJSON(w, http.StatusOK, s.currentPolicyPayload())
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPost)
	}
}

func (s *Server) currentPolicyPayload() map[string]any {
	dropList := []string{}
	bypassList := []string{}

	if s.httpHandler != nil {
		dropList = s.httpHandler.BlockListEntries()
		bypassList = s.httpHandler.BypassListEntries()
	} else if s.httpsHandler != nil {
		dropList = s.httpsHandler.BlockListEntries()
		bypassList = s.httpsHandler.BypassListEntries()
	}

	return map[string]any{
		"drop_list":   dropList,
		"bypass_list": bypassList,
	}
}

func normalizePolicyEntries(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, row := range raw {
		for _, token := range strings.Split(row, ",") {
			normalized := blocklist.NormalizeFQDN(token)
			if normalized == "" {
				continue
			}
			if _, exists := seen[normalized]; exists {
				continue
			}
			seen[normalized] = struct{}{}
			out = append(out, normalized)
		}
	}
	sort.Strings(out)
	return out
}
