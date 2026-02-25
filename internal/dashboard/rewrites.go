package dashboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/rewrites"
)

const dashboardManagedRewriteFileName = "dashboard-managed.rules.json"

type rewriteRuleItem struct {
	Key       string        `json:"key"`
	Managed   bool          `json:"managed"`
	ManagedID int           `json:"managed_id,omitempty"`
	File      string        `json:"file"`
	Index     int           `json:"index"`
	Rule      rewrites.Rule `json:"rule"`
}

func (s *Server) handleRewrites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		payload, err := s.currentRewritesPayload()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to load rewrite rules")
			return
		}
		writeJSON(w, http.StatusOK, payload)
	case http.MethodPost:
		user := userFromContext(r.Context())
		if user == nil || user.Role != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin role required")
			return
		}
		if s.rewriter == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "rewrite engine unavailable")
			return
		}

		rule, err := decodeRewriteRulePayload(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateRewriteRuleForEditor(rule); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		rules, err := s.loadManagedRewriteRules()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to load managed rewrite rules")
			return
		}
		rules = append(rules, rule)

		if err := s.saveManagedRewriteRulesTransactional(rules); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{
			"managed_id": len(rules),
			"rule":       rule,
		})
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleRewriteByID(w http.ResponseWriter, r *http.Request) {
	managedID, err := parseManagedRewriteID(r.URL.Path)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.rewriter == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "rewrite engine unavailable")
		return
	}

	switch r.Method {
	case http.MethodGet:
		rules, err := s.loadManagedRewriteRules()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to load managed rewrite rules")
			return
		}
		if managedID < 1 || managedID > len(rules) {
			writeJSONError(w, http.StatusNotFound, "rewrite rule not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"managed_id": managedID,
			"rule":       rules[managedID-1],
		})
	case http.MethodPut:
		user := userFromContext(r.Context())
		if user == nil || user.Role != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin role required")
			return
		}

		rule, err := decodeRewriteRulePayload(r)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateRewriteRuleForEditor(rule); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}

		rules, err := s.loadManagedRewriteRules()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to load managed rewrite rules")
			return
		}
		if managedID < 1 || managedID > len(rules) {
			writeJSONError(w, http.StatusNotFound, "rewrite rule not found")
			return
		}
		rules[managedID-1] = rule

		if err := s.saveManagedRewriteRulesTransactional(rules); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"managed_id": managedID,
			"rule":       rule,
		})
	case http.MethodDelete:
		user := userFromContext(r.Context())
		if user == nil || user.Role != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin role required")
			return
		}

		rules, err := s.loadManagedRewriteRules()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to load managed rewrite rules")
			return
		}
		if managedID < 1 || managedID > len(rules) {
			writeJSONError(w, http.StatusNotFound, "rewrite rule not found")
			return
		}

		next := append([]rewrites.Rule{}, rules[:managedID-1]...)
		next = append(next, rules[managedID:]...)

		if err := s.saveManagedRewriteRulesTransactional(next); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"deleted":    true,
			"managed_id": managedID,
		})
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodDelete)
	}
}

func (s *Server) currentRewritesPayload() (map[string]any, error) {
	rules := make([]rewrites.Rule, 0)
	items := make([]rewriteRuleItem, 0)

	if s.rewriter == nil {
		return map[string]any{
			"rules":        rules,
			"items":        items,
			"managed_file": dashboardManagedRewriteFileName,
		}, nil
	}

	jsonFileCount, _ := countRewriteJSONFiles(s.rewriter.Dir())

	sources, err := rewrites.LoadRuleSources(s.rewriter.Dir())
	if err != nil {
		rules, items = activeRewriteSnapshot(s.rewriter.ListRules())
		return map[string]any{
			"rules":        rules,
			"items":        items,
			"managed_file": dashboardManagedRewriteFileName,
			"warning":      err.Error(),
		}, nil
	}

	if len(sources) == 0 && jsonFileCount > 0 {
		activeRules := s.rewriter.ListRules()
		if len(activeRules) > 0 {
			rules, items = activeRewriteSnapshot(activeRules)
			return map[string]any{
				"rules":        rules,
				"items":        items,
				"managed_file": dashboardManagedRewriteFileName,
				"warning":      "transient rewrite file read detected; showing active rule snapshot",
			}, nil
		}
	}

	for _, source := range sources {
		item := rewriteRuleItem{
			Managed: source.File == dashboardManagedRewriteFileName,
			File:    source.File,
			Index:   source.Index,
			Rule:    source.Rule,
		}
		if item.Managed {
			item.ManagedID = source.Index
			item.Key = fmt.Sprintf("managed:%d", source.Index)
		} else {
			item.Key = fmt.Sprintf("external:%s#%d", source.File, source.Index)
		}

		items = append(items, item)
		rules = append(rules, source.Rule)
	}

	return map[string]any{
		"rules":        rules,
		"items":        items,
		"managed_file": dashboardManagedRewriteFileName,
	}, nil
}

func activeRewriteSnapshot(activeRules []rewrites.Rule) ([]rewrites.Rule, []rewriteRuleItem) {
	rules := make([]rewrites.Rule, 0)
	items := make([]rewriteRuleItem, 0)
	if activeRules == nil {
		return rules, items
	}
	rules = append(rules, activeRules...)
	for i, rule := range activeRules {
		items = append(items, rewriteRuleItem{
			Key:     fmt.Sprintf("active:%d", i+1),
			Managed: false,
			File:    "(active)",
			Index:   i + 1,
			Rule:    rule,
		})
	}
	return rules, items
}

func countRewriteJSONFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			count++
		}
	}
	return count, nil
}

func parseManagedRewriteID(pathValue string) (int, error) {
	prefixes := []string{
		"/api/v1/rewrites/",
		"/api/rewrites/",
	}
	for _, prefix := range prefixes {
		id, err := parsePathID(pathValue, prefix)
		if err == nil {
			return int(id), nil
		}
	}
	return 0, errors.New("invalid resource id")
}

func validateRewriteRuleForEditor(rule rewrites.Rule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return errors.New("rule.name is required")
	}

	if len(rule.Actions.SetHeaders) == 0 &&
		len(rule.Actions.AddHeaders) == 0 &&
		len(rule.Actions.DelHeaders) == 0 &&
		len(rule.Actions.ReplaceBody) == 0 &&
		len(rule.Actions.ReplaceBodyRegex) == 0 {
		return errors.New("at least one action is required")
	}

	if err := rewrites.ValidateRule(rule); err != nil {
		return err
	}
	return nil
}

func decodeRewriteRulePayload(r *http.Request) (rewrites.Rule, error) {
	defer r.Body.Close()

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return rewrites.Rule{}, errors.New("failed to read request body")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return rewrites.Rule{}, errors.New("request body is required")
	}

	var wrapped struct {
		Rule rewrites.Rule `json:"rule"`
	}
	if err := decodeJSONStrict(body, &wrapped); err == nil && !reflect.DeepEqual(wrapped.Rule, rewrites.Rule{}) {
		return wrapped.Rule, nil
	}

	var rule rewrites.Rule
	if err := decodeJSONStrict(body, &rule); err == nil {
		return rule, nil
	}

	return rewrites.Rule{}, errors.New("invalid JSON payload")
}

func decodeJSONStrict(body []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("body must contain a single JSON object")
		}
		return err
	}
	return nil
}

func (s *Server) managedRewriteFilePath() (string, error) {
	if s.rewriter == nil {
		return "", errors.New("rewrite engine unavailable")
	}
	dir := strings.TrimSpace(s.rewriter.Dir())
	if dir == "" {
		return "", errors.New("rewrite directory is not configured")
	}
	return filepath.Join(dir, dashboardManagedRewriteFileName), nil
}

func (s *Server) loadManagedRewriteRules() ([]rewrites.Rule, error) {
	path, err := s.managedRewriteFilePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return make([]rewrites.Rule, 0), nil
		}
		return nil, err
	}

	rules, err := rewrites.ParseRulesJSON(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dashboardManagedRewriteFileName, err)
	}
	if rules == nil {
		rules = make([]rewrites.Rule, 0)
	}
	return rules, nil
}

func (s *Server) saveManagedRewriteRulesTransactional(rules []rewrites.Rule) error {
	path, err := s.managedRewriteFilePath()
	if err != nil {
		return err
	}

	backupData, backupExists, err := readOptionalFile(path)
	if err != nil {
		return err
	}

	if err := writeManagedRewriteRules(path, rules); err != nil {
		return err
	}

	if s.rewriter == nil {
		return nil
	}

	if _, err := s.rewriter.LoadNow(); err != nil {
		_ = restoreOptionalFile(path, backupData, backupExists)
		_, _ = s.rewriter.LoadNow()
		return fmt.Errorf("failed to reload rewrite rules: %w", err)
	}
	return nil
}

func readOptionalFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return data, true, nil
}

func restoreOptionalFile(path string, data []byte, exists bool) error {
	if !exists {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeManagedRewriteRules(path string, rules []rewrites.Rule) error {
	if len(rules) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	payload := map[string]any{
		"rules": rules,
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tempPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tempPath, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return nil
}
