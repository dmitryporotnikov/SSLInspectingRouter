package firewall

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

type Action string

const (
	ActionBlock   Action = "block"
	ActionBypass  Action = "bypass"
	ActionInspect Action = "inspect"
)

type BlockMode string

const (
	BlockModeDisplayPage BlockMode = "display_page"
	BlockModeSilentDrop  BlockMode = "silent_drop"
)

type RuleMatch struct {
	Host      string `json:"host,omitempty"`
	HostRegex string `json:"host_regex,omitempty"`
	IP        string `json:"ip,omitempty"`
	CIDR      string `json:"cidr,omitempty"`
}

type Rule struct {
	ID        int64     `json:"id"`
	Priority  int       `json:"priority"`
	Enabled   bool      `json:"enabled"`
	Action    Action    `json:"action"`
	BlockMode BlockMode `json:"block_mode,omitempty"`
	Match     RuleMatch `json:"match"`
	CreatedAt string    `json:"created_at,omitempty"`
	UpdatedAt string    `json:"updated_at,omitempty"`
}

type Manager struct {
	mu          sync.RWMutex
	enabled     bool
	rules       []Rule
	nextID      int64
	db          *sql.DB
	onRuleChange func([]Rule)
}

var defaultManager = &Manager{
	rules:  []Rule{},
	nextID: 1,
}

func GetManager() *Manager {
	return defaultManager
}

func (m *Manager) Initialize(db *sql.DB) error {
	m.db = db
	if err := m.ensureSchema(); err != nil {
		return fmt.Errorf("ensure firewall schema: %w", err)
	}
	if err := m.loadRules(); err != nil {
		return fmt.Errorf("load firewall rules: %w", err)
	}
	logger.LogInfo("Firewall manager initialized with " + string(rune(len(m.rules))) + " rules")
	return nil
}

func (m *Manager) ensureSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS firewall_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		priority INTEGER NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		action TEXT NOT NULL,
		block_mode TEXT,
		match_json TEXT NOT NULL,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS firewall_config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);
	`
	_, err := m.db.Exec(schema)
	return err
}

func isTransientDBError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked") ||
		strings.Contains(msg, "database is busy") ||
		strings.Contains(msg, "sql logic error: database is locked") ||
		strings.Contains(msg, "busy")
}

func (m *Manager) execWithRetry(query string, args ...any) (any, error) {
	backoff := 5 * time.Millisecond
	maxAttempts := 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, err := m.db.Exec(query, args...)
		if err == nil {
			return result, nil
		}
		if !isTransientDBError(err) {
			return nil, err
		}
		lastErr = err
		if attempt < maxAttempts {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	return nil, lastErr
}

func (m *Manager) queryWithRetry(query string, args ...any) (*sql.Rows, error) {
	backoff := 5 * time.Millisecond
	maxAttempts := 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		rows, err := m.db.Query(query, args...)
		if err == nil {
			return rows, nil
		}
		if !isTransientDBError(err) {
			return nil, err
		}
		lastErr = err
		if attempt < maxAttempts {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	return nil, lastErr
}

func (m *Manager) queryRowWithRetry(query string, args ...any) *sql.Row {
	return m.db.QueryRow(query, args...)
}

func (m *Manager) loadRules() error {
	rows, err := m.queryWithRetry(`
		SELECT id, priority, enabled, action, block_mode, match_json, created_at, updated_at
		FROM firewall_rules ORDER BY priority DESC
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	m.mu.Lock()
	defer m.mu.Unlock()

	var maxID int64 = 0
	for rows.Next() {
		var rule Rule
		var enabled int
		var blockMode sql.NullString
		var matchJSON string
		if err := rows.Scan(&rule.ID, &rule.Priority, &enabled, &rule.Action, &blockMode, &matchJSON, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return err
		}
		rule.Enabled = enabled == 1
		if blockMode.Valid {
			rule.BlockMode = BlockMode(blockMode.String)
		}
		if err := json.Unmarshal([]byte(matchJSON), &rule.Match); err != nil {
			return err
		}
		m.rules = append(m.rules, rule)
		if rule.ID > maxID {
			maxID = rule.ID
		}
	}
	m.nextID = maxID + 1

	// Load enabled state from config
	row := m.queryRowWithRetry("SELECT value FROM firewall_config WHERE key = 'enabled'")
	var enabledVal string
	if err := row.Scan(&enabledVal); err == nil {
		m.enabled = enabledVal == "true"
	}

	return nil
}

func (m *Manager) saveRule(rule Rule) error {
	if m.db == nil {
		return nil
	}
	_, err := m.execWithRetry(`
		INSERT INTO firewall_rules (id, priority, enabled, action, block_mode, match_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			priority = excluded.priority,
			enabled = excluded.enabled,
			action = excluded.action,
			block_mode = excluded.block_mode,
			match_json = excluded.match_json,
			updated_at = excluded.updated_at
	`, rule.ID, rule.Priority, rule.Enabled, rule.Action, rule.BlockMode, mustMarshalJSON(rule.Match), rule.CreatedAt, rule.UpdatedAt)
	return err
}

func (m *Manager) deleteRuleFromDB(id int64) error {
	if m.db == nil {
		return nil
	}
	_, err := m.execWithRetry("DELETE FROM firewall_rules WHERE id = ?", id)
	return err
}

func (m *Manager) saveEnabledState() error {
	if m.db == nil {
		return nil
	}
	enabledVal := "false"
	if m.enabled {
		enabledVal = "true"
	}
	_, err := m.execWithRetry(`
		INSERT INTO firewall_config (key, value) VALUES ('enabled', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, enabledVal)
	return err
}

func mustMarshalJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (m *Manager) Enable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = true
	logger.LogInfo("Firewall mode enabled")
}

func (m *Manager) Disable() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = false
	logger.LogInfo("Firewall mode disabled")
}

func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

func (m *Manager) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if enabled && !m.enabled && !m.hasDefaultBlockAllRule() {
		defaultRule := Rule{
			Priority:  -1000,
			Enabled:   true,
			Action:    ActionBlock,
			BlockMode: BlockModeSilentDrop,
			Match:     RuleMatch{},
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		m.rules = append(m.rules, defaultRule)
		m.sortRulesByPriority()
		// Save the default rule to database
		go m.saveRule(defaultRule)
	}
	m.enabled = enabled
	go m.saveEnabledState()
}

func (m *Manager) SetOnRuleChange(f func([]Rule)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onRuleChange = f
}

func (m *Manager) GetRules() []Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rules := make([]Rule, len(m.rules))
	copy(rules, m.rules)
	return rules
}

func (m *Manager) GetRuleByID(id int64) *Rule {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, rule := range m.rules {
		if rule.ID == id {
			return &rule
		}
	}
	return nil
}

func (m *Manager) AddRule(rule Rule) Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	rule.ID = m.nextID
	m.nextID++
	rule.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	rule.UpdatedAt = rule.CreatedAt
	m.rules = append(m.rules, rule)
	m.sortRulesByPriority()
	m.notifyRuleChange()
	logger.LogInfo("Firewall rule added: id=" + string(rune(rule.ID)) + " action=" + string(rule.Action))
	go m.saveRule(rule)
	return rule
}

func (m *Manager) UpdateRule(id int64, updates Rule) *Rule {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, rule := range m.rules {
		if rule.ID == id {
			m.rules[i].Priority = updates.Priority
			m.rules[i].Enabled = updates.Enabled
			m.rules[i].Action = updates.Action
			m.rules[i].BlockMode = updates.BlockMode
			m.rules[i].Match = updates.Match
			m.rules[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			m.sortRulesByPriority()
			m.notifyRuleChange()
			logger.LogInfo("Firewall rule updated: id=" + string(rune(id)))
			go m.saveRule(m.rules[i])
			return &m.rules[i]
		}
	}
	return nil
}

func (m *Manager) DeleteRule(id int64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, rule := range m.rules {
		if rule.ID == id {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			m.notifyRuleChange()
			logger.LogInfo("Firewall rule deleted: id=" + string(rune(id)))
			go m.deleteRuleFromDB(id)
			return true
		}
	}
	return false
}

func (m *Manager) SetRules(rules []Rule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules = rules
	m.sortRulesByPriority()
	m.notifyRuleChange()
	logger.LogInfo("Firewall rules replaced: count=" + string(rune(len(rules))))
}

func (m *Manager) sortRulesByPriority() {
	sort.Slice(m.rules, func(i, j int) bool {
		return m.rules[i].Priority > m.rules[j].Priority
	})
}

func (m *Manager) notifyRuleChange() {
	if m.onRuleChange != nil {
		rulesCopy := make([]Rule, len(m.rules))
		copy(rulesCopy, m.rules)
		go m.onRuleChange(rulesCopy)
	}
}

func (m *Manager) MatchTraffic(host, ip string) (action Action, blockMode BlockMode, matched bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled {
		return "", "", false
	}

	for _, rule := range m.rules {
		if !rule.Enabled {
			continue
		}

		if m.ruleMatches(rule, host, ip) {
			return rule.Action, rule.BlockMode, true
		}
	}
	return "", "", false
}

func (m *Manager) ruleMatches(rule Rule, host, ip string) bool {
	ruleMatch := rule.Match

	if ruleMatch.Host != "" && host != "" {
		if ruleMatch.Host == host || (len(host) > len(ruleMatch.Host) && host[len(host)-len(ruleMatch.Host)-1:] == "."+ruleMatch.Host) {
			return true
		}
	}

	if ruleMatch.HostRegex != "" && host != "" {
		if matchHostRegex(host, ruleMatch.HostRegex) {
			return true
		}
	}

	if ruleMatch.IP != "" && ip != "" {
		if ruleMatch.IP == ip {
			return true
		}
	}

	if ruleMatch.CIDR != "" && ip != "" {
		if matchCIDR(ip, ruleMatch.CIDR) {
			return true
		}
	}

	if ruleMatch.Host == "" && ruleMatch.HostRegex == "" && ruleMatch.IP == "" && ruleMatch.CIDR == "" {
		return true
	}

	return false
}

func matchHostRegex(host, pattern string) bool {
	return false
}

func (m *Manager) hasDefaultBlockAllRule() bool {
	for _, rule := range m.rules {
		if rule.Priority == -1000 && rule.Action == ActionBlock && rule.Match.Host == "" && rule.Match.HostRegex == "" && rule.Match.IP == "" && rule.Match.CIDR == "" {
			return true
		}
	}
	return false
}

func matchCIDR(ip, cidr string) bool {
	return false
}