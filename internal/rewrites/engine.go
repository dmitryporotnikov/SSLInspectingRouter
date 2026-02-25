package rewrites

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Engine loads rewrite rules from a directory and creates per-response rewrite plans.
// It is safe for concurrent use.
type Engine struct {
	dir            string
	reloadInterval time.Duration

	lastCheckUnixNano atomic.Int64

	mu      sync.Mutex
	lastSig string

	rules atomic.Value // ruleSet
}

type ruleSet struct {
	rules    []compiledRule
	rawRules []Rule
}

type Stats struct {
	Total   int
	Enabled int
}

// NewEngine creates a rewrite engine reading rules from dir.
func NewEngine(dir string) *Engine {
	e := &Engine{
		dir:            dir,
		reloadInterval: 1 * time.Second,
	}
	e.rules.Store(ruleSet{})
	return e
}

func (e *Engine) Dir() string {
	return e.dir
}

// ListRules returns the currently active rewrite rules.
func (e *Engine) ListRules() []Rule {
	rs := e.rules.Load().(ruleSet)
	return rs.rawRules
}

// LoadNow forces a rules reload and returns rule stats.
// If an error occurs, previously loaded rules remain active.
func (e *Engine) LoadNow() (Stats, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	sig, sigErr := dirSignature(e.dir)
	if sigErr != nil {
		return e.rules.Load().(ruleSet).stats(), sigErr
	}

	compiled, raw, loadErr := loadAndCompileRules(e.dir)
	e.lastSig = sig
	if loadErr != nil {
		return e.rules.Load().(ruleSet).stats(), loadErr
	}

	e.rules.Store(ruleSet{rules: compiled, rawRules: raw})
	return (ruleSet{rules: compiled}).stats(), nil
}

// DefaultDir returns the preferred rewrites directory.
// Resolution order:
//  1. $SSLINSPECTINGROUTER_REWRITES_DIR if set
//  2. ./rewrites if it exists
//  3. <exeDir>/rewrites (may not exist)
func DefaultDir() string {
	if v := strings.TrimSpace(os.Getenv("SSLINSPECTINGROUTER_REWRITES_DIR")); v != "" {
		return v
	}

	if cwd, err := os.Getwd(); err == nil {
		cwdDir := filepath.Join(cwd, "rewrites")
		if fi, err := os.Stat(cwdDir); err == nil && fi.IsDir() {
			return cwdDir
		}
	}

	exePath, err := os.Executable()
	if err != nil {
		return "rewrites"
	}
	return filepath.Join(filepath.Dir(exePath), "rewrites")
}

// Plan creates a rewrite plan for a response. It may return a non-nil error if the
// engine failed to reload updated rules; in that case the returned plan is based on
// the last successfully loaded rule set.
func (e *Engine) Plan(req *http.Request, targetHost string, statusCode int, respHeader http.Header) (*Plan, error) {
	reloadErr := e.maybeReload(time.Now())

	rs := e.rules.Load().(ruleSet)
	if len(rs.rules) == 0 {
		return nil, reloadErr
	}

	plan := &Plan{}
	for _, rule := range rs.rules {
		if !rule.enabled {
			continue
		}
		if !rule.matches(req, targetHost, statusCode, respHeader) {
			continue
		}
		plan.appliedRules = append(plan.appliedRules, rule.name)
		plan.headerOps = append(plan.headerOps, rule.headerOps...)
		plan.bodyOps = append(plan.bodyOps, rule.bodyOps...)
	}

	if !plan.HasChanges() {
		return nil, reloadErr
	}
	return plan, reloadErr
}

// ShouldForceGzip returns true if any enabled rule that could match this request has body rewrites.
// The caller can use this to ensure upstream content-encoding is decodable (gzip/identity).
func (e *Engine) ShouldForceGzip(req *http.Request, targetHost string) bool {
	_ = e.maybeReload(time.Now())

	rs := e.rules.Load().(ruleSet)
	for _, rule := range rs.rules {
		if !rule.enabled || !rule.hasBodyOps() {
			continue
		}
		if rule.requestMatches(req, targetHost) {
			return true
		}
	}
	return false
}

func (e *Engine) maybeReload(now time.Time) error {
	last := time.Unix(0, e.lastCheckUnixNano.Load())
	if !last.IsZero() && now.Sub(last) < e.reloadInterval {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	last = time.Unix(0, e.lastCheckUnixNano.Load())
	if !last.IsZero() && now.Sub(last) < e.reloadInterval {
		return nil
	}
	e.lastCheckUnixNano.Store(now.UnixNano())

	sig, sigErr := dirSignature(e.dir)
	if sigErr != nil {
		return sigErr
	}
	if sig == e.lastSig {
		return nil
	}

	compiled, raw, loadErr := loadAndCompileRules(e.dir)
	e.lastSig = sig
	if loadErr != nil {
		return loadErr
	}

	e.rules.Store(ruleSet{rules: compiled, rawRules: raw})
	return nil
}

func (rs ruleSet) stats() Stats {
	stats := Stats{Total: len(rs.rules)}
	for _, r := range rs.rules {
		if r.enabled {
			stats.Enabled++
		}
	}
	return stats
}

func dirSignature(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "missing", nil
		}
		return "", err
	}

	type item struct {
		name string
		mod  int64
		size int64
	}
	var items []item
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if !strings.EqualFold(filepath.Ext(ent.Name()), ".json") {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			return "", err
		}
		items = append(items, item{
			name: ent.Name(),
			mod:  info.ModTime().UnixNano(),
			size: info.Size(),
		})
	}

	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })

	var b strings.Builder
	b.WriteString("v1;")
	for _, it := range items {
		b.WriteString(it.name)
		b.WriteByte('|')
		b.WriteString(fmt.Sprintf("%d|%d;", it.mod, it.size))
	}
	return b.String(), nil
}

func loadAndCompileRules(dir string) ([]compiledRule, []Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	var fileNames []string
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if !strings.EqualFold(filepath.Ext(ent.Name()), ".json") {
			continue
		}
		fileNames = append(fileNames, ent.Name())
	}
	sort.Strings(fileNames)

	var out []compiledRule
	var rawOut []Rule
	for _, name := range fileNames {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}

		rules, err := parseRuleFile(data)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}

		rawOut = append(rawOut, rules...)

		for i, rule := range rules {
			compiled, err := compileRule(rule, fmt.Sprintf("%s#%d", name, i+1))
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", name, err)
			}
			out = append(out, compiled)
		}
	}

	return out, rawOut, nil
}

func parseRuleFile(data []byte) ([]Rule, error) {
	trim := bytes.TrimSpace(data)
	if len(trim) == 0 {
		return nil, nil
	}
	if trim[0] == '[' {
		var rules []Rule
		if err := json.Unmarshal(trim, &rules); err != nil {
			return nil, err
		}
		return rules, nil
	}
	if trim[0] != '{' {
		return nil, fmt.Errorf("expected JSON object or array")
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trim, &obj); err != nil {
		return nil, err
	}
	if rawRules, ok := obj["rules"]; ok {
		var rules []Rule
		if err := json.Unmarshal(rawRules, &rules); err != nil {
			return nil, err
		}
		return rules, nil
	}

	var rule Rule
	if err := json.Unmarshal(trim, &rule); err != nil {
		return nil, err
	}
	return []Rule{rule}, nil
}
