package rewrites

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RuleSource describes a rule and where it came from on disk.
type RuleSource struct {
	File  string `json:"file"`
	Index int    `json:"index"`
	Rule  Rule   `json:"rule"`
}

// ParseRulesJSON parses one rewrite JSON payload into one or more rules.
// Supported payloads:
//   - single rule object
//   - {"rules":[...]}
//   - array of rules
func ParseRulesJSON(data []byte) ([]Rule, error) {
	return parseRuleFile(data)
}

// ValidateRule checks whether a rule compiles and can be applied by the engine.
func ValidateRule(rule Rule) error {
	_, err := compileRule(rule, "rule")
	return err
}

// LoadRuleSources reads rewrite JSON files from dir and returns rules with source metadata.
func LoadRuleSources(dir string) ([]RuleSource, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	fileNames := make([]string, 0, len(entries))
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

	out := make([]RuleSource, 0, len(fileNames))
	for _, name := range fileNames {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		rules, err := ParseRulesJSON(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}

		for i, rule := range rules {
			out = append(out, RuleSource{
				File:  name,
				Index: i + 1,
				Rule:  rule,
			})
		}
	}

	return out, nil
}
