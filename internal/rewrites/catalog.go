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
		path, err := safeRuleFilePath(dir, name)
		if err != nil {
			return nil, err
		}
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

func safeRuleFilePath(dir, fileName string) (string, error) {
	trimmedDir := strings.TrimSpace(dir)
	if trimmedDir == "" {
		return "", errors.New("rewrite directory is empty")
	}
	baseDir := filepath.Clean(trimmedDir)

	name := strings.TrimSpace(fileName)
	if name == "" {
		return "", errors.New("rewrite filename is empty")
	}
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("invalid rewrite filename %q", fileName)
	}
	if !strings.EqualFold(filepath.Ext(name), ".json") {
		return "", fmt.Errorf("invalid rewrite file extension %q", fileName)
	}

	path := filepath.Join(baseDir, name)
	rel, err := filepath.Rel(baseDir, path)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("rewrite file escapes configured directory: %q", fileName)
	}
	return path, nil
}
