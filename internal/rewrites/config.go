package rewrites

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Rule is the JSON-serializable configuration for a single rewrite rule.
type Rule struct {
	Name    string  `json:"name,omitempty"`
	Enabled *bool   `json:"enabled,omitempty"`
	Match   Match   `json:"match,omitempty"`
	Actions Actions `json:"actions,omitempty"`
}

type Match struct {
	Host      string `json:"host,omitempty"`       // exact, case-insensitive
	HostRegex string `json:"host_regex,omitempty"` // RE2

	PathPrefix string `json:"path_prefix,omitempty"` // matches request URI prefix (includes query string)
	PathRegex  string `json:"path_regex,omitempty"`  // RE2 against request URI (includes query string)

	Method  string   `json:"method,omitempty"`  // exact, case-insensitive
	Methods []string `json:"methods,omitempty"` // exact, case-insensitive

	Status   int   `json:"status,omitempty"`
	Statuses []int `json:"statuses,omitempty"`

	ContentTypeContains string `json:"content_type_contains,omitempty"` // case-insensitive substring
	ContentTypeRegex    string `json:"content_type_regex,omitempty"`    // RE2 against Content-Type

	RequestHeaderContains  map[string]string `json:"request_header_contains,omitempty"`  // header substring match (any value)
	ResponseHeaderContains map[string]string `json:"response_header_contains,omitempty"` // header substring match (any value)
}

type Actions struct {
	SetHeaders map[string]string `json:"set_headers,omitempty"`
	AddHeaders map[string]string `json:"add_headers,omitempty"`
	DelHeaders []string          `json:"del_headers,omitempty"`

	ReplaceBody      []Replacement      `json:"replace_body,omitempty"`
	ReplaceBodyRegex []RegexReplacement `json:"replace_body_regex,omitempty"`
}

type Replacement struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type RegexReplacement struct {
	Pattern string `json:"pattern"`
	Replace string `json:"replace"`
}

type compiledRule struct {
	name    string
	enabled bool

	match compiledMatch

	headerOps []headerOp
	bodyOps   []bodyOp
}

type compiledMatch struct {
	host      string
	hostRegex *regexp.Regexp

	pathPrefix string
	pathRegex  *regexp.Regexp

	methods map[string]struct{}

	statuses map[int]struct{}

	contentTypeContains string // lower-case substring
	contentTypeRegex    *regexp.Regexp

	reqHeaderContains  map[string]string
	respHeaderContains map[string]string
}

func compileRule(rule Rule, fallbackName string) (compiledRule, error) {
	name := strings.TrimSpace(rule.Name)
	if name == "" {
		name = fallbackName
	}

	enabled := true
	if rule.Enabled != nil {
		enabled = *rule.Enabled
	}

	cm := compiledMatch{
		host:               strings.ToLower(strings.TrimSpace(rule.Match.Host)),
		pathPrefix:         strings.TrimSpace(rule.Match.PathPrefix),
		contentTypeContains: strings.ToLower(strings.TrimSpace(rule.Match.ContentTypeContains)),
		reqHeaderContains:  make(map[string]string),
		respHeaderContains: make(map[string]string),
	}

	if v := strings.TrimSpace(rule.Match.HostRegex); v != "" {
		re, err := regexp.Compile(v)
		if err != nil {
			return compiledRule{}, fmt.Errorf("invalid match.host_regex: %w", err)
		}
		cm.hostRegex = re
	}
	if v := strings.TrimSpace(rule.Match.PathRegex); v != "" {
		re, err := regexp.Compile(v)
		if err != nil {
			return compiledRule{}, fmt.Errorf("invalid match.path_regex: %w", err)
		}
		cm.pathRegex = re
	}
	if v := strings.TrimSpace(rule.Match.ContentTypeRegex); v != "" {
		re, err := regexp.Compile(v)
		if err != nil {
			return compiledRule{}, fmt.Errorf("invalid match.content_type_regex: %w", err)
		}
		cm.contentTypeRegex = re
	}

	methods := append([]string{}, rule.Match.Methods...)
	if v := strings.TrimSpace(rule.Match.Method); v != "" {
		methods = append(methods, v)
	}
	if len(methods) > 0 {
		cm.methods = make(map[string]struct{}, len(methods))
		for _, m := range methods {
			m = strings.ToUpper(strings.TrimSpace(m))
			if m == "" {
				continue
			}
			cm.methods[m] = struct{}{}
		}
	}

	statuses := append([]int{}, rule.Match.Statuses...)
	if rule.Match.Status != 0 {
		statuses = append(statuses, rule.Match.Status)
	}
	if len(statuses) > 0 {
		cm.statuses = make(map[int]struct{}, len(statuses))
		for _, s := range statuses {
			if s <= 0 {
				continue
			}
			cm.statuses[s] = struct{}{}
		}
	}

	for k, v := range rule.Match.RequestHeaderContains {
		key := http.CanonicalHeaderKey(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		cm.reqHeaderContains[key] = v
	}
	for k, v := range rule.Match.ResponseHeaderContains {
		key := http.CanonicalHeaderKey(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		cm.respHeaderContains[key] = v
	}
	if len(cm.reqHeaderContains) == 0 {
		cm.reqHeaderContains = nil
	}
	if len(cm.respHeaderContains) == 0 {
		cm.respHeaderContains = nil
	}

	var headerOps []headerOp
	if len(rule.Actions.DelHeaders) > 0 {
		for _, k := range rule.Actions.DelHeaders {
			key := http.CanonicalHeaderKey(strings.TrimSpace(k))
			if key == "" {
				continue
			}
			headerOps = append(headerOps, headerOp{typ: headerOpDel, name: key})
		}
	}
	if len(rule.Actions.SetHeaders) > 0 {
		keys := make([]string, 0, len(rule.Actions.SetHeaders))
		for k := range rule.Actions.SetHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			key := http.CanonicalHeaderKey(strings.TrimSpace(k))
			if key == "" {
				continue
			}
			headerOps = append(headerOps, headerOp{typ: headerOpSet, name: key, value: rule.Actions.SetHeaders[k]})
		}
	}
	if len(rule.Actions.AddHeaders) > 0 {
		keys := make([]string, 0, len(rule.Actions.AddHeaders))
		for k := range rule.Actions.AddHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			key := http.CanonicalHeaderKey(strings.TrimSpace(k))
			if key == "" {
				continue
			}
			headerOps = append(headerOps, headerOp{typ: headerOpAdd, name: key, value: rule.Actions.AddHeaders[k]})
		}
	}

	var bodyOps []bodyOp
	for _, r := range rule.Actions.ReplaceBody {
		from := []byte(r.From)
		if len(from) == 0 {
			return compiledRule{}, fmt.Errorf("replace_body.from must be non-empty")
		}
		bodyOps = append(bodyOps, bodyOp{
			typ:  bodyOpReplace,
			from: from,
			to:   []byte(r.To),
		})
	}
	for _, r := range rule.Actions.ReplaceBodyRegex {
		pattern := strings.TrimSpace(r.Pattern)
		if pattern == "" {
			return compiledRule{}, fmt.Errorf("replace_body_regex.pattern must be non-empty")
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return compiledRule{}, fmt.Errorf("invalid replace_body_regex.pattern: %w", err)
		}
		bodyOps = append(bodyOps, bodyOp{
			typ:         bodyOpRegex,
			re:          re,
			replacement: []byte(r.Replace),
		})
	}

	return compiledRule{
		name:      name,
		enabled:   enabled,
		match:     cm,
		headerOps: headerOps,
		bodyOps:   bodyOps,
	}, nil
}

