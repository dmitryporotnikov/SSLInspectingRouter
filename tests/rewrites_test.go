package tests

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/rewrites"
)

func TestRewriteEngine_HeaderAndBody(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rule.json")
	if err := os.WriteFile(rulePath, []byte(`{
		"name": "test",
		"enabled": true,
		"match": { "host": "example.com", "content_type_contains": "text/plain" },
		"actions": {
			"set_headers": { "X-Debug": "true" },
			"replace_body": [{ "from": "Google", "to": "MyApp" }]
		}
	}`), 0644); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	engine := rewrites.NewEngine(dir)
	if stats, err := engine.LoadNow(); err != nil || stats.Total != 1 || stats.Enabled != 1 {
		t.Fatalf("LoadNow = (%+v, %v), want (Total=1, Enabled=1, nil)", stats, err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/hello", nil)
	h := http.Header{
		"Content-Type":     []string{"text/plain"},
		"Transfer-Encoding": []string{"chunked"},
	}

	plan, err := engine.Plan(req, "example.com", 200, h)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if plan == nil {
		t.Fatal("expected non-nil plan")
	}

	plan.ApplyHeaders(h)
	if got := h.Get("X-Debug"); got != "true" {
		t.Fatalf("X-Debug = %q, want %q", got, "true")
	}

	out, changed, err := plan.RewriteBody(h, []byte("Hello Google"))
	if err != nil {
		t.Fatalf("RewriteBody error: %v", err)
	}
	if !changed {
		t.Fatalf("changed = false, want true")
	}
	if string(out) != "Hello MyApp" {
		t.Fatalf("body = %q, want %q", string(out), "Hello MyApp")
	}
	if h.Get("Transfer-Encoding") != "" {
		t.Fatalf("expected Transfer-Encoding to be removed")
	}
	if h.Get("Content-Length") == "" {
		t.Fatalf("expected Content-Length to be set")
	}
}

func TestRewriteEngine_GzipBody(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rule.json"), []byte(`{
		"name": "gzip",
		"enabled": true,
		"actions": { "replace_body": [{ "from": "Google", "to": "MyApp" }] }
	}`), 0644); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	engine := rewrites.NewEngine(dir)
	if stats, err := engine.LoadNow(); err != nil || stats.Total != 1 || stats.Enabled != 1 {
		t.Fatalf("LoadNow = (%+v, %v), want (Total=1, Enabled=1, nil)", stats, err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/hello", nil)
	h := http.Header{
		"Content-Type":     []string{"text/plain"},
		"Content-Encoding": []string{"gzip"},
	}

	plan, err := engine.Plan(req, "example.com", 200, h)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	if plan == nil {
		t.Fatal("expected non-nil plan")
	}

	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	_, _ = zw.Write([]byte("Google"))
	_ = zw.Close()

	out, changed, err := plan.RewriteBody(h, raw.Bytes())
	if err != nil {
		t.Fatalf("RewriteBody error: %v", err)
	}
	if !changed {
		t.Fatalf("changed = false, want true")
	}
	if h.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", h.Get("Content-Encoding"))
	}

	zr, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	decoded, _ := io.ReadAll(zr)
	_ = zr.Close()

	if string(decoded) != "MyApp" {
		t.Fatalf("decoded body = %q, want %q", string(decoded), "MyApp")
	}
}

func TestRewriteEngine_ShouldForceGzip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rule.json"), []byte(`{
		"name": "force",
		"enabled": true,
		"match": { "host": "example.com", "path_prefix": "/api/" },
		"actions": { "replace_body": [{ "from": "a", "to": "b" }] }
	}`), 0644); err != nil {
		t.Fatalf("write rule: %v", err)
	}

	engine := rewrites.NewEngine(dir)
	if _, err := engine.LoadNow(); err != nil {
		t.Fatalf("LoadNow error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/test", nil)
	if !engine.ShouldForceGzip(req, "example.com") {
		t.Fatalf("ShouldForceGzip = false, want true")
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/other", nil)
	if engine.ShouldForceGzip(req2, "example.com") {
		t.Fatalf("ShouldForceGzip = true, want false")
	}
}
