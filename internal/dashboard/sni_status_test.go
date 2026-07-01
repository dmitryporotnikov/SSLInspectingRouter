package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleStatusSNIOnlyModeRejectsNonAdmin(t *testing.T) {
	db := openDashboardTestDB(t)
	s := &Server{
		db:  db,
		now: time.Now,
	}

	// Without an admin user, the PUT should be rejected even if the field
	// is present. The handler returns 403.
	req := httptest.NewRequest(http.MethodPut, "/api/v1/status", strings.NewReader(`{"sni_only_mode":true}`))
	recorder := httptest.NewRecorder()
	s.handleStatus(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestHandleStatusSNIOnlyModeInPayloadAfterInit(t *testing.T) {
	db := openDashboardTestDB(t)
	s := &Server{
		db:          db,
		now:         time.Now,
		sniOnlyMode: true,
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/status", strings.NewReader(`{"sni_only_mode":true}`))
	req = req.WithContext(context.WithValue(req.Context(), contextUserKey, &DashboardUser{
		ID:   1,
		Role: "admin",
	}))
	s.handleStatus(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	enabled, ok := payload["sni_only_mode"].(bool)
	if !ok {
		t.Fatalf("sni_only_mode missing or not a bool: %v", payload["sni_only_mode"])
	}
	if !enabled {
		t.Fatalf("sni_only_mode = false, want true from initial state")
	}
}

func TestHandleStatusSNIOnlyModeInPayload(t *testing.T) {
	db := openDashboardTestDB(t)
	s := &Server{
		db:          db,
		now:         time.Now,
		sniOnlyMode: true,
	}

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	s.handleStatus(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	enabled, ok := payload["sni_only_mode"].(bool)
	if !ok {
		t.Fatalf("sni_only_mode missing or not a bool: %v", payload["sni_only_mode"])
	}
	if !enabled {
		t.Fatalf("sni_only_mode = false, want true from initial state")
	}
}

func TestTrafficModeConditionSNI(t *testing.T) {
	cond, ok := trafficModeCondition("sni")
	if !ok {
		t.Fatal("trafficModeCondition(\"sni\") = false, want true")
	}
	if !strings.Contains(cond, "SNI-ONLY") {
		t.Fatalf("SNI condition missing SNI-ONLY marker: %q", cond)
	}
}

func TestDetectTrafficModeSNI(t *testing.T) {
	if got := detectTrafficMode("SNI-ONLY", "SNI-ONLY"); got != "sni" {
		t.Fatalf("detectTrafficMode SNI-ONLY = %q, want %q", got, "sni")
	}
	if got := detectTrafficMode("SNI-ONLY", ""); got != "sni" {
		t.Fatalf("detectTrafficMode SNI-ONLY req = %q, want %q", got, "sni")
	}
}

func TestParseRequestLineSNI(t *testing.T) {
	method, url := parseRequestLine("SNI-ONLY")
	if method != "SNI" || url != "-" {
		t.Fatalf("parseRequestLine SNI-ONLY = (%q, %q), want (SNI, -)", method, url)
	}
}
