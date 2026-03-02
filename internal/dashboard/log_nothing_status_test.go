package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

func TestHandleStatusLogNothingToggle(t *testing.T) {
	db := openDashboardTestDB(t)

	original := logger.IsTrafficLoggingEnabled()
	logger.SetTrafficLogging(true)
	t.Cleanup(func() {
		logger.SetTrafficLogging(original)
	})

	s := &Server{
		db:  db,
		now: time.Now,
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/status", strings.NewReader(`{"log_nothing_enabled":true}`))
	req = req.WithContext(context.WithValue(req.Context(), contextUserKey, &DashboardUser{
		ID:   1,
		Role: "admin",
	}))
	recorder := httptest.NewRecorder()

	s.handleStatus(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if logger.IsTrafficLoggingEnabled() {
		t.Fatalf("traffic logging should be disabled")
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if logNothing, _ := payload["log_nothing_enabled"].(bool); !logNothing {
		t.Fatalf("log_nothing_enabled = %v, want true", payload["log_nothing_enabled"])
	}
}
