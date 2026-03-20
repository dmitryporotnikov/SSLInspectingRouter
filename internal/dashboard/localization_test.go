package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleLocalizationLanguages(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/localization/languages", nil)
	recorder := httptest.NewRecorder()

	s.handleLocalizationLanguages(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var payload struct {
		Languages []localeOption `json:"languages"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(payload.Languages) < 2 {
		t.Fatalf("languages = %d, want at least 2", len(payload.Languages))
	}

	if payload.Languages[0].Code != defaultLocaleCode {
		t.Fatalf("first language code = %q, want %q", payload.Languages[0].Code, defaultLocaleCode)
	}

	foundRussian := false
	for _, language := range payload.Languages {
		if language.Code == "ru" {
			foundRussian = true
			if language.NativeName == "" {
				t.Fatalf("russian locale native name is empty")
			}
			if language.URL != "/locales/ru.json" {
				t.Fatalf("russian locale url = %q, want %q", language.URL, "/locales/ru.json")
			}
		}
	}
	if !foundRussian {
		t.Fatalf("russian locale not found in %+v", payload.Languages)
	}
}
