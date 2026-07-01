package dashboard

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

const defaultLocaleCode = "en"

type localeBundleMeta struct {
	Code       string `json:"code"`
	Name       string `json:"name"`
	NativeName string `json:"native_name"`
}

type localeBundle struct {
	Meta localeBundleMeta `json:"meta"`
}

type localeOption struct {
	Code       string `json:"code"`
	Name       string `json:"name"`
	NativeName string `json:"native_name"`
	URL        string `json:"url"`
}

func availableLocales() ([]localeOption, error) {
	entries, err := fs.ReadDir(frontendFiles, "frontend/locales")
	if err != nil {
		return nil, err
	}

	locales := make([]localeOption, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if path.Ext(name) != ".json" {
			continue
		}

		filePath := path.Join("frontend/locales", name)
		raw, err := fs.ReadFile(frontendFiles, filePath)
		if err != nil {
			logger.LogError("dashboard locale read failed for " + filePath + ": " + err.Error())
			continue
		}

		var bundle localeBundle
		if err := json.Unmarshal(raw, &bundle); err != nil {
			logger.LogError("dashboard locale decode failed for " + filePath + ": " + err.Error())
			continue
		}

		code := strings.TrimSpace(bundle.Meta.Code)
		if code == "" {
			code = strings.TrimSuffix(name, path.Ext(name))
		}
		displayName := strings.TrimSpace(bundle.Meta.Name)
		if displayName == "" {
			displayName = code
		}
		nativeName := strings.TrimSpace(bundle.Meta.NativeName)
		if nativeName == "" {
			nativeName = displayName
		}

		locales = append(locales, localeOption{
			Code:       code,
			Name:       displayName,
			NativeName: nativeName,
			URL:        "/locales/" + name,
		})
	}

	sort.Slice(locales, func(i, j int) bool {
		left := locales[i]
		right := locales[j]
		if left.Code == defaultLocaleCode {
			return true
		}
		if right.Code == defaultLocaleCode {
			return false
		}
		if left.NativeName == right.NativeName {
			return left.Code < right.Code
		}
		return left.NativeName < right.NativeName
	})

	return locales, nil
}

func (s *Server) handleLocalizationLanguages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

	locales, err := availableLocales()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load locale catalog")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"languages": locales,
	})
}
