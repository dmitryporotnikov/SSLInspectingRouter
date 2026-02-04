package proxy

import (
	"net/http"
	"strings"
)

const maxTamperBodyBytes = 10 << 20 // 10 MiB

func shouldSkipBodyTampering(statusCode int, h http.Header) bool {
	if statusCode == http.StatusSwitchingProtocols {
		return true
	}

	if v := strings.TrimSpace(h.Get("Upgrade")); v != "" {
		return true
	}

	ct := strings.ToLower(h.Get("Content-Type"))
	if strings.Contains(ct, "text/event-stream") {
		return true
	}
	if strings.Contains(ct, "application/grpc") {
		return true
	}
	if strings.Contains(ct, "multipart/x-mixed-replace") {
		return true
	}

	return false
}

