package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/blocklist"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

// HTTPHandler implements a transparent HTTP proxy.
type HTTPHandler struct {
	Client     *http.Client
	blockList  *blocklist.BlockList
	bypassList *blocklist.BlockList
}

// NewHTTPHandler creates a new HTTP proxy handler.
func NewHTTPHandler(blockList *blocklist.BlockList, bypassList *blocklist.BlockList) *HTTPHandler {
	return &HTTPHandler{
		Client: &http.Client{
			// Manual redirect handling for transparency
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		blockList:  blockList,
		bypassList: bypassList,
	}
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sourceIP := getSourceIP(r)
	targetHost := requestHost(r)

	logger.LogDebug(fmt.Sprintf("HTTP request from %s: %s %s", sourceIP, r.Method, r.URL.String()))

	bodyBytes := []byte{}
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	if h.blockList != nil && h.blockList.Matches(targetHost) {
		reqID := logger.LogHTTPRequest(sourceIP, targetHost, r.Method, getFullURL(r), r.Header, bodyBytes)
		logger.LogInfo(fmt.Sprintf("Blocked HTTP host %s from %s", targetHost, sourceIP))
		http.Error(w, "Blocked", http.StatusForbidden)
		logger.LogHTTPResponse(reqID, sourceIP, targetHost, "403 Forbidden", http.Header{}, []byte("Blocked"), false)
		return
	}

	bypassed := h.bypassList != nil && h.bypassList.Matches(targetHost)
	var reqID int64
	if bypassed {
		reqID = logger.LogBypassedRequest(sourceIP, targetHost)
	} else {
		reqID = logger.LogHTTPRequest(sourceIP, targetHost, r.Method, getFullURL(r), r.Header, bodyBytes)
	}

	proxyReq, err := http.NewRequest(r.Method, getFullURL(r), bytes.NewBuffer(bodyBytes))
	if err != nil {
		logger.LogError(fmt.Sprintf("Failed to create proxy request: %v", err))
		http.Error(w, "Proxy Error", http.StatusInternalServerError)
		if bypassed {
			logger.LogBypassedResponse(reqID, sourceIP, targetHost)
		}
		return
	}

	copyHeaders(proxyReq.Header, r.Header)

	if proxyReq.Host == "" {
		proxyReq.Host = r.Host
	}

	resp, err := h.Client.Do(proxyReq)
	if err != nil {
		logger.LogError(fmt.Sprintf("Upstream request failed: %v", err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		if bypassed {
			logger.LogBypassedResponse(reqID, sourceIP, targetHost)
		} else {
			logger.LogHTTPResponse(reqID, sourceIP, targetHost, "502 Bad Gateway", http.Header{}, []byte("Bad Gateway"), false)
		}
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if bypassed {
		_, _ = io.Copy(w, resp.Body)
		logger.LogBypassedResponse(reqID, sourceIP, targetHost)
		logger.LogDebug(fmt.Sprintf("HTTP bypassed: %s %s -> %d", r.Method, r.URL.String(), resp.StatusCode))
		return
	}

	preview := &logger.LimitedBuffer{Max: logger.LogBodyLimit()}
	tee := io.TeeReader(resp.Body, preview)
	_, _ = io.Copy(w, tee)

	logger.LogHTTPResponse(reqID, sourceIP, targetHost, resp.Status, resp.Header, preview.Bytes(), preview.Truncated())
	logger.LogDebug(fmt.Sprintf("HTTP completed: %s %s -> %d", r.Method, r.URL.String(), resp.StatusCode))
}

func getFullURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	if r.URL.IsAbs() {
		return r.URL.String()
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, r.URL.RequestURI())
}

func requestHost(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") && !strings.Contains(host, "]") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	return host
}

func getSourceIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func copyHeaders(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}
