package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// HTTPHandler implements a transparent HTTP proxy.
type HTTPHandler struct {
	client *http.Client
}

// NewHTTPHandler creates a new HTTP proxy handler.
func NewHTTPHandler() *HTTPHandler {
	return &HTTPHandler{
		client: &http.Client{
			// Manual redirect handling for transparency
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sourceIP := getSourceIP(r)
	
	LogDebug(fmt.Sprintf("HTTP request from %s: %s %s", sourceIP, r.Method, r.URL.String()))

	bodyBytes := []byte{}
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	LogHTTPRequest(sourceIP, r.Method, getFullURL(r), r.Header, bodyBytes)

	proxyReq, err := http.NewRequest(r.Method, getFullURL(r), bytes.NewBuffer(bodyBytes))
	if err != nil {
		LogError(fmt.Sprintf("Failed to create proxy request: %v", err))
		http.Error(w, "Proxy Error", http.StatusInternalServerError)
		return
	}

	copyHeaders(proxyReq.Header, r.Header)

	if proxyReq.Host == "" {
		proxyReq.Host = r.Host
	}

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		LogError(fmt.Sprintf("Upstream request failed: %v", err))
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	LogDebug(fmt.Sprintf("HTTP completed: %s %s -> %d", r.Method, r.URL.String(), resp.StatusCode))
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
