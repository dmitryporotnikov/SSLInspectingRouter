package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/blocklist"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/rewrites"
)

// HTTPHandler implements a transparent HTTP proxy.
type HTTPHandler struct {
	Client     *http.Client
	blockList  *blocklist.BlockList
	bypassList *blocklist.BlockList
	rewriter   *rewrites.Engine
	policyMu   sync.RWMutex

	upstreamMu sync.RWMutex
	torClient  *http.Client
}

// NewHTTPHandler creates a new HTTP proxy handler.
func NewHTTPHandler(blockList *blocklist.BlockList, bypassList *blocklist.BlockList, rewriter *rewrites.Engine) *HTTPHandler {
	return &HTTPHandler{
		Client: &http.Client{
			// Manual redirect handling for transparency
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		blockList:  blockList,
		bypassList: bypassList,
		rewriter:   rewriter,
	}
}

func (h *HTTPHandler) SetBlockList(blockList *blocklist.BlockList) {
	h.policyMu.Lock()
	h.blockList = blockList
	h.policyMu.Unlock()
}

func (h *HTTPHandler) SetBypassList(bypassList *blocklist.BlockList) {
	h.policyMu.Lock()
	h.bypassList = bypassList
	h.policyMu.Unlock()
}

func (h *HTTPHandler) BlockListEntries() []string {
	h.policyMu.RLock()
	defer h.policyMu.RUnlock()
	if h.blockList == nil {
		return []string{}
	}
	return h.blockList.Entries()
}

func (h *HTTPHandler) BypassListEntries() []string {
	h.policyMu.RLock()
	defer h.policyMu.RUnlock()
	if h.bypassList == nil {
		return []string{}
	}
	return h.bypassList.Entries()
}

func (h *HTTPHandler) currentBlockList() *blocklist.BlockList {
	h.policyMu.RLock()
	defer h.policyMu.RUnlock()
	return h.blockList
}

func (h *HTTPHandler) currentBypassList() *blocklist.BlockList {
	h.policyMu.RLock()
	defer h.policyMu.RUnlock()
	return h.bypassList
}

// SetSOCKSProxy enables or disables upstream routing via SOCKS5.
func (h *HTTPHandler) SetSOCKSProxy(enabled bool, socksAddr string) error {
	h.upstreamMu.Lock()
	defer h.upstreamMu.Unlock()

	if !enabled {
		h.torClient = nil
		return nil
	}

	roundTripper, _, err := buildSOCKS5RoundTripper(h.Client.Transport, socksAddr)
	if err != nil {
		return err
	}

	clientCopy := *h.Client
	clientCopy.Transport = roundTripper
	h.torClient = &clientCopy
	return nil
}

func (h *HTTPHandler) upstreamClient() *http.Client {
	h.upstreamMu.RLock()
	defer h.upstreamMu.RUnlock()
	if h.torClient != nil {
		return h.torClient
	}
	return h.Client
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sourceIP := getSourceIP(r)
	fullURL, targetHost, err := buildProxyTarget(r)
	if err != nil {
		logger.LogError(fmt.Sprintf("Rejected HTTP request from %s: %v", sourceIP, err))
		writePlainError(w, http.StatusBadRequest, "Bad Request")
		return
	}
	blockList := h.currentBlockList()
	bypassList := h.currentBypassList()

	logger.LogDebug(fmt.Sprintf("HTTP request from %s: %s %s", sourceIP, r.Method, fullURL))

	bodyBytes := []byte{}
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	if blockList != nil && blockList.Matches(targetHost) {
		reqID := logger.LogHTTPRequest(logger.RequestLogEntry{
			SourceIP: sourceIP,
			FQDN:     targetHost,
			Method:   r.Method,
			URL:      fullURL,
			Headers:  r.Header,
			Body:     bodyBytes,
		})
		logger.LogInfo(fmt.Sprintf("Blocked HTTP host %s from %s", targetHost, sourceIP))
		writePlainError(w, http.StatusForbidden, "Blocked")
		logger.LogHTTPResponse(logger.ResponseLogEntry{
			ReqID:       reqID,
			SourceIP:    sourceIP,
			FQDN:        targetHost,
			Status:      "403 Forbidden",
			Headers:     http.Header{},
			BodyPreview: []byte("Blocked"),
			Truncated:   false,
		})
		return
	}

	bypassed := bypassList != nil && bypassList.Matches(targetHost)
	var reqID int64
	if bypassed {
		reqID = logger.LogBypassedRequest(sourceIP, targetHost)
	} else {
		reqID = logger.LogHTTPRequest(logger.RequestLogEntry{
			SourceIP: sourceIP,
			FQDN:     targetHost,
			Method:   r.Method,
			URL:      fullURL,
			Headers:  r.Header,
			Body:     bodyBytes,
		})
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, fullURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		logger.LogError(fmt.Sprintf("Failed to create proxy request: %v", err))
		writePlainError(w, http.StatusInternalServerError, "Proxy Error")
		if bypassed {
			logger.LogBypassedResponse(reqID, sourceIP, targetHost)
		}
		return
	}

	copyHeaders(proxyReq.Header, r.Header)

	if h.rewriter != nil && !bypassed && h.rewriter.ShouldForceGzip(r, targetHost) {
		// Avoid brotli upstream responses; we only support body tampering for identity/gzip/deflate.
		proxyReq.Header.Set("Accept-Encoding", "gzip")
	}

	if proxyReq.Host == "" {
		proxyReq.Host = proxyReq.URL.Host
	}

	resp, err := h.upstreamClient().Do(proxyReq)
	if err != nil {
		logger.LogError(fmt.Sprintf("Upstream request failed: %v", err))
		writePlainError(w, http.StatusBadGateway, "Bad Gateway")
		if bypassed {
			logger.LogBypassedResponse(reqID, sourceIP, targetHost)
		} else {
			logger.LogHTTPResponse(logger.ResponseLogEntry{
				ReqID:       reqID,
				SourceIP:    sourceIP,
				FQDN:        targetHost,
				Status:      "502 Bad Gateway",
				Headers:     http.Header{},
				BodyPreview: []byte("Bad Gateway"),
				Truncated:   false,
			})
		}
		return
	}
	defer resp.Body.Close()

	if bypassed {
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		logger.LogBypassedResponse(reqID, sourceIP, targetHost)
		logger.LogDebug(fmt.Sprintf("HTTP bypassed: %s %s -> %d", r.Method, r.URL.String(), resp.StatusCode))
		return
	}

	var rewritePlan *rewrites.Plan
	if h.rewriter != nil {
		plan, err := h.rewriter.Plan(r, targetHost, resp.StatusCode, resp.Header)
		if err != nil {
			logger.LogError(fmt.Sprintf("Rewrite rules reload failed: %v", err))
		}
		rewritePlan = plan
	}

	if rewritePlan != nil {
		rewritePlan.ApplyHeaders(resp.Header)

		if rewritePlan.NeedsBody() && !shouldSkipBodyTampering(resp.StatusCode, resp.Header) {
			rawBody, err := io.ReadAll(io.LimitReader(resp.Body, maxTamperBodyBytes+1))
			if err != nil {
				logger.LogError(fmt.Sprintf("Failed reading upstream response body: %v", err))
				writePlainError(w, http.StatusBadGateway, "Bad Gateway")
				logger.LogHTTPResponse(logger.ResponseLogEntry{
					ReqID:       reqID,
					SourceIP:    sourceIP,
					FQDN:        targetHost,
					Status:      "502 Bad Gateway",
					Headers:     http.Header{},
					BodyPreview: []byte("Bad Gateway"),
					Truncated:   false,
				})
				return
			}

			if len(rawBody) > maxTamperBodyBytes {
				// Too large (or effectively streaming). Fall back to forwarding the original body.
				copyHeaders(w.Header(), resp.Header)
				w.WriteHeader(resp.StatusCode)

				preview := &logger.LimitedBuffer{Max: logger.LogBodyLimit()}
				_, _ = preview.Write(rawBody)
				_, _ = w.Write(rawBody)

				tee := io.TeeReader(resp.Body, preview)
				_, _ = io.Copy(w, tee)

				logger.LogHTTPResponse(logger.ResponseLogEntry{
					ReqID:       reqID,
					SourceIP:    sourceIP,
					FQDN:        targetHost,
					Status:      resp.Status,
					Headers:     resp.Header,
					BodyPreview: preview.Bytes(),
					Truncated:   preview.Truncated(),
				})
				logger.LogDebug(fmt.Sprintf("HTTP completed (tamper skipped: body too large): %s %s -> %d", r.Method, r.URL.String(), resp.StatusCode))
				return
			}

			outBody, _, err := rewritePlan.RewriteBody(resp.Header, rawBody)
			if err != nil {
				logger.LogError(fmt.Sprintf("Response tampering failed (sending original body): %v", err))
				outBody = rawBody
			}

			resp.Header.Set("Content-Length", strconv.Itoa(len(outBody)))
			resp.Header.Del("Transfer-Encoding")

			copyHeaders(w.Header(), resp.Header)
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(outBody)

			preview := &logger.LimitedBuffer{Max: logger.LogBodyLimit()}
			_, _ = preview.Write(outBody)
			logger.LogHTTPResponse(logger.ResponseLogEntry{
				ReqID:       reqID,
				SourceIP:    sourceIP,
				FQDN:        targetHost,
				Status:      resp.Status,
				Headers:     resp.Header,
				BodyPreview: preview.Bytes(),
				Truncated:   preview.Truncated(),
			})
			logger.LogDebug(fmt.Sprintf("HTTP completed (tampered): %s %s -> %d", r.Method, r.URL.String(), resp.StatusCode))
			return
		}
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	preview := &logger.LimitedBuffer{Max: logger.LogBodyLimit()}
	tee := io.TeeReader(resp.Body, preview)
	_, _ = io.Copy(w, tee)

	logger.LogHTTPResponse(logger.ResponseLogEntry{
		ReqID:       reqID,
		SourceIP:    sourceIP,
		FQDN:        targetHost,
		Status:      resp.Status,
		Headers:     resp.Header,
		BodyPreview: preview.Bytes(),
		Truncated:   preview.Truncated(),
	})
	logger.LogDebug(fmt.Sprintf("HTTP completed: %s %s -> %d", r.Method, r.URL.String(), resp.StatusCode))
}

func writePlainError(w http.ResponseWriter, status int, message string) {
	if message == "" {
		message = http.StatusText(status)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, message)
}

func buildProxyTarget(r *http.Request) (string, string, error) {
	if r == nil || r.URL == nil {
		return "", "", errors.New("request URL is missing")
	}

	scheme := strings.ToLower(strings.TrimSpace(r.URL.Scheme))
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	if scheme != "http" && scheme != "https" {
		return "", "", fmt.Errorf("unsupported target scheme %q", scheme)
	}

	hostInput := strings.TrimSpace(r.Host)
	if r.URL.IsAbs() && strings.TrimSpace(r.URL.Host) != "" {
		hostInput = strings.TrimSpace(r.URL.Host)
	}
	normalizedHost, hostOnly, err := normalizeURLHost(hostInput)
	if err != nil {
		return "", "", err
	}

	path := r.URL.Path
	if path == "" {
		path = "/"
	}

	targetURL := &url.URL{
		Scheme:     scheme,
		Host:       normalizedHost,
		Path:       path,
		RawPath:    r.URL.RawPath,
		RawQuery:   r.URL.RawQuery,
		ForceQuery: r.URL.ForceQuery,
	}
	return targetURL.String(), hostOnly, nil
}

func normalizeURLHost(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("target host is empty")
	}
	if strings.Contains(raw, "@") || strings.ContainsAny(raw, "/\\") || containsControlChars(raw) {
		return "", "", fmt.Errorf("invalid target host %q", raw)
	}

	parsed, err := url.Parse("http://" + raw)
	if err != nil {
		return "", "", fmt.Errorf("invalid target host %q", raw)
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" || containsControlChars(host) {
		return "", "", fmt.Errorf("invalid target host %q", raw)
	}

	hostOnly := strings.TrimSuffix(strings.ToLower(host), ".")
	if hostOnly == "" {
		return "", "", fmt.Errorf("invalid target host %q", raw)
	}
	if ip := net.ParseIP(hostOnly); ip != nil {
		hostOnly = ip.String()
	}

	port := strings.TrimSpace(parsed.Port())
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("invalid target port %q", port)
		}
	}

	hostForURL := hostOnly
	if port != "" {
		hostForURL = net.JoinHostPort(hostOnly, port)
	} else if strings.Contains(hostOnly, ":") {
		hostForURL = "[" + hostOnly + "]"
	}

	return hostForURL, hostOnly, nil
}

func containsControlChars(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func getSourceIP(r *http.Request) string {
	if ip := parseForwardedFor(r.Header.Get("X-Forwarded-For")); ip != "" {
		return ip
	}

	if ip := parseIPAddress(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}

	remote := strings.TrimSpace(r.RemoteAddr)
	ip, _, err := net.SplitHostPort(remote)
	if err != nil {
		if parsed := parseIPAddress(remote); parsed != "" {
			return parsed
		}
		if token := sanitizeTextToken(remote); token != "" {
			return token
		}
		return "unknown"
	}
	if parsed := parseIPAddress(ip); parsed != "" {
		return parsed
	}
	if token := sanitizeTextToken(ip); token != "" {
		return token
	}
	return "unknown"
}

func parseForwardedFor(value string) string {
	for _, part := range strings.Split(value, ",") {
		if ip := parseIPAddress(part); ip != "" {
			return ip
		}
	}
	return ""
}

func parseIPAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func sanitizeTextToken(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(value))
}

func copyHeaders(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}
