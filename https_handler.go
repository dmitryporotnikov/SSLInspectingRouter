package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// HTTPSHandler manages transparent HTTPS proxying.
// It intercepts TLS connections, performs MITM to inspect traffic, and forwards requests.
type HTTPSHandler struct {
	certManager *CertManager
	client      *http.Client
}

// NewHTTPSHandler creates a new HTTPS handler with a custom client that ignores upstream certificates (for testing).
func NewHTTPSHandler(certManager *CertManager) *HTTPSHandler {
	return &HTTPSHandler{
		certManager: certManager,
		client: &http.Client{
			// Prevent automatic redirect following to maintain transparent proxy behavior
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false, // Verify upstream certificates by default
				},
			},
		},
	}
}

// HandleConnection intercepts a raw TCP connection, performs SNI sniffing,
// and upgrades it to a MITM TLS connection for inspection.
func (h *HTTPSHandler) HandleConnection(conn net.Conn) {
	defer conn.Close()

	sourceIP := conn.RemoteAddr().String()
	LogDebug(fmt.Sprintf("HTTPS connection from %s", sourceIP))

	hostname, peekedBytes, err := h.extractSNI(conn)
	if err != nil {
		LogError(fmt.Sprintf("SNI extraction failed: %v", err))
		return
	}

	LogDebug(fmt.Sprintf("SNI hostname: %s", hostname))

	certPair, err := h.certManager.GetCertificateForHost(hostname)
	if err != nil {
		LogError(fmt.Sprintf("Certificate generation failed for %s: %v", hostname, err))
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{certPair.Cert.Raw, h.certManager.GetCACert().Raw},
				PrivateKey:  certPair.Key,
			},
		},
	}

	// Wrap the connection to replay the bytes we read for SNI sniffing
	rConn := &replayConn{
		Conn:   conn,
		replay: peekedBytes,
	}

	tlsConn := tls.Server(rConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		LogError(fmt.Sprintf("TLS handshake failed: %v", err))
		return
	}
	defer tlsConn.Close()

	h.handleHTTPSRequest(tlsConn, hostname, sourceIP)
}

// handleHTTPSRequest reads the decrypted request from the TLS connection and forwards it.
func (h *HTTPSHandler) handleHTTPSRequest(tlsConn *tls.Conn, hostname, sourceIP string) {
	req, err := http.ReadRequest(bufioReaderFromConn(tlsConn))
	if err != nil {
		LogError(fmt.Sprintf("Failed to read HTTPS request: %v", err))
		return
	}

	bodyBytes := []byte{}
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	fullURL := fmt.Sprintf("https://%s%s", hostname, req.URL.RequestURI())

	LogHTTPSRequest(sourceIP, req.Method, fullURL, req.Header, bodyBytes)

	proxyReq, err := http.NewRequest(req.Method, fullURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		LogError(fmt.Sprintf("Failed to create proxy request: %v", err))
		sendHTTPError(tlsConn, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	copyHeaders(proxyReq.Header, req.Header)
	proxyReq.Host = hostname

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		LogError(fmt.Sprintf("Upstream request failed: %v", err))
		sendHTTPError(tlsConn, http.StatusBadGateway, "Bad Gateway")
		return
	}
	defer resp.Body.Close()

	if err := resp.Write(tlsConn); err != nil {
		LogError(fmt.Sprintf("Failed to write response to client: %v", err))
		return
	}

	LogDebug(fmt.Sprintf("HTTPS completed: %s %s -> %d", req.Method, fullURL, resp.StatusCode))
}

// extractSNI reads the ClientHello to determine the target hostname without fully consuming the handshake bytes.
// Note: This implementation currently consumes bytes, which may require replay logic if not handled carefully.
// (See `replayConn` structure below if strict strict replay is needed, though currently we rely on re-reading if implementation allows).
//
// In this specific implementation, extractSNI consumes the ClientHello bytes.
// The caller must be aware that the `net.Conn` passed to `tls.Server` needs to have those bytes "put back" or
// be served by a wrapper that replays them.

func (h *HTTPSHandler) extractSNI(conn net.Conn) (string, []byte, error) {
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// Peek/Read enough bytes for ClientHello
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", nil, err
	}

	hostname := parseSNI(buf[:n])
	if hostname == "" {
		return "", nil, fmt.Errorf("no SNI found in ClientHello")
	}

	return hostname, buf[:n], nil
}

// parseSNI attempts to find the Server Name Indication extension in the TLS ClientHello.
func parseSNI(data []byte) string {
	if len(data) < 43 {
		return ""
	}

	// 0x16 = Handshake
	if data[0] != 0x16 {
		return ""
	}

	// 0x01 = ClientHello
	if len(data) < 6 || data[5] != 0x01 {
		return ""
	}

	// Skip past known fixed-length and variable-length fields (SessionID, Random, etc.)
	// This is a minimal parser and brittle to changes in TLS versions or unusual Hello structures.
	pos := 43 // Offset after SessionID length

	if pos >= len(data) {
		return ""
	}

	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if pos+2 >= len(data) {
		return ""
	}

	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	if pos >= len(data) {
		return ""
	}

	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	if pos+2 >= len(data) {
		return ""
	}

	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	endPos := pos + extensionsLen
	for pos+4 <= endPos && pos+4 <= len(data) {
		extType := int(data[pos])<<8 | int(data[pos+1])
		extLen := int(data[pos+2])<<8 | int(data[pos+3])
		pos += 4

		if extType == 0 { // 0x00 is SNI
			if pos+extLen > len(data) {
				return ""
			}
			return parseSNIExtension(data[pos : pos+extLen])
		}

		pos += extLen
	}

	return ""
}

func parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	pos := 2
	// Name Type: 0x00 (HostName)
	if data[pos] != 0 {
		return ""
	}
	pos++

	nameLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	if pos+nameLen > len(data) {
		return ""
	}

	return string(data[pos : pos+nameLen])
}

type replayConn struct {
	net.Conn
	replay []byte
	rpos   int
}

func (rc *replayConn) Read(b []byte) (int, error) {
	if rc.rpos < len(rc.replay) {
		n := copy(b, rc.replay[rc.rpos:])
		rc.rpos += n
		return n, nil
	}
	return rc.Conn.Read(b)
}

func bufioReaderFromConn(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}

func sendHTTPError(conn net.Conn, statusCode int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s",
		statusCode, http.StatusText(statusCode), len(message), message)
	conn.Write([]byte(response))
}
