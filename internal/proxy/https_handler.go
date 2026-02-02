package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/blocklist"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/cert"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

// HTTPSHandler manages transparent HTTPS proxying.
// It intercepts TLS connections, performs MITM to inspect traffic, and forwards requests.
type HTTPSHandler struct {
	certManager *cert.CertManager
	client      *http.Client
	blockList   *blocklist.BlockList
	bypassList  *blocklist.BlockList
}

// NewHTTPSHandler creates a new HTTPS handler with a custom client that ignores upstream certificates (for testing).
func NewHTTPSHandler(certManager *cert.CertManager, blockList *blocklist.BlockList, bypassList *blocklist.BlockList) *HTTPSHandler {
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
		blockList:  blockList,
		bypassList: bypassList,
	}
}

// HandleConnection intercepts a raw TCP connection, performs SNI sniffing,
// and upgrades it to a MITM TLS connection for inspection.
func (h *HTTPSHandler) HandleConnection(conn net.Conn) {
	defer conn.Close()

	sourceIP := sourceIPFromAddr(conn.RemoteAddr())
	logger.LogDebug(fmt.Sprintf("HTTPS connection from %s", sourceIP))

	hostname, peekedBytes, err := h.extractSNI(conn)
	if err != nil {
		logger.LogError(fmt.Sprintf("SNI extraction failed: %v", err))
		return
	}

	logger.LogDebug(fmt.Sprintf("SNI hostname: %s", hostname))

	if h.blockList != nil && h.blockList.Matches(hostname) {
		logger.LogInfo(fmt.Sprintf("Blocked HTTPS host %s from %s", hostname, sourceIP))
		logger.LogTLSRequest(sourceIP, hostname, "TLS SNI")
		logger.LogHTTPSResponse(sourceIP, hostname, "BLOCKED", http.Header{}, []byte("Blocked by policy"), false)
		return
	}

	if h.bypassList != nil && h.bypassList.Matches(hostname) {
		logger.LogBypassedRequest(sourceIP, hostname)
		h.handleBypassedTLS(conn, hostname, sourceIP, peekedBytes)
		return
	}

	certPair, err := h.certManager.GetCertificateForHost(hostname)
	if err != nil {
		logger.LogError(fmt.Sprintf("Certificate generation failed for %s: %v", hostname, err))
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
		logger.LogError(fmt.Sprintf("TLS handshake failed: %v", err))
		return
	}
	defer tlsConn.Close()

	h.handleHTTPSRequest(tlsConn, hostname, sourceIP)
}

func (h *HTTPSHandler) handleBypassedTLS(clientConn net.Conn, hostname, sourceIP string, peekedBytes []byte) {
	upstreamConn, err := net.DialTimeout("tcp", net.JoinHostPort(hostname, "443"), 10*time.Second)
	if err != nil {
		logger.LogError(fmt.Sprintf("Bypass upstream dial failed for %s: %v", hostname, err))
		logger.LogBypassedResponse(sourceIP, hostname)
		return
	}
	defer upstreamConn.Close()

	if _, err := io.Copy(upstreamConn, bytes.NewReader(peekedBytes)); err != nil {
		logger.LogError(fmt.Sprintf("Bypass upstream write failed for %s: %v", hostname, err))
		logger.LogBypassedResponse(sourceIP, hostname)
		return
	}

	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(upstreamConn, clientConn)
		if tcpConn, ok := upstreamConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		errCh <- err
	}()

	go func() {
		_, err := io.Copy(clientConn, upstreamConn)
		if tcpConn, ok := clientConn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		errCh <- err
	}()

	for i := 0; i < 2; i++ {
		if copyErr := <-errCh; copyErr != nil && !isTunnelCompletion(copyErr) {
			logger.LogDebug(fmt.Sprintf("HTTPS bypass stream closed for %s: %v", hostname, copyErr))
		}
	}

	logger.LogBypassedResponse(sourceIP, hostname)
	logger.LogDebug(fmt.Sprintf("HTTPS bypassed: %s", hostname))
}

// handleHTTPSRequest reads the decrypted request from the TLS connection and forwards it.
func (h *HTTPSHandler) handleHTTPSRequest(tlsConn *tls.Conn, hostname, sourceIP string) {
	req, err := http.ReadRequest(bufioReaderFromConn(tlsConn))
	if err != nil {
		logger.LogError(fmt.Sprintf("Failed to read HTTPS request: %v", err))
		return
	}

	bodyBytes := []byte{}
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	fullURL := fmt.Sprintf("https://%s%s", hostname, req.URL.RequestURI())

	logger.LogHTTPSRequest(sourceIP, hostname, req.Method, fullURL, req.Header, bodyBytes)

	proxyReq, err := http.NewRequest(req.Method, fullURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		logger.LogError(fmt.Sprintf("Failed to create proxy request: %v", err))
		sendHTTPError(tlsConn, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	copyHeaders(proxyReq.Header, req.Header)
	proxyReq.Host = hostname

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		logger.LogError(fmt.Sprintf("Upstream request failed: %v", err))
		sendHTTPError(tlsConn, http.StatusBadGateway, "Bad Gateway")
		logger.LogHTTPSResponse(sourceIP, hostname, "502 Bad Gateway", http.Header{}, []byte("Bad Gateway"), false)
		return
	}
	defer resp.Body.Close()

	preview := &logger.LimitedBuffer{Max: logger.LogBodyLimit()}
	tee := io.TeeReader(resp.Body, preview)
	resp.Body = io.NopCloser(tee)

	if err := resp.Write(tlsConn); err != nil {
		logger.LogError(fmt.Sprintf("Failed to write response to client: %v", err))
		return
	}
	logger.LogHTTPSResponse(sourceIP, hostname, resp.Status, resp.Header, preview.Bytes(), preview.Truncated())

	logger.LogDebug(fmt.Sprintf("HTTPS completed: %s %s -> %d", req.Method, fullURL, resp.StatusCode))
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

func sourceIPFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func isTunnelCompletion(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}
