package proxy

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

// buildClientHello synthesizes a TLS 1.2 ClientHello record carrying the
// provided SNI, cipher suites, ALPN, and extensions. It lets the metadata
// parser be tested without performing a real handshake.
func buildClientHello(sni string, ciphers []uint16, alpn []string, extraExts map[uint16][]byte) []byte {
	// 32-byte random
	clientRandom := bytes.Repeat([]byte{0xab}, 32)

	// SNI extension
	var sniExt bytes.Buffer
	sniListLen := uint16(0)
	if sni != "" {
		entry := []byte{
			0x00, // host_name type
		}
		nameLen := uint16(len(sni))
		entry = append(entry, byte(nameLen>>8), byte(nameLen))
		entry = append(entry, []byte(sni)...)
		listLen := uint16(len(entry))
		sniListLen = listLen
		sniExt.WriteByte(byte(listLen >> 8))
		sniExt.WriteByte(byte(listLen))
		sniExt.Write(entry)
	}

	// ALPN extension
	var alpnExt bytes.Buffer
	var alpnEntries bytes.Buffer
	for _, p := range alpn {
		alpnEntries.WriteByte(byte(len(p)))
		alpnEntries.WriteString(p)
	}
	alpnListLen := uint16(alpnEntries.Len())
	alpnExt.WriteByte(byte(alpnListLen >> 8))
	alpnExt.WriteByte(byte(alpnListLen))
	alpnExt.Write(alpnEntries.Bytes())

	// Compose extensions block
	var exts bytes.Buffer
	// SNI
	if sni != "" {
		exts.Write([]byte{0x00, 0x00})
		exts.WriteByte(byte(sniExt.Len() >> 8))
		exts.WriteByte(byte(sniExt.Len()))
		exts.Write(sniExt.Bytes())
		_ = sniListLen // referenced for clarity above
	}
	// ALPN
	if len(alpn) > 0 {
		exts.Write([]byte{0x00, 0x10})
		exts.WriteByte(byte(alpnExt.Len() >> 8))
		exts.WriteByte(byte(alpnExt.Len()))
		exts.Write(alpnExt.Bytes())
	}
	// Extra extensions
	for extType, payload := range extraExts {
		exts.WriteByte(byte(extType >> 8))
		exts.WriteByte(byte(extType))
		exts.WriteByte(byte(len(payload) >> 8))
		exts.WriteByte(byte(len(payload)))
		exts.Write(payload)
	}

	// Ciphers
	var csBytes bytes.Buffer
	for _, c := range ciphers {
		csBytes.WriteByte(byte(c >> 8))
		csBytes.WriteByte(byte(c))
	}
	csLen := uint16(csBytes.Len())

	// Handshake body: legacy_version(2) + random(32) + session_id_len(1) +
	// ciphers_len(2) + ciphers + compression_len(1) + compression(1) +
	// extensions_len(2) + extensions
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03}) // legacy_version TLS 1.2
	body.Write(clientRandom)
	body.WriteByte(0) // session_id length
	binary.Write(&body, binary.BigEndian, csLen)
	body.Write(csBytes.Bytes())
	body.WriteByte(1)  // compression methods length
	body.WriteByte(0)  // null compression
	binary.Write(&body, binary.BigEndian, uint16(exts.Len()))
	body.Write(exts.Bytes())

	// Handshake header: type(1) + length(3)
	var hs bytes.Buffer
	hs.WriteByte(0x01) // ClientHello
	hs.WriteByte(byte(body.Len() >> 16))
	hs.WriteByte(byte(body.Len() >> 8))
	hs.WriteByte(byte(body.Len()))
	hs.Write(body.Bytes())

	// TLS record header
	var rec bytes.Buffer
	rec.WriteByte(0x16) // handshake
	rec.Write([]byte{0x03, 0x03})
	binary.Write(&rec, binary.BigEndian, uint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func TestParseClientHelloExtractsSNI(t *testing.T) {
	data := buildClientHello("example.com", []uint16{0xc02f, 0xc030}, []string{"h2", "http/1.1"}, nil)

	info := parseClientHello(data)
	if info.SNI != "example.com" {
		t.Fatalf("SNI = %q, want %q", info.SNI, "example.com")
	}
	if info.RecordVersion != 0x0303 {
		t.Fatalf("RecordVersion = 0x%04x, want 0x0303", info.RecordVersion)
	}
	if info.ClientVersion != 0x0303 {
		t.Fatalf("ClientVersion = 0x%04x, want 0x0303", info.ClientVersion)
	}
	if len(info.CipherSuites) != 2 {
		t.Fatalf("len(CipherSuites) = %d, want 2", len(info.CipherSuites))
	}
	if info.CipherSuites[0] != 0xc02f || info.CipherSuites[1] != 0xc030 {
		t.Fatalf("CipherSuites = %v, want [0xc02f, 0xc030]", info.CipherSuites)
	}
	if len(info.ALPN) != 2 || info.ALPN[0] != "h2" || info.ALPN[1] != "http/1.1" {
		t.Fatalf("ALPN = %v, want [h2 http/1.1]", info.ALPN)
	}
	if len(info.Compression) != 1 || info.Compression[0] != 0 {
		t.Fatalf("Compression = %v, want [0]", info.Compression)
	}
	if !containsExt(info.Extensions, 0) {
		t.Fatalf("Extensions missing SNI (0): %v", info.Extensions)
	}
	if !containsExt(info.Extensions, 16) {
		t.Fatalf("Extensions missing ALPN (16): %v", info.Extensions)
	}
}

func TestParseClientHelloHandlesTruncatedInput(t *testing.T) {
	if info := parseClientHello([]byte{0x16, 0x03, 0x03}); info.SNI != "" {
		t.Fatalf("SNI on truncated input = %q, want empty", info.SNI)
	}
}

func TestParseClientHelloHandlesNoSNI(t *testing.T) {
	data := buildClientHello("", []uint16{0xc02f}, nil, nil)
	info := parseClientHello(data)
	if info.SNI != "" {
		t.Fatalf("SNI = %q, want empty when not requested", info.SNI)
	}
	if len(info.CipherSuites) != 1 {
		t.Fatalf("len(CipherSuites) = %d, want 1", len(info.CipherSuites))
	}
}

func TestParseClientHelloExtractsSupportedGroups(t *testing.T) {
	// Supported Groups (extension 10) payload: list_len(2) + groups...
	payload := []byte{0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19}
	extra := map[uint16][]byte{10: payload}

	data := buildClientHello("example.com", []uint16{0xc02f}, nil, extra)
	info := parseClientHello(data)

	if len(info.SupportedGroups) != 3 {
		t.Fatalf("len(SupportedGroups) = %d, want 3", len(info.SupportedGroups))
	}
	if info.SupportedGroups[0] != 0x0017 || info.SupportedGroups[2] != 0x0019 {
		t.Fatalf("SupportedGroups = %v, want [0x0017 0x0018 0x0019]", info.SupportedGroups)
	}
}

func TestFormatClientHelloMetadataContainsKeyFields(t *testing.T) {
	data := buildClientHello("example.com", []uint16{0xc02f}, []string{"h2"}, nil)
	info := parseClientHello(data)
	out := formatClientHelloMetadata(info, "10.0.0.1", "93.184.216.34", 443)

	for _, want := range []string{
		"TLS Version (client): TLS 1.2",
		"Source IP: 10.0.0.1",
		"Original Destination: 93.184.216.34:443",
		"Cipher Suites (1):",
		"  0xc02f = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"ALPN (1):",
		`  "h2" = HTTP/2 over TLS`,
		"Extensions (2):",
		"  0x0000 = server_name",
		"  0x0010 = application_layer_protocol_negotiation",
		"Compression Methods (1):",
		"  0x00 = NULL",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in metadata output:\n%s", want, out)
		}
	}
}

func TestSNIOnlyModeSettersAndGetters(t *testing.T) {
	h := &HTTPSHandler{}
	if h.IsSNIOnlyMode() {
		t.Fatal("default SNIOnlyMode = true, want false")
	}
	h.SetSNIOnlyMode(true)
	if !h.IsSNIOnlyMode() {
		t.Fatal("SNIOnlyMode = false after SetSNIOnlyMode(true)")
	}
	h.SetSNIOnlyMode(false)
	if h.IsSNIOnlyMode() {
		t.Fatal("SNIOnlyMode = true after SetSNIOnlyMode(false)")
	}
}

func TestLogSNIRequestStoresMetadata(t *testing.T) {
	db := setupProxyTestDB(t)

	metadata := "TLS Version (client): 0x0303\nCipher Suites (1):\n  0xc02f\n"
	reqID := logger.LogSNIRequest("10.0.0.1", "example.com", metadata)
	if reqID == 0 {
		t.Fatal("LogSNIRequest returned 0")
	}

	var request, content string
	if err := db.QueryRow(`SELECT request, content FROM Requests WHERE id = ?`, reqID).Scan(&request, &content); err != nil {
		t.Fatalf("read request row: %v", err)
	}
	if request != "SNI-ONLY" {
		t.Fatalf("request = %q, want %q", request, "SNI-ONLY")
	}
	if content != metadata {
		t.Fatalf("content mismatch")
	}
}

func containsExt(exts []uint16, target uint16) bool {
	for _, e := range exts {
		if e == target {
			return true
		}
	}
	return false
}
