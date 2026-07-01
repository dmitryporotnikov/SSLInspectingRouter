package tlsnames

import "testing"

func TestCipherSuiteKnown(t *testing.T) {
	if got := CipherSuite(0xc02f); got != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Fatalf("CipherSuite(0xc02f) = %q", got)
	}
	if got := CipherSuite(0x1301); got != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("CipherSuite(0x1301) = %q", got)
	}
}

func TestCipherSuiteUnknownFallback(t *testing.T) {
	if got := CipherSuite(0xbeef); got != "0xbeef" {
		t.Fatalf("CipherSuite(0xbeef) = %q, want 0xbeef", got)
	}
}

func TestExtensionTypeKnown(t *testing.T) {
	cases := map[uint16]string{
		0x0000: "server_name",
		0x0010: "application_layer_protocol_negotiation",
		0x000a: "supported_groups",
		0x000d: "signature_algorithms",
	}
	for code, want := range cases {
		if got := ExtensionType(code); got != want {
			t.Fatalf("ExtensionType(0x%04x) = %q, want %q", code, got, want)
		}
	}
}

func TestSupportedGroupKnown(t *testing.T) {
	if got := SupportedGroup(0x0017); got != "secp256r1" {
		t.Fatalf("SupportedGroup(0x0017) = %q, want secp256r1", got)
	}
}

func TestSignatureSchemeKnown(t *testing.T) {
	if got := SignatureScheme(0x0401); got != "rsa_pkcs1_sha256" {
		t.Fatalf("SignatureScheme(0x0401) = %q, want rsa_pkcs1_sha256", got)
	}
}

func TestCompressionMethodKnown(t *testing.T) {
	if got := CompressionMethod(0x00); got != "NULL" {
		t.Fatalf("CompressionMethod(0x00) = %q, want NULL", got)
	}
}

func TestHandshakeTypeKnown(t *testing.T) {
	if got := HandshakeType(0x01); got != "client_hello" {
		t.Fatalf("HandshakeType(0x01) = %q, want client_hello", got)
	}
}

func TestContentTypeKnown(t *testing.T) {
	cases := map[uint8]string{
		20: "change_cipher_spec",
		21: "alert",
		22: "handshake",
		23: "application_data",
	}
	for code, want := range cases {
		if got := ContentType(code); got != want {
			t.Fatalf("ContentType(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestALPNKnown(t *testing.T) {
	cases := map[string]string{
		"h2":     "HTTP/2 over TLS",
		"h2c":    "HTTP/2 over TCP",
		"http/1.1": "HTTP/1.1",
		"spdy/3": "SPDY/3",
	}
	for proto, want := range cases {
		if got := ALPN(proto); got != want {
			t.Fatalf("ALPN(%q) = %q, want %q", proto, got, want)
		}
	}
}

func TestALPNUnknownReturnsInput(t *testing.T) {
	if got := ALPN("unknown-protocol"); got != "unknown-protocol" {
		t.Fatalf("ALPN unknown = %q, want echo", got)
	}
}

func TestLookupsNotEmpty(t *testing.T) {
	// ponytail: one sanity check that the generator produced data, not an
	// empty map after a CSV parse regression.
	if len(cipherSuites) < 50 {
		t.Fatalf("cipherSuites has %d entries, expected a few dozen", len(cipherSuites))
	}
	if len(extensionTypes) < 20 {
		t.Fatalf("extensionTypes has %d entries, expected at least 20", len(extensionTypes))
	}
	if len(alpnProtocols) < 5 {
		t.Fatalf("alpnProtocols has %d entries, expected at least 5", len(alpnProtocols))
	}
}
