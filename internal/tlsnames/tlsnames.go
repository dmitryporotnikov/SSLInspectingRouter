// Package tlsnames maps IANA-assigned TLS identifiers to their registered
// names. The lookup tables are generated from the IANA CSV files committed
// under the csv/ directory; see gen/main.go for the generator.
//
// All Lookup* functions return the registered name when known and a hex
// fallback ("0xNNNN") otherwise. Callers do not need to handle the empty
// case.
package tlsnames

import "fmt"

// CipherSuite returns the IANA name for a 16-bit cipher suite identifier.
func CipherSuite(code uint16) string {
	if name, ok := cipherSuites[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", code)
}

// ContentType returns the IANA name for a TLS record-layer content type byte.
func ContentType(code uint8) string {
	if name, ok := contentTypes[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%02x", code)
}

// HandshakeType returns the IANA name for a TLS handshake message type byte.
func HandshakeType(code uint8) string {
	if name, ok := handshakeTypes[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%02x", code)
}

// SupportedGroup returns the IANA name for a supported_group / named_group
// identifier.
func SupportedGroup(code uint16) string {
	// supportedGroups is keyed by uint32 because that mirrors the raw CSV
	// values; values that fit in 16 bits are returned here.
	if name, ok := supportedGroups[uint32(code)]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", code)
}

// ECPointFormat returns the IANA name for an EC point format byte.
func ECPointFormat(code uint8) string {
	if name, ok := ecPointFormats[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%02x", code)
}

// SignatureScheme returns the IANA name for a 16-bit signature scheme.
func SignatureScheme(code uint16) string {
	if name, ok := signatureSchemes[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", code)
}

// ExtensionType returns the IANA name for a 16-bit extension type.
func ExtensionType(code uint16) string {
	if name, ok := extensionTypes[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", code)
}

// CompressionMethod returns the IANA name for a 1-byte compression method.
func CompressionMethod(code uint8) string {
	if name, ok := compressionMethods[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%02x", code)
}

// ALPN returns the IANA description for an ALPN protocol identifier (the
// wire-form string the client offered).
func ALPN(protocol string) string {
	if name, ok := alpnProtocols[protocol]; ok {
		return name
	}
	return protocol
}
