// Command gen downloads the IANA TLS parameter CSVs (already cached in the
// csv/ directory) and emits a Go source file (lookup.go) that contains the
// lookup maps for the tlsnames package.
//
// Run from the tlsnames directory:
//
//	go run ./gen
//
// ponytail: the generator keeps parsing simple. If IANA changes its CSV
// layout, regenerate and inspect the diff. We do not depend on this tool
// at runtime.
package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type entry struct {
	key  uint64
	name string
}

type alpnEntry struct {
	protocol string
	name     string
}

type rangeSkip struct {
	reason string
}

func mustOpen(path string) *csv.Reader {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", path, err)
		os.Exit(1)
	}
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	return r
}

func readRecords(path string) [][]string {
	r := mustOpen(path)
	rows, err := r.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(1)
	}
	return rows
}

func skipHeader(rows [][]string) [][]string {
	if len(rows) == 0 {
		return rows
	}
	first := rows[0]
	// Heuristic: drop the row only if the first column isn't a number/hex.
	if _, err := strconv.Atoi(strings.TrimSpace(first[0])); err == nil {
		return rows
	}
	if _, err := parseHexField(first[0]); err == nil {
		return rows
	}
	if len(first) > 0 && strings.EqualFold(strings.TrimSpace(first[0]), "protocol") {
		return rows[1:]
	}
	return rows[1:]
}

// parseHexField accepts "0x00", "0x00,0x01", "0-19", "3-247", "224-255", "20".
func parseHexField(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	// Cipher suites are "0x00,0x01" - first byte is the high byte.
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		if len(parts) >= 2 {
			hi, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 0, 16)
			lo, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 0, 16)
			if err1 == nil && err2 == nil {
				return (hi << 8) | lo, nil
			}
		}
		return 0, fmt.Errorf("bad hex range: %s", s)
	}
	// Skip ranges like "0-19", "3-247", "224-255", "0x0000-0x0200".
	if strings.Contains(s, "-") && !strings.HasPrefix(s, "0x") {
		return 0, fmt.Errorf("range skipped: %s", s)
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s, 0, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

func isRange(s string) bool {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		// Hex range like "0x0000-0x0200" still has a dash in it.
		return strings.Contains(s, "-")
	}
	return strings.Contains(s, "-")
}

// cleanName strips RFC citations, parenthetical annotations, and leading/
// trailing whitespace from a CSV cell. We want the canonical IANA name, not
// rename history.
func cleanName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "["); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	if i := strings.Index(s, "("); i > 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

func parseCipherSuites() []entry {
	rows := skipHeader(readRecords("csv/tls-parameters-4.csv"))
	out := make([]entry, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		if isRange(row[0]) {
			continue
		}
		v, err := parseHexField(row[0])
		if err != nil {
			continue
		}
		name := cleanName(row[1])
		if name == "" {
			continue
		}
		out = append(out, entry{key: v, name: name})
	}
	return out
}

func parseContentTypes() []entry {
	rows := skipHeader(readRecords("csv/tls-parameters-5.csv"))
	out := make([]entry, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		if isRange(row[0]) {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(row[0]), 10, 8)
		if err != nil {
			continue
		}
		name := cleanName(row[1])
		if name == "" {
			continue
		}
		out = append(out, entry{key: v, name: name})
	}
	return out
}

func parseHandshakeTypes() []entry {
	rows := skipHeader(readRecords("csv/tls-parameters-7.csv"))
	out := make([]entry, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		if isRange(row[0]) {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(row[0]), 10, 8)
		if err != nil {
			continue
		}
		name := cleanName(row[1])
		if name == "" {
			continue
		}
		out = append(out, entry{key: v, name: name})
	}
	return out
}

func parseSupportedGroups() []entry {
	rows := skipHeader(readRecords("csv/tls-parameters-8.csv"))
	out := make([]entry, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		if isRange(row[0]) {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(row[0]), 10, 32)
		if err != nil {
			continue
		}
		name := cleanName(row[1])
		if name == "" {
			continue
		}
		out = append(out, entry{key: v, name: name})
	}
	return out
}

func parseECPointFormats() []entry {
	rows := skipHeader(readRecords("csv/tls-parameters-9.csv"))
	out := make([]entry, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		if isRange(row[0]) {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(row[0]), 10, 8)
		if err != nil {
			continue
		}
		name := cleanName(row[1])
		if name == "" {
			continue
		}
		out = append(out, entry{key: v, name: name})
	}
	return out
}

func parseSignatureSchemes() []entry {
	rows := skipHeader(readRecords("csv/tls-signaturescheme.csv"))
	out := make([]entry, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		if isRange(row[0]) {
			continue
		}
		v, err := parseHexField(row[0])
		if err != nil {
			continue
		}
		name := cleanName(row[1])
		if name == "" {
			continue
		}
		out = append(out, entry{key: v, name: name})
	}
	return out
}

func parseExtensions() []entry {
	rows := skipHeader(readRecords("csv/tls-extensiontype-values-1.csv"))
	out := make([]entry, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		if isRange(row[0]) {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(row[0]), 10, 32)
		if err != nil {
			continue
		}
		name := cleanName(row[1])
		if name == "" {
			continue
		}
		out = append(out, entry{key: v, name: name})
	}
	return out
}

var alpnQuoteRE = regexp.MustCompile(`\(\s*\"([^\"]+)\"\s*\)`)

func parseALPN() []alpnEntry {
	rows := readRecords("csv/alpn-protocol-ids.csv")
	if len(rows) > 0 {
		// Drop the header if the first column doesn't look like a protocol.
		first := rows[0]
		if len(first) > 0 && strings.EqualFold(strings.TrimSpace(first[0]), "protocol") {
			rows = rows[1:]
		}
	}
	out := make([]alpnEntry, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		protocol := ""
		matches := alpnQuoteRE.FindStringSubmatch(row[1])
		if len(matches) >= 2 {
			protocol = matches[1]
		}
		if protocol == "" {
			continue
		}
		// First column is the human-friendly description; keep it short.
		name := strings.TrimSpace(row[0])
		if name == "" {
			name = protocol
		}
		out = append(out, alpnEntry{protocol: protocol, name: name})
	}
	return out
}

func parseCompressionMethods() []entry {
	rows := skipHeader(readRecords("csv/comp-meth-ids-2.csv"))
	out := make([]entry, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		if isRange(row[0]) {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(row[0]), 10, 8)
		if err != nil {
			continue
		}
		name := cleanName(row[1])
		if name == "" {
			continue
		}
		out = append(out, entry{key: v, name: name})
	}
	return out
}

func writeUint16Map(name string, entries []entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// %s maps the IANA-assigned value to its registered name.\n", name)
	fmt.Fprintf(&b, "var %s = map[uint16]string{\n", name)
	for _, e := range entries {
		if e.key > 0xFFFF {
			continue
		}
		fmt.Fprintf(&b, "\t0x%04x: %q,\n", e.key, e.name)
	}
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func writeUint8Map(name string, entries []entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// %s maps the IANA-assigned value to its registered name.\n", name)
	fmt.Fprintf(&b, "var %s = map[uint8]string{\n", name)
	for _, e := range entries {
		if e.key > 0xFF {
			continue
		}
		fmt.Fprintf(&b, "\t0x%02x: %q,\n", e.key, e.name)
	}
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func writeUint32Map(name string, entries []entry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// %s maps the IANA-assigned value to its registered name.\n", name)
	fmt.Fprintf(&b, "var %s = map[uint32]string{\n", name)
	for _, e := range entries {
		if e.key > 0xFFFFFFFF {
			continue
		}
		fmt.Fprintf(&b, "\t0x%x: %q,\n", e.key, e.name)
	}
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func writeALPNMap(entries []alpnEntry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// alpnProtocols maps the wire-form ALPN identifier to its IANA\n")
	fmt.Fprintf(&b, "// registered description.\n")
	fmt.Fprintf(&b, "var alpnProtocols = map[string]string{\n")
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if _, dup := seen[e.protocol]; dup {
			continue
		}
		seen[e.protocol] = struct{}{}
		fmt.Fprintf(&b, "\t%q: %q,\n", e.protocol, e.name)
	}
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func sortedUint16(entries []entry) []entry {
	out := append([]entry(nil), entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func sortedUint8(entries []entry) []entry {
	out := append([]entry(nil), entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func sortedUint32(entries []entry) []entry {
	out := append([]entry(nil), entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func main() {
	header := `// Code generated by gen. DO NOT EDIT.
// Source: IANA TLS Parameters assignments, see csv/ directory for inputs.
//
// ponytail: regenerate with ` + "`go run ./gen`" + ` when IANA updates its CSVs.

package tlsnames

`

	var b strings.Builder
	b.WriteString(header)

	b.WriteString(writeUint16Map("cipherSuites", sortedUint16(parseCipherSuites())))
	b.WriteString("\n")
	b.WriteString(writeUint8Map("contentTypes", sortedUint8(parseContentTypes())))
	b.WriteString("\n")
	b.WriteString(writeUint8Map("handshakeTypes", sortedUint8(parseHandshakeTypes())))
	b.WriteString("\n")
	b.WriteString(writeUint32Map("supportedGroups", sortedUint32(parseSupportedGroups())))
	b.WriteString("\n")
	b.WriteString(writeUint8Map("ecPointFormats", sortedUint8(parseECPointFormats())))
	b.WriteString("\n")
	b.WriteString(writeUint16Map("signatureSchemes", sortedUint16(parseSignatureSchemes())))
	b.WriteString("\n")
	b.WriteString(writeUint16Map("extensionTypes", sortedUint16(parseExtensions())))
	b.WriteString("\n")
	b.WriteString(writeUint8Map("compressionMethods", sortedUint8(parseCompressionMethods())))
	b.WriteString("\n")
	b.WriteString(writeALPNMap(parseALPN()))

	out := filepath.Join("lookup.go")
	if err := os.WriteFile(out, []byte(b.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", out, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\n", out)
}
