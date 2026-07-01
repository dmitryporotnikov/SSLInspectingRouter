package pcap_test

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/pcap"
)

func TestPcapGeneration(t *testing.T) {
	tmpfile := "test_output.pcap"
	defer os.Remove(tmpfile)

	// Determine file size before init
	// It should be 0 or not exist

	err := pcap.Init(tmpfile)
	if err != nil {
		t.Fatalf("Failed to init pcap: %v", err)
	}

	// Write a dummy request
	pcap.GlobalManager.WriteRequest(1, "192.168.1.10", "example.com", []byte("GET / HTTP/1.1\r\n\r\n"))

	// Write a dummy response
	pcap.GlobalManager.WriteResponse(1, "192.168.1.10", "example.com", []byte("HTTP/1.1 200 OK\r\n\r\nHello"))

	pcap.Close()

	// Verify file exists and has content
	content, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read pcap file: %v", err)
	}

	if len(content) < 24 {
		t.Fatalf("File too small to contain global header: %d bytes", len(content))
	}

	// Check Magic Number (0xa1b2c3d4 in Little Endian)
	magic := binary.LittleEndian.Uint32(content[0:4])
	if magic != 0xa1b2c3d4 {
		t.Fatalf("Invalid magic number: expected 0xa1b2c3d4, got 0x%x", magic)
	}

	t.Logf("PCAP file generated successfully, size: %d bytes", len(content))
}
