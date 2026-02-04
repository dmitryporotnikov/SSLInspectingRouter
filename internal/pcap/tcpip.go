package pcap

import (
	"encoding/binary"
	"net"
)

// Checksum logic
func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func BuildEthernetHeader(src, dst net.HardwareAddr) []byte {
	// 6 bytes dst, 6 bytes src, 2 bytes type (IPv4 0x0800)
	buf := make([]byte, 14)
	copy(buf[0:6], dst)
	copy(buf[6:12], src)
	binary.BigEndian.PutUint16(buf[12:14], 0x0800)
	return buf
}

func BuildIPv4Header(srcIP, dstIP net.IP, length int, id uint16) []byte {
	// Standard 20 byte IPv4 header
	h := make([]byte, 20)
	h[0] = 0x45                                           // Version 4, Header length 5 words (20 bytes)
	h[1] = 0x00                                           // TOS
	binary.BigEndian.PutUint16(h[2:4], uint16(20+length)) // Total Length
	binary.BigEndian.PutUint16(h[4:6], id)                // ID
	h[6] = 0x40                                           // Flags: Don't Fragment
	h[7] = 0x00                                           // Frag Offset
	h[8] = 64                                             // TTL
	h[9] = 6                                              // Protocol: TCP
	h[10] = 0x00                                          // Checksum (zero for calc)
	h[11] = 0x00

	copy(h[12:16], srcIP.To4())
	copy(h[16:20], dstIP.To4())

	// Calculate header checksum
	cs := checksum(h)
	binary.BigEndian.PutUint16(h[10:12], cs)

	return h
}

func BuildTCPHeader(srcPort, dstPort int, seq, ack uint32, flags byte, window uint16, payload []byte, srcIP, dstIP net.IP) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(h[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(h[4:8], seq)
	binary.BigEndian.PutUint32(h[8:12], ack)
	h[12] = 0x50 // Data Offset (5 words = 20 bytes), no options
	h[13] = flags
	binary.BigEndian.PutUint16(h[14:16], window)
	h[16] = 0x00 // Checksum (zero for calc)
	h[17] = 0x00
	h[18] = 0x00 // Urgent Pointer
	h[19] = 0x00

	// Pseudo Header for Checksum
	// SrcIP (4), DstIP (4), Zero (1), Protocol (1), TCP Length (2)
	pseudoLen := 12 + 20 + len(payload)
	pseudo := make([]byte, pseudoLen)
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(20+len(payload)))
	copy(pseudo[12:32], h)
	copy(pseudo[32:], payload)

	cs := checksum(pseudo)
	binary.BigEndian.PutUint16(h[16:18], cs)

	return h
}
