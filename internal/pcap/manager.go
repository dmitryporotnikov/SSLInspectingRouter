package pcap

import (
	"crypto/md5"
	"math/rand"
	"net"
	"strconv"
	"sync"
)

var (
	GlobalManager *Manager
	dummyMAC      = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	routerMAC     = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
)

type Manager struct {
	writer *Writer
	mu     sync.Mutex
	flows  map[int64]*Flow // Map RequestID to Flow
}

type Flow struct {
	SrcIP   net.IP
	SrcPort int
	DstIP   net.IP
	DstPort int
	Seq     uint32
	Ack     uint32
}

func Init(filename string) error {
	w, err := NewWriter(filename)
	if err != nil {
		return err
	}
	GlobalManager = &Manager{
		writer: w,
		flows:  make(map[int64]*Flow),
	}
	return nil
}

func Close() {
	if GlobalManager != nil && GlobalManager.writer != nil {
		GlobalManager.writer.Close()
	}
}

// Map FQDN to a consistent fake IP (10.200.x.x)
func resolveFakeIP(fqdn string) net.IP {
	hash := md5.Sum([]byte(fqdn))
	// Use 2nd and 3rd bytes of hash for x.y
	return net.IPv4(10, 200, hash[1], hash[2])
}

func (m *Manager) GetOrCreateFlow(reqID int64, srcIPStr, fqdn string) *Flow {
	m.mu.Lock()
	defer m.mu.Unlock()

	if flow, ok := m.flows[reqID]; ok {
		return flow
	}

	srcIP := net.ParseIP(srcIPStr)
	if srcIP == nil {
		srcIP = net.IPv4(192, 168, 1, 100) // Fallback
	}

	// Fake random source port for entropy if we can't get real one
	srcPort := 50000 + (int(reqID) % 10000)

	flow := &Flow{
		SrcIP:   srcIP,
		SrcPort: srcPort,
		DstIP:   resolveFakeIP(fqdn),
		DstPort: 443, // Assuming HTTPS primarily
		Seq:     rand.Uint32(),
		Ack:     rand.Uint32(),
	}
	m.flows[reqID] = flow
	return flow
}

func (m *Manager) WriteRequest(reqID int64, srcIPStr, fqdn string, body []byte) {
	if m == nil {
		return
	}
	flow := m.GetOrCreateFlow(reqID, srcIPStr, fqdn)

	// Simulate handshake only on first packet? simplifying to just PSH/ACK for now
	// To make it look real, we should probably do a handshake. But Wireshark
	// can often tolerate missing handshakes if we just send data.

	// Server -> Client (ACK previous if any)
	// Client -> Server (PSH, ACK) containing request

	pkt := m.buildPacket(flow.SrcIP, flow.DstIP, flow.SrcPort, flow.DstPort, flow.Seq, flow.Ack, 0x18, body) // PSH|ACK
	m.writer.WritePacket(pkt)

	flow.Seq += uint32(len(body))
}

func (m *Manager) WriteResponse(reqID int64, srcIPStr, fqdn string, body []byte) {
	if m == nil {
		return
	}
	// We need the same flow to get correct Seq/Ack
	m.mu.Lock()
	flow, ok := m.flows[reqID]
	m.mu.Unlock()

	if !ok {
		// Should create if missing (e.g. restart) but usually should exist
		flow = m.GetOrCreateFlow(reqID, srcIPStr, fqdn)
	}

	// Server -> Client (PSH, ACK) containing response
	// ACK should acknowledge the request bytes

	pkt := m.buildPacket(flow.DstIP, flow.SrcIP, flow.DstPort, flow.SrcPort, flow.Ack, flow.Seq, 0x18, body) // PSH|ACK swaps roles
	m.writer.WritePacket(pkt)

	// Update Flow State (The Server's sequence advances, Client's ACK advances)
	flow.Ack += uint32(len(body))

	// Clean up flow to save memory? keep for now
}

func (m *Manager) buildPacket(src, dst net.IP, srcPort, dstPort int, seq, ack uint32, flags byte, payload []byte) []byte {
	eth := BuildEthernetHeader(dummyMAC, routerMAC)
	ip := BuildIPv4Header(src, dst, 20+len(payload), 1234)
	tcp := BuildTCPHeader(srcPort, dstPort, seq, ack, flags, 65535, payload, src, dst)

	full := append(eth, ip...)
	full = append(full, tcp...)
	full = append(full, payload...)
	return full
}

// Utility to parse port from IP string if present
func parsePort(s string) int {
	_, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(portStr)
	return p
}
