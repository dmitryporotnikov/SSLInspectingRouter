package dnsproxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/blocklist"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

const (
	DNS_PROXY_PORT = 5353
	dnsTimeout     = 2 * time.Second
)

type DNSProxy struct {
	listenAddr string
	upstreams  []string
	blockList  *blocklist.BlockList
}

func NewDNSProxy(listenPort int, blockList *blocklist.BlockList) (*DNSProxy, error) {
	if blockList == nil || blockList.Count() == 0 {
		return nil, errors.New("drop list is empty")
	}

	upstreams, err := readResolvConf("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	if len(upstreams) == 0 {
		return nil, errors.New("no upstream nameservers found in /etc/resolv.conf")
	}

	upstreamAddrs := make([]string, 0, len(upstreams))
	for _, upstream := range upstreams {
		upstreamAddrs = append(upstreamAddrs, net.JoinHostPort(upstream, "53"))
	}

	return &DNSProxy{
		listenAddr: fmt.Sprintf(":%d", listenPort),
		upstreams:  upstreamAddrs,
		blockList:  blockList,
	}, nil
}

func (p *DNSProxy) Start() error {
	udpConn, err := net.ListenPacket("udp", p.listenAddr)
	if err != nil {
		return fmt.Errorf("DNS UDP listen failed: %v", err)
	}

	tcpLn, err := net.Listen("tcp", p.listenAddr)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("DNS TCP listen failed: %v", err)
	}

	go p.serveUDP(udpConn)
	go p.serveTCP(tcpLn)
	return nil
}

func (p *DNSProxy) serveUDP(conn net.PacketConn) {
	defer conn.Close()
	buf := make([]byte, 4096)

	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			logger.LogError(fmt.Sprintf("DNS UDP read error: %v", err))
			continue
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		blocked, qname, qtype := p.analyzeQuery(payload)
		sourceIP, _, _ := net.SplitHostPort(addr.String())
		var reqID int64
		if qname != "" {
			reqID = logger.LogDNSRequest(sourceIP, qname, qtype)
		}
		if blocked {
			logger.LogInfo(fmt.Sprintf("Dropped DNS UDP query for %s from %s", qname, addr.String()))
			if qname != "" {
				logger.LogDNSResponse(reqID, sourceIP, qname, "DNS DROPPED", "Blocked by policy")
			}
			continue
		}

		resp, err := p.forwardUDP(payload)
		if err != nil {
			logger.LogError(fmt.Sprintf("DNS UDP forward error: %v", err))
			continue
		}
		if qname != "" {
			logger.LogDNSResponse(reqID, sourceIP, qname, "DNS RESPONSE", fmt.Sprintf("Bytes: %d", len(resp)))
		}

		if _, err := conn.WriteTo(resp, addr); err != nil {
			logger.LogError(fmt.Sprintf("DNS UDP write error: %v", err))
		}
	}
}

func (p *DNSProxy) serveTCP(ln net.Listener) {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			logger.LogError(fmt.Sprintf("DNS TCP accept error: %v", err))
			continue
		}
		go p.handleTCP(conn)
	}
}

func (p *DNSProxy) handleTCP(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dnsTimeout))

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		return
	}
	msgLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
	if msgLen <= 0 || msgLen > 65535 {
		return
	}

	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return
	}

	blocked, qname, qtype := p.analyzeQuery(msg)
	sourceIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	var reqID int64
	if qname != "" {
		reqID = logger.LogDNSRequest(sourceIP, qname, qtype)
	}
	if blocked {
		logger.LogInfo(fmt.Sprintf("Dropped DNS TCP query for %s from %s", qname, conn.RemoteAddr().String()))
		if qname != "" {
			logger.LogDNSResponse(reqID, sourceIP, qname, "DNS DROPPED", "Blocked by policy")
		}
		return
	}

	resp, err := p.forwardTCP(msg)
	if err != nil {
		logger.LogError(fmt.Sprintf("DNS TCP forward error: %v", err))
		return
	}
	if qname != "" {
		logger.LogDNSResponse(reqID, sourceIP, qname, "DNS RESPONSE", fmt.Sprintf("Bytes: %d", len(resp)))
	}

	respLen := len(resp)
	if respLen > 65535 {
		return
	}
	respHdr := []byte{byte(respLen >> 8), byte(respLen & 0xff)}
	conn.Write(respHdr)
	conn.Write(resp)
}

func (p *DNSProxy) analyzeQuery(msg []byte) (bool, string, string) {
	name, qtype, err := parseDNSQuestion(msg)
	if err != nil {
		return false, "", ""
	}
	if p.blockList == nil {
		return false, name, qtype
	}
	return p.blockList.Matches(name), name, qtype
}

func (p *DNSProxy) forwardUDP(payload []byte) ([]byte, error) {
	var lastErr error
	for _, upstream := range p.upstreams {
		conn, err := net.DialTimeout("udp", upstream, dnsTimeout)
		if err != nil {
			lastErr = err
			continue
		}

		conn.SetDeadline(time.Now().Add(dnsTimeout))
		if _, err := conn.Write(payload); err != nil {
			lastErr = err
			conn.Close()
			continue
		}

		respBuf := make([]byte, 4096)
		n, err := conn.Read(respBuf)
		conn.Close()
		if err != nil {
			lastErr = err
			continue
		}

		return respBuf[:n], nil
	}
	return nil, fmt.Errorf("all upstreams failed: %v", lastErr)
}

func (p *DNSProxy) forwardTCP(payload []byte) ([]byte, error) {
	var lastErr error
	for _, upstream := range p.upstreams {
		conn, err := net.DialTimeout("tcp", upstream, dnsTimeout)
		if err != nil {
			lastErr = err
			continue
		}

		conn.SetDeadline(time.Now().Add(dnsTimeout))
		length := len(payload)
		header := []byte{byte(length >> 8), byte(length & 0xff)}
		if _, err := conn.Write(append(header, payload...)); err != nil {
			lastErr = err
			conn.Close()
			continue
		}

		respHdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, respHdr); err != nil {
			lastErr = err
			conn.Close()
			continue
		}
		respLen := int(respHdr[0])<<8 | int(respHdr[1])
		if respLen <= 0 || respLen > 65535 {
			lastErr = errors.New("invalid response length")
			conn.Close()
			continue
		}
		resp := make([]byte, respLen)
		if _, err := io.ReadFull(conn, resp); err != nil {
			lastErr = err
			conn.Close()
			continue
		}
		conn.Close()
		return resp, nil
	}
	return nil, fmt.Errorf("all upstreams failed: %v", lastErr)
}

func extractQuestionName(msg []byte) (string, error) {
	name, _, err := parseDNSQuestion(msg)
	return name, err
}

func parseDNSQuestion(msg []byte) (string, string, error) {
	var p dnsmessage.Parser
	if _, err := p.Start(msg); err != nil {
		return "", "", err
	}
	question, err := p.Question()
	if err != nil {
		return "", "", err
	}
	return question.Name.String(), question.Type.String(), nil
}

func readResolvConf(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", path, err)
	}
	defer file.Close()

	nameservers := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			nameservers = append(nameservers, fields[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", path, err)
	}
	return nameservers, nil
}
