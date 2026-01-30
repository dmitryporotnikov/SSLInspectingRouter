package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// FirewallManager handles the configuration of iptables rules to transparently intercept traffic.
type FirewallManager struct {
	httpPort  int
	httpsPort int
	dnsPort   int
	enableDNS bool
	blockQuic bool
	rules     []string
}

func NewFirewallManager(httpPort, httpsPort int) *FirewallManager {
	return &FirewallManager{
		httpPort:  httpPort,
		httpsPort: httpsPort,
		dnsPort:   0,
		enableDNS: false,
		blockQuic: false,
		rules:     make([]string, 0),
	}
}

// EnableDNSRedirect toggles DNS interception for a local DNS proxy port.
func (fm *FirewallManager) EnableDNSRedirect(dnsPort int) {
	fm.dnsPort = dnsPort
	fm.enableDNS = true
}

// EnableQUICBlock toggles blocking UDP/443 to force TCP-based HTTPS.
func (fm *FirewallManager) EnableQUICBlock() {
	fm.blockQuic = true
}

// Setup applies the necessary iptables rules to redirect traffic to the proxy ports.
// It requires root privileges.
func (fm *FirewallManager) Setup() error {
	LogInfo("Configuring iptables for transparent proxying...")

	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required for iptables configuration")
	}

	if err := fm.enableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	// Create custom chain SSLPROXY to manage our rules cleanly
	if err := fm.runIPTables("-t", "nat", "-N", "SSLPROXY"); err != nil {
		// If chain exists, flush it to start fresh
		fm.runIPTables("-t", "nat", "-F", "SSLPROXY")
	}

	// Rule: Redirect TCP/80 -> Local HTTP Proxy Port
	rule := []string{
		"-t", "nat", "-A", "SSLPROXY",
		"-p", "tcp", "--dport", "80",
		"-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", fm.httpPort),
	}
	if err := fm.runIPTables(rule...); err != nil {
		return fmt.Errorf("failed to add HTTP redirect rule: %v", err)
	}
	fm.rules = append(fm.rules, strings.Join(rule, " "))

	// Rule: Redirect TCP/443 -> Local HTTPS Proxy Port
	rule = []string{
		"-t", "nat", "-A", "SSLPROXY",
		"-p", "tcp", "--dport", "443",
		"-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", fm.httpsPort),
	}
	if err := fm.runIPTables(rule...); err != nil {
		return fmt.Errorf("failed to add HTTPS redirect rule: %v", err)
	}
	fm.rules = append(fm.rules, strings.Join(rule, " "))

	if fm.enableDNS {
		// Rule: Redirect UDP/53 -> Local DNS Proxy Port
		rule = []string{
			"-t", "nat", "-A", "SSLPROXY",
			"-p", "udp", "--dport", "53",
			"-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", fm.dnsPort),
		}
		if err := fm.runIPTables(rule...); err != nil {
			return fmt.Errorf("failed to add DNS UDP redirect rule: %v", err)
		}
		fm.rules = append(fm.rules, strings.Join(rule, " "))

		// Rule: Redirect TCP/53 -> Local DNS Proxy Port
		rule = []string{
			"-t", "nat", "-A", "SSLPROXY",
			"-p", "tcp", "--dport", "53",
			"-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", fm.dnsPort),
		}
		if err := fm.runIPTables(rule...); err != nil {
			return fmt.Errorf("failed to add DNS TCP redirect rule: %v", err)
		}
		fm.rules = append(fm.rules, strings.Join(rule, " "))
	}

	if fm.blockQuic {
		// Rule: Drop UDP/443 in FORWARD to block QUIC from clients
		rule = []string{
			"-t", "filter", "-A", "FORWARD",
			"-p", "udp", "--dport", "443",
			"-j", "DROP",
		}
		if err := fm.runIPTables(rule...); err != nil {
			return fmt.Errorf("failed to add QUIC block rule (FORWARD): %v", err)
		}
		fm.rules = append(fm.rules, strings.Join(rule, " "))

		// Rule: Drop UDP/443 in OUTPUT for local traffic
		rule = []string{
			"-t", "filter", "-A", "OUTPUT",
			"-p", "udp", "--dport", "443",
			"-j", "DROP",
		}
		if err := fm.runIPTables(rule...); err != nil {
			return fmt.Errorf("failed to add QUIC block rule (OUTPUT): %v", err)
		}
		fm.rules = append(fm.rules, strings.Join(rule, " "))
	}

	// Apply SSLPROXY chain to PREROUTING (for incoming traffic from other devices)
	rule = []string{
		"-t", "nat", "-A", "PREROUTING",
		"-j", "SSLPROXY",
	}
	if err := fm.runIPTables(rule...); err != nil {
		return fmt.Errorf("failed to apply SSLPROXY chain: %v", err)
	}
	fm.rules = append(fm.rules, strings.Join(rule, " "))

	// Optional: Apply to OUTPUT for local traffic (excluding root to avoid loops)
	rule = []string{
		"-t", "nat", "-A", "OUTPUT",
		"-p", "tcp", "-m", "owner", "!", "--uid-owner", "0",
		"-j", "SSLPROXY",
	}
	if err := fm.runIPTables(rule...); err != nil {
		LogError(fmt.Sprintf("Failed to apply OUTPUT chain rule (non-critical): %v", err))
	} else {
		fm.rules = append(fm.rules, strings.Join(rule, " "))
	}

	LogInfo("iptables configured.")
	LogInfo(fmt.Sprintf("Redirecting port 80  -> :%d", fm.httpPort))
	LogInfo(fmt.Sprintf("Redirecting port 443 -> :%d", fm.httpsPort))
	if fm.enableDNS {
		LogInfo(fmt.Sprintf("Redirecting DNS (53/udp,tcp) -> :%d", fm.dnsPort))
	}
	if fm.blockQuic {
		LogInfo("Blocking QUIC (UDP/443)")
	}

	return nil
}

// Cleanup flushes and removes the custom iptables chain.
func (fm *FirewallManager) Cleanup() error {
	LogInfo("Reverting iptables rules...")

	fm.runIPTables("-t", "nat", "-F", "SSLPROXY")
	fm.runIPTables("-t", "nat", "-D", "PREROUTING", "-j", "SSLPROXY")
	fm.runIPTables("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--uid-owner", "0", "-j", "SSLPROXY")
	fm.runIPTables("-t", "nat", "-X", "SSLPROXY")
	if fm.blockQuic {
		fm.runIPTables("-t", "filter", "-D", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP")
		fm.runIPTables("-t", "filter", "-D", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "DROP")
	}

	LogInfo("iptables rules cleaned up.")
	return nil
}

func (fm *FirewallManager) enableIPForwarding() error {
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sysctl failed: %v, output: %s", err, string(output))
	}
	return nil
}

func (fm *FirewallManager) runIPTables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables failed: %v, output: %s", err, string(output))
	}
	return nil
}

func (fm *FirewallManager) GetHTTPPort() int {
	return fm.httpPort
}

func (fm *FirewallManager) GetHTTPSPort() int {
	return fm.httpsPort
}
