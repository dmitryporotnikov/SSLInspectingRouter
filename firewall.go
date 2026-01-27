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
	rules     []string
}

func NewFirewallManager(httpPort, httpsPort int) *FirewallManager {
	return &FirewallManager{
		httpPort:  httpPort,
		httpsPort: httpsPort,
		rules:     make([]string, 0),
	}
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

	return nil
}

// Cleanup flushes and removes the custom iptables chain.
func (fm *FirewallManager) Cleanup() error {
	LogInfo("Reverting iptables rules...")

	fm.runIPTables("-t", "nat", "-F", "SSLPROXY")
	fm.runIPTables("-t", "nat", "-D", "PREROUTING", "-j", "SSLPROXY")
	fm.runIPTables("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--uid-owner", "0", "-j", "SSLPROXY")
	fm.runIPTables("-t", "nat", "-X", "SSLPROXY")

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
