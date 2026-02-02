package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

// FirewallManager handles the configuration of iptables rules to transparently intercept traffic.
type FirewallManager struct {
	httpPort       int
	httpsPort      int
	dnsPort        int
	enableDNS      bool
	blockQuic      bool
	blockedIPs     []string
	inspectOnlyIPs []string
	rules          []string
}

func NewFirewallManager(httpPort, httpsPort int) *FirewallManager {
	return &FirewallManager{
		httpPort:       httpPort,
		httpsPort:      httpsPort,
		dnsPort:        0,
		enableDNS:      false,
		blockQuic:      false,
		blockedIPs:     make([]string, 0),
		inspectOnlyIPs: make([]string, 0),
		rules:          make([]string, 0),
	}
}

// EnableInspectOnly restricts interception to the specified source IPs.
func (fm *FirewallManager) EnableInspectOnly(ips []string) {
	fm.inspectOnlyIPs = append(fm.inspectOnlyIPs, ips...)
}

// EnableIPBlocking configures the firewall to drop traffic to specific IPs/CIDRs.
func (fm *FirewallManager) EnableIPBlocking(ips []string) {
	fm.blockedIPs = append(fm.blockedIPs, ips...)
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
	logger.LogInfo("Configuring iptables for transparent proxying...")

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

	// Create custom chain SSL_DISPATCH to manage entry points
	if err := fm.runIPTables("-t", "nat", "-N", "SSL_DISPATCH"); err != nil {
		// If chain exists, flush it to start fresh
		fm.runIPTables("-t", "nat", "-F", "SSL_DISPATCH")
	} else {
		// New chain created
		fm.rules = append(fm.rules, "SSL_DISPATCH_CREATED") // Marker to remove chain on cleanup
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

	// Apply IP blocking rules (DROP)
	for _, ip := range fm.blockedIPs {
		// Rule: Drop in FORWARD (for traffic passing through the router)
		rule = []string{
			"-t", "filter", "-I", "FORWARD",
			"-d", ip, "-j", "DROP",
		}
		if err := fm.runIPTables(rule...); err != nil {
			logger.LogError(fmt.Sprintf("Failed to add BLOCK rule for %s (FORWARD): %v", ip, err))
		} else {
			fm.rules = append(fm.rules, strings.Join(rule, " "))
		}

		// Rule: Drop in OUTPUT (for traffic originating from the router itself)
		rule = []string{
			"-t", "filter", "-I", "OUTPUT",
			"-d", ip, "-j", "DROP",
		}
		if err := fm.runIPTables(rule...); err != nil {
			logger.LogError(fmt.Sprintf("Failed to add BLOCK rule for %s (OUTPUT): %v", ip, err))
		} else {
			fm.rules = append(fm.rules, strings.Join(rule, " "))
		}
	}

	// Populate SSL_DISPATCH
	// If inspect-only mode is active, apply distinct rules for each allowed source IP.
	// Otherwise, apply a global redirect.
	if len(fm.inspectOnlyIPs) > 0 {
		for _, ip := range fm.inspectOnlyIPs {
			rule := []string{
				"-t", "nat", "-A", "SSL_DISPATCH",
				"-s", ip,
				"-j", "SSLPROXY",
			}
			if err := fm.runIPTables(rule...); err != nil {
				return fmt.Errorf("failed to apply SSL_DISPATCH rule for source %s: %v", ip, err)
			}
		}
	} else {
		rule := []string{
			"-t", "nat", "-A", "SSL_DISPATCH",
			"-j", "SSLPROXY",
		}
		if err := fm.runIPTables(rule...); err != nil {
			return fmt.Errorf("failed to apply SSL_DISPATCH global rule: %v", err)
		}
	}

	// Link PREROUTING to SSL_DISPATCH
	// First, clean up any old direct links to SSLPROXY or SSL_DISPATCH
	fm.cleanLegacyRules()

	rule = []string{
		"-t", "nat", "-A", "PREROUTING",
		"-j", "SSL_DISPATCH",
	}
	if err := fm.runIPTables(rule...); err != nil {
		return fmt.Errorf("failed to link PREROUTING to SSL_DISPATCH: %v", err)
	}
	fm.rules = append(fm.rules, strings.Join(rule, " "))

	// Optional: Apply to OUTPUT for local traffic (excluding root to avoid loops)
	rule = []string{
		"-t", "nat", "-A", "OUTPUT",
		"-p", "tcp", "-m", "owner", "!", "--uid-owner", "0",
		"-j", "SSL_DISPATCH",
	}
	if err := fm.runIPTables(rule...); err != nil {
		logger.LogError(fmt.Sprintf("Failed to apply OUTPUT chain rule (non-critical): %v", err))
	} else {
		fm.rules = append(fm.rules, strings.Join(rule, " "))
	}

	logger.LogInfo("iptables configured.")
	logger.LogInfo(fmt.Sprintf("Redirecting port 80  -> :%d", fm.httpPort))
	logger.LogInfo(fmt.Sprintf("Redirecting port 443 -> :%d", fm.httpsPort))
	if fm.enableDNS {
		logger.LogInfo(fmt.Sprintf("Redirecting DNS (53/udp,tcp) -> :%d", fm.dnsPort))
	}
	if fm.blockQuic {
		logger.LogInfo("Blocking QUIC (UDP/443)")
	}
	if len(fm.inspectOnlyIPs) > 0 {
		logger.LogInfo(fmt.Sprintf("Inspection limited to %d source IPs", len(fm.inspectOnlyIPs)))
	}
	if len(fm.blockedIPs) > 0 {
		logger.LogInfo(fmt.Sprintf("Blocking %d IPs/CIDRs at network layer", len(fm.blockedIPs)))
	}

	return nil
}

// Cleanup flushes and removes the custom iptables chain.
func (fm *FirewallManager) Cleanup() error {
	logger.LogInfo("Reverting iptables rules...")

	// Remove links from PREROUTING and OUTPUT
	fm.runIPTables("-t", "nat", "-D", "PREROUTING", "-j", "SSL_DISPATCH")
	fm.runIPTables("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--uid-owner", "0", "-j", "SSL_DISPATCH")

	// Flush and delete SSL_DISPATCH
	fm.runIPTables("-t", "nat", "-F", "SSL_DISPATCH")
	fm.runIPTables("-t", "nat", "-X", "SSL_DISPATCH")

	// Flush and delete SSLPROXY
	fm.runIPTables("-t", "nat", "-F", "SSLPROXY")
	fm.runIPTables("-t", "nat", "-X", "SSLPROXY")

	if fm.blockQuic {
		fm.runIPTables("-t", "filter", "-D", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP")
		fm.runIPTables("-t", "filter", "-D", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "DROP")
	}

	// Cleanup blocking rules
	for _, ip := range fm.blockedIPs {
		fm.runIPTables("-t", "filter", "-D", "FORWARD", "-d", ip, "-j", "DROP")
		fm.runIPTables("-t", "filter", "-D", "OUTPUT", "-d", ip, "-j", "DROP")
	}

	logger.LogInfo("iptables rules cleaned up.")
	return nil
}

func (fm *FirewallManager) cleanLegacyRules() {
	// Best effort cleanup of any potential lingering rules
	// We loop because there might be multiple entries if previous runs crashed hard
	for {
		if err := fm.runIPTables("-t", "nat", "-D", "PREROUTING", "-j", "SSLPROXY"); err != nil {
			break
		}
	}
	for {
		if err := fm.runIPTables("-t", "nat", "-D", "PREROUTING", "-j", "SSL_DISPATCH"); err != nil {
			break
		}
	}
	// Also clean OUTPUT legacy
	for {
		if err := fm.runIPTables("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--uid-owner", "0", "-j", "SSLPROXY"); err != nil {
			break
		}
	}
	for {
		if err := fm.runIPTables("-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--uid-owner", "0", "-j", "SSL_DISPATCH"); err != nil {
			break
		}
	}
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
