package firewall

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

const (
	forwardEstablishedRuleComment = "SSLINSPECT_FWD_EST"
	forwardAllowRuleComment       = "SSLINSPECT_FWD_ALL"
	forwardOutboundRuleComment    = "SSLINSPECT_FWD_OUTBOUND"
	outboundAcceptRuleComment     = "SSLINSPECT_OUTBOUND_ACCEPT"
	outboundDropRuleComment       = "SSLINSPECT_OUTBOUND_DROP"
	masqueradeRuleComment         = "SSLINSPECT_MASQ"
	outboundChainName             = "SSL_OUTBOUND"
)

// OutboundPortEntry is a single (port, protocol) tuple allowed through SSL_OUTBOUND.
type OutboundPortEntry struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp" or "udp"
}

// FirewallManager handles the configuration of iptables rules to transparently intercept traffic.
type FirewallManager struct {
	httpPort           int
	httpsPort          int
	dnsPort            int
	enableDNS          bool
	blockQuic          bool
	blockedIPs         []string
	inspectOnlyIPs     []string
	additionalTLSPorts []int
	lanInterface       string
	egressInterface    string
	defaultEgressIF    string
	rules              []string
	// outboundsActive mirrors whether ApplyOutboundPorts(true, ...) is currently in effect.
	// It is used by Cleanup and by re-apply calls to avoid duplicate work.
	outboundsActive bool
	outboundsMu     sync.Mutex
	outboundEntries []OutboundPortEntry
}

func NewFirewallManager(httpPort, httpsPort int) *FirewallManager {
	return &FirewallManager{
		httpPort:           httpPort,
		httpsPort:          httpsPort,
		dnsPort:            0,
		enableDNS:          false,
		blockQuic:          false,
		blockedIPs:         make([]string, 0),
		inspectOnlyIPs:     make([]string, 0),
		additionalTLSPorts: make([]int, 0),
		lanInterface:       "",
		egressInterface:    "",
		defaultEgressIF:    "",
		rules:              make([]string, 0),
		outboundsActive:    false,
		outboundEntries:    make([]OutboundPortEntry, 0),
	}
}

// SetLANInterface pins the LAN-side ingress interface. When set, the
// PREROUTING → SSL_DISPATCH rules are constrained with `-i <lan>` so only
// traffic ingressing on this interface is intercepted.
func (fm *FirewallManager) SetLANInterface(iface string) {
	fm.lanInterface = strings.TrimSpace(iface)
}

// LANInterface returns the configured LAN ingress interface, or empty string
// when not pinned (single-NIC behavior).
func (fm *FirewallManager) LANInterface() string {
	return fm.lanInterface
}

// EnableInspectOnly restricts interception to the specified source IPs.
func (fm *FirewallManager) EnableInspectOnly(ips []string) {
	fm.inspectOnlyIPs = append(fm.inspectOnlyIPs, ips...)
}

// EnableAdditionalTLSPorts enables interception for extra TLS destination ports
// that should be redirected to the local HTTPS proxy listener.
func (fm *FirewallManager) EnableAdditionalTLSPorts(ports []int) {
	fm.additionalTLSPorts = append(fm.additionalTLSPorts, ports...)
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

	if fm.egressInterface == "" {
		iface, err := detectDefaultEgressInterface()
		if err != nil {
			return fmt.Errorf("failed to detect default egress interface: %v", err)
		}
		fm.egressInterface = iface
		fm.defaultEgressIF = iface
	}
	if fm.defaultEgressIF == "" {
		fm.defaultEgressIF = fm.egressInterface
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

	for _, port := range fm.additionalTLSPorts {
		rule = []string{
			"-t", "nat", "-A", "SSLPROXY",
			"-p", "tcp", "--dport", strconv.Itoa(port),
			"-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", fm.httpsPort),
		}
		if err := fm.runIPTables(rule...); err != nil {
			return fmt.Errorf("failed to add TLS redirect rule for port %d: %v", port, err)
		}
		fm.rules = append(fm.rules, strings.Join(rule, " "))
	}

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
			rule = fm.appendIngressIface(rule)
			if err := fm.runIPTables(rule...); err != nil {
				return fmt.Errorf("failed to apply SSL_DISPATCH rule for source %s: %v", ip, err)
			}
		}
	} else {
		rule := []string{
			"-t", "nat", "-A", "SSL_DISPATCH",
			"-j", "SSLPROXY",
		}
		rule = fm.appendIngressIface(rule)
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
	rule = fm.appendIngressIface(rule)
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
	// The OUTPUT chain attaches to locally generated traffic, so the LAN
	// ingress filter does not apply here.
	if err := fm.runIPTables(rule...); err != nil {
		logger.LogError(fmt.Sprintf("Failed to apply OUTPUT chain rule (non-critical): %v", err))
	} else {
		fm.rules = append(fm.rules, strings.Join(rule, " "))
	}

	if err := fm.configureGatewayForwarding(); err != nil {
		return fmt.Errorf("failed to configure forwarding/NAT pass-through: %v", err)
	}

	logger.LogInfo("iptables configured.")
	logger.LogInfo(fmt.Sprintf("Redirecting port 80  -> :%d", fm.httpPort))
	logger.LogInfo(fmt.Sprintf("Redirecting port 443 -> :%d", fm.httpsPort))
	if len(fm.additionalTLSPorts) > 0 {
		ports := make([]string, 0, len(fm.additionalTLSPorts))
		for _, port := range fm.additionalTLSPorts {
			ports = append(ports, strconv.Itoa(port))
		}
		logger.LogInfo(fmt.Sprintf("Redirecting extra TLS ports [%s] -> :%d", strings.Join(ports, ","), fm.httpsPort))
	}
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
	if fm.lanInterface != "" {
		logger.LogInfo(fmt.Sprintf("LAN ingress pinned to %s (PREROUTING constrained)", fm.lanInterface))
	}
	logger.LogInfo(fmt.Sprintf("Gateway pass-through enabled on interface %s (FORWARD + MASQUERADE)", fm.egressInterface))

	return nil
}

// Cleanup flushes and removes the custom iptables chain.
func (fm *FirewallManager) Cleanup() error {
	logger.LogInfo("Reverting iptables rules...")

	// Remove the SSL_OUTBOUND chain first so the FORWARD jump is gone before
	// we delete the unconditional ACCEPT it replaced.
	fm.removeOutboundChain()

	// Remove links from PREROUTING and OUTPUT
	fm.deleteRuleCompletely([]string{"-t", "nat", "-A", "PREROUTING", "-j", "SSL_DISPATCH"})
	if fm.lanInterface != "" {
		fm.deleteRuleCompletely([]string{
			"-t", "nat", "-A", "PREROUTING", "-i", fm.lanInterface, "-j", "SSL_DISPATCH",
		})
	}
	fm.deleteRuleCompletely([]string{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "!", "--uid-owner", "0", "-j", "SSL_DISPATCH"})

	// Flush and delete SSL_DISPATCH
	fm.runIPTables("-t", "nat", "-F", "SSL_DISPATCH")
	fm.runIPTables("-t", "nat", "-X", "SSL_DISPATCH")

	// Flush and delete SSLPROXY
	fm.runIPTables("-t", "nat", "-F", "SSLPROXY")
	fm.runIPTables("-t", "nat", "-X", "SSLPROXY")

	if fm.blockQuic {
		fm.deleteRuleCompletely([]string{"-t", "filter", "-A", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP"})
		fm.deleteRuleCompletely([]string{"-t", "filter", "-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "DROP"})
	}

	// Cleanup blocking rules
	for _, ip := range fm.blockedIPs {
		fm.deleteRuleCompletely([]string{"-t", "filter", "-A", "FORWARD", "-d", ip, "-j", "DROP"})
		fm.deleteRuleCompletely([]string{"-t", "filter", "-A", "OUTPUT", "-d", ip, "-j", "DROP"})
	}

	fm.deleteRuleCompletely([]string{
		"-t", "filter", "-A", "FORWARD",
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
		"-m", "comment", "--comment", forwardEstablishedRuleComment,
		"-j", "ACCEPT",
	})
	fm.deleteRuleCompletely([]string{
		"-t", "filter", "-A", "FORWARD",
		"-m", "comment", "--comment", forwardAllowRuleComment,
		"-j", "ACCEPT",
	})

	if fm.egressInterface == "" {
		if iface, err := detectDefaultEgressInterface(); err == nil {
			fm.egressInterface = iface
		}
	}
	if fm.egressInterface != "" {
		fm.deleteRuleCompletely(masqueradeRuleForInterface(fm.egressInterface))
	}
	if fm.defaultEgressIF != "" && fm.defaultEgressIF != fm.egressInterface {
		fm.deleteRuleCompletely(masqueradeRuleForInterface(fm.defaultEgressIF))
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
	// Legacy constrained PREROUTING links from previous dual-NIC runs.
	if fm.lanInterface != "" {
		for {
			if err := fm.runIPTables("-t", "nat", "-D", "PREROUTING", "-i", fm.lanInterface, "-j", "SSL_DISPATCH"); err != nil {
				break
			}
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
	// Cleanup forwarding/NAT pass-through rules from previous runs.
	fm.deleteRuleCompletely([]string{
		"-t", "filter", "-A", "FORWARD",
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
		"-m", "comment", "--comment", forwardEstablishedRuleComment,
		"-j", "ACCEPT",
	})
	fm.deleteRuleCompletely([]string{
		"-t", "filter", "-A", "FORWARD",
		"-m", "comment", "--comment", forwardAllowRuleComment,
		"-j", "ACCEPT",
	})
	fm.deleteRuleCompletely([]string{
		"-t", "filter", "-A", "FORWARD",
		"-m", "comment", "--comment", forwardOutboundRuleComment,
		"-j", outboundChainName,
	})
	if fm.egressInterface != "" {
		fm.deleteRuleCompletely(masqueradeRuleForInterface(fm.egressInterface))
	}
	if fm.defaultEgressIF != "" && fm.defaultEgressIF != fm.egressInterface {
		fm.deleteRuleCompletely(masqueradeRuleForInterface(fm.defaultEgressIF))
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

func (fm *FirewallManager) EgressInterface() string {
	return fm.egressInterface
}

func (fm *FirewallManager) DefaultEgressInterface() string {
	if fm.defaultEgressIF != "" {
		return fm.defaultEgressIF
	}
	return fm.egressInterface
}

// SetEgressInterface switches outbound NAT masquerading to a target interface.
func (fm *FirewallManager) SetEgressInterface(iface string) error {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return fmt.Errorf("egress interface cannot be empty")
	}

	if fm.egressInterface != "" && fm.egressInterface != iface {
		fm.deleteRuleCompletely(masqueradeRuleForInterface(fm.egressInterface))
	}

	masqueradeRule := masqueradeRuleForInterface(iface)
	fm.deleteRuleCompletely(masqueradeRule)
	if err := fm.runIPTables(masqueradeRule...); err != nil {
		return fmt.Errorf("failed to add POSTROUTING masquerade rule on %s: %v", iface, err)
	}
	fm.rules = append(fm.rules, strings.Join(masqueradeRule, " "))

	fm.egressInterface = iface
	if fm.defaultEgressIF == "" {
		fm.defaultEgressIF = iface
	}
	logger.LogInfo(fmt.Sprintf("Gateway egress interface: %s", fm.egressInterface))
	return nil
}

func (fm *FirewallManager) configureGatewayForwarding() error {
	forwardEstablishedRule := []string{
		"-t", "filter", "-A", "FORWARD",
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
		"-m", "comment", "--comment", forwardEstablishedRuleComment,
		"-j", "ACCEPT",
	}
	fm.deleteRuleCompletely(forwardEstablishedRule)
	if err := fm.runIPTables(forwardEstablishedRule...); err != nil {
		return fmt.Errorf("failed to add FORWARD established/related rule: %v", err)
	}
	fm.rules = append(fm.rules, strings.Join(forwardEstablishedRule, " "))

	forwardAllowRule := []string{
		"-t", "filter", "-A", "FORWARD",
		"-m", "comment", "--comment", forwardAllowRuleComment,
		"-j", "ACCEPT",
	}
	fm.deleteRuleCompletely(forwardAllowRule)
	if err := fm.runIPTables(forwardAllowRule...); err != nil {
		return fmt.Errorf("failed to add FORWARD allow rule: %v", err)
	}
	fm.rules = append(fm.rules, strings.Join(forwardAllowRule, " "))

	if err := fm.SetEgressInterface(fm.egressInterface); err != nil {
		return err
	}

	return nil
}

func (fm *FirewallManager) deleteRuleCompletely(addRule []string) {
	delRule := make([]string, len(addRule))
	copy(delRule, addRule)
	for i, arg := range delRule {
		if arg == "-A" || arg == "-I" {
			delRule[i] = "-D"
			break
		}
	}
	for {
		if err := fm.runIPTables(delRule...); err != nil {
			break
		}
	}
}

func detectDefaultEgressInterface() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("open /proc/net/route: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Skip header.
	if !scanner.Scan() {
		return "", fmt.Errorf("empty routing table")
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		// Destination 00000000 represents the default route.
		if fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseInt(fields[3], 16, 64)
		if err != nil {
			continue
		}
		// Route flag 0x1 indicates the route is up.
		if flags&0x1 == 0 {
			continue
		}
		iface := fields[0]
		if iface != "" && iface != "lo" {
			return iface, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read /proc/net/route: %w", err)
	}

	return "", fmt.Errorf("default route interface not found")
}

func masqueradeRuleForInterface(iface string) []string {
	return []string{
		"-t", "nat", "-A", "POSTROUTING",
		"-o", iface,
		"-m", "comment", "--comment", masqueradeRuleComment,
		"-j", "MASQUERADE",
	}
}

// appendIngressIface inserts `-i <lanInterface>` before the jump target
// when a LAN ingress interface is configured. Match options must precede
// `-j`; target-specific options, if any, stay after it.
func (fm *FirewallManager) appendIngressIface(rule []string) []string {
	if fm.lanInterface == "" {
		return rule
	}
	out := make([]string, 0, len(rule)+2)
	for i, arg := range rule {
		if arg == "-j" {
			out = append(out, "-i", fm.lanInterface)
			out = append(out, rule[i:]...)
			return out
		}
		out = append(out, arg)
	}
	return append(out, "-i", fm.lanInterface)
}

// ApplyOutboundPorts toggles the SSL_OUTBOUND chain. When enabled is true
// and entries is non-empty, the chain is (re)built with one ACCEPT per
// (protocol, port) pair and a terminating DROP, and the FORWARD chain is
// rewired to jump to it (replacing the unconditional FORWARD ACCEPT for
// forwarded traffic — ESTABLISHED/RELATED remains accepted above).
//
// When enabled is false or entries is empty, the chain and the FORWARD
// jump are removed and the original FORWARD ACCEPT is restored.
//
// Returns the first iptables error encountered; partial state is best
// effort and is always cleaned up before returning.
func (fm *FirewallManager) ApplyOutboundPorts(enabled bool, entries []OutboundPortEntry) error {
	fm.outboundsMu.Lock()
	defer fm.outboundsMu.Unlock()
	// Always tear down any previous outbound state first so re-apply is
	// idempotent and the new entries are installed into a clean chain.
	if err := fm.removeOutboundChain(); err != nil {
		return err
	}

	normalized := normalizeOutboundEntries(entries)
	fm.outboundEntries = normalized

	if !enabled || len(normalized) == 0 {
		fm.outboundsActive = false
		// Reinstall the unconditional FORWARD ACCEPT that we previously removed.
		// Use -I (insert) so the rule lands right after the ESTABLISHED,RELATED
		// rule, even if other rules were added between SSL_OUTBOUND toggles.
		restoreRule := forwardAllowAllInsertRule()
		fm.deleteRuleCompletely(forwardAllowAllRule())
		if err := fm.runIPTables(restoreRule...); err != nil {
			return fmt.Errorf("failed to restore FORWARD accept-all: %w", err)
		}
		fm.rules = append(fm.rules, strings.Join(restoreRule, " "))
		logger.LogInfo("Outbound port allowlist removed; FORWARD restored to accept-all.")
		return nil
	}

	// Remove the unconditional FORWARD ACCEPT; the SSL_OUTBOUND chain
	// takes its place. ESTABLISHED,RELATED ACCEPT above it stays put.
	forwardAllowRule := forwardAllowAllRule()
	fm.deleteRuleCompletely(forwardAllowRule)

	// Create the SSL_OUTBOUND chain (idempotent — flush if it already exists).
	if err := fm.runIPTables("-t", "filter", "-N", outboundChainName); err != nil {
		// Chain already exists from a previous run; flush it.
		fm.runIPTables("-t", "filter", "-F", outboundChainName)
	}

	// Populate the chain: one ACCEPT per (protocol, port), then a final DROP.
	for _, entry := range normalized {
		rule := []string{
			"-t", "filter", "-A", outboundChainName,
			"-p", entry.Protocol, "--dport", strconv.Itoa(entry.Port),
			"-m", "comment", "--comment", outboundAcceptRuleComment,
			"-j", "ACCEPT",
		}
		if err := fm.runIPTables(rule...); err != nil {
			fm.removeOutboundChain()
			return fmt.Errorf("failed to add outbound ACCEPT for %s/%d: %w", entry.Protocol, entry.Port, err)
		}
		fm.rules = append(fm.rules, strings.Join(rule, " "))
	}

	dropRule := []string{
		"-t", "filter", "-A", outboundChainName,
		"-m", "comment", "--comment", outboundDropRuleComment,
		"-j", "DROP",
	}
	if err := fm.runIPTables(dropRule...); err != nil {
		fm.removeOutboundChain()
		return fmt.Errorf("failed to add outbound DROP: %w", err)
	}
	fm.rules = append(fm.rules, strings.Join(dropRule, " "))

	// Wire FORWARD → SSL_OUTBOUND. Insert at position 2 so the jump sits
	// immediately after the ESTABLISHED,RELATED ACCEPT (position 1) and
	// before any other rule. This guarantees the port allowlist is always
	// consulted, even if a stale unconditional FORWARD ACCEPT exists.
	jumpRule := []string{
		"-t", "filter", "-I", "FORWARD", "2",
		"-m", "comment", "--comment", forwardOutboundRuleComment,
		"-j", outboundChainName,
	}
	if err := fm.runIPTables(jumpRule...); err != nil {
		fm.removeOutboundChain()
		return fmt.Errorf("failed to link FORWARD to %s: %w", outboundChainName, err)
	}
	fm.rules = append(fm.rules, strings.Join(jumpRule, " "))

	fm.outboundsActive = true
	logger.LogInfo(fmt.Sprintf("Outbound port allowlist active: %d entries (FORWARD → %s)", len(normalized), outboundChainName))
	return nil
}

// OutboundPortsActive reports whether the SSL_OUTBOUND chain is currently installed.
func (fm *FirewallManager) OutboundPortsActive() bool {
	return fm.outboundsActive
}

// removeOutboundChain flushes and deletes the SSL_OUTBOUND chain and the
// FORWARD jump that references it, leaving FORWARD in its prior state.
// It is safe to call when no outbound chain is present.
func (fm *FirewallManager) removeOutboundChain() error {
	if !fm.outboundsActive && !chainExists(outboundChainName) {
		return nil
	}

	fm.deleteRuleCompletely([]string{
		"-t", "filter", "-A", "FORWARD",
		"-m", "comment", "--comment", forwardOutboundRuleComment,
		"-j", outboundChainName,
	})
	fm.deleteRuleCompletely([]string{
		"-t", "filter", "-A", outboundChainName,
		"-m", "comment", "--comment", outboundAcceptRuleComment,
		"-j", "ACCEPT",
	})
	fm.deleteRuleCompletely([]string{
		"-t", "filter", "-A", outboundChainName,
		"-m", "comment", "--comment", outboundDropRuleComment,
		"-j", "DROP",
	})
	fm.runIPTables("-t", "filter", "-F", outboundChainName)
	fm.runIPTables("-t", "filter", "-X", outboundChainName)
	fm.outboundsActive = false
	return nil
}

func forwardAllowAllRule() []string {
	return []string{
		"-t", "filter", "-A", "FORWARD",
		"-m", "comment", "--comment", forwardAllowRuleComment,
		"-j", "ACCEPT",
	}
}

// forwardAllowAllInsertRule is the form used to (re)install the
// unconditional FORWARD ACCEPT at position 2 (right after the
// ESTABLISHED,RELATED rule). The delete form uses the -A shape; only
// the install form needs the explicit -I 2 to guarantee position.
func forwardAllowAllInsertRule() []string {
	return []string{
		"-t", "filter", "-I", "FORWARD", "2",
		"-m", "comment", "--comment", forwardAllowRuleComment,
		"-j", "ACCEPT",
	}
}

// normalizeOutboundEntries validates, de-duplicates, and sorts entries
// so the iptables chain has stable, predictable order.
func normalizeOutboundEntries(entries []OutboundPortEntry) []OutboundPortEntry {
	seen := make(map[string]struct{}, len(entries))
	out := make([]OutboundPortEntry, 0, len(entries))
	for _, e := range entries {
		proto := strings.ToLower(strings.TrimSpace(e.Protocol))
		if proto != "tcp" && proto != "udp" {
			continue
		}
		if e.Port < 1 || e.Port > 65535 {
			continue
		}
		key := proto + "/" + strconv.Itoa(e.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, OutboundPortEntry{Port: e.Port, Protocol: proto})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// chainExists checks whether an iptables chain exists in the filter table.
// Best effort: a non-zero exit from iptables is treated as "does not exist".
func chainExists(name string) bool {
	cmd := exec.Command("iptables", "-t", "filter", "-nL", name)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}
