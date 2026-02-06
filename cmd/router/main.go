package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/banner"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/blocklist"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/cert"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/dashboard"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/dnsproxy"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/firewall"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/pcap"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/proxy"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/rewrites"
)

const (
	HTTP_PROXY_PORT  = 8080
	HTTPS_PROXY_PORT = 8443
)

func main() {
	dropFlag := flag.String("drop", "", "comma-separated FQDNs to drop (DNS/HTTP/HTTPS)")
	bypassFlag := flag.String("bypass", "", "comma-separated FQDNs to bypass inspection (HTTP/HTTPS)")
	inspectOnlyFlag := flag.String("inspectonly", "", "comma-separated IPs to inspect (if set, only these IPs are intercepted)")
	newCACert := flag.Bool("newcacert", false, "generate a new CA certificate and key")
	allowQUIC := flag.Bool("allowquic", false, "allow QUIC (UDP/443); QUIC is blocked by default")
	portsFlag := flag.String("ports", "", "comma-separated additional TLS destination ports to inspect (e.g. 8443,9443)")
	truncateLog := flag.Bool("truncatelog", false, "store truncated request/response bodies in logs")
	wipeDB := flag.Bool("wipedb", false, "delete the traffic database before startup")
	webFlag := flag.String("web", "", "address to serve web dashboard (e.g. :3000)")
	pcapFlag := flag.String("pcap", "", "path to write PCAP file of decrypted traffic")
	flag.Parse()

	logger.SetConsoleRequestLogging(*webFlag == "")
	logger.SetLogTruncation(*truncateLog)
	if *wipeDB {
		if err := logger.WipeLogDB(); err != nil {
			logger.LogError(fmt.Sprintf("Failed to wipe log database: %v", err))
			os.Exit(1)
		}
	}
	dropList := blocklist.ParseDropList(*dropFlag)
	blockList := blocklist.NewBlockList(dropList)
	bypassList := blocklist.NewBlockList(blocklist.ParseDropList(*bypassFlag))
	inspectOnlyList := blocklist.ParseDropList(*inspectOnlyFlag) // Reusing ParseDropList as it splits comma-separated strings
	additionalTLSPorts, err := parseAdditionalPorts(*portsFlag)
	if err != nil {
		logger.LogError(fmt.Sprintf("Invalid -ports value: %v", err))
		os.Exit(1)
	}

	banner.PrintBanner()

	if os.Geteuid() != 0 {
		logger.LogError("Root privileges required for iptables configuration and packet interception.")
		os.Exit(1)
	}

	logger.LogInfo("Starting SSL-Inspecting Transparent Router (Ubuntu 24.04)...")

	if err := logger.InitLogger(); err != nil {
		logger.LogError(fmt.Sprintf("Failed to initialize logger: %v", err))
		os.Exit(1)
	}
	defer logger.CloseLogger()

	if *pcapFlag != "" {
		if err := pcap.Init(*pcapFlag); err != nil {
			logger.LogError(fmt.Sprintf("Failed to initialize PCAP writer: %v", err))
		} else {
			logger.LogInfo(fmt.Sprintf("PCAP capture enabled: writing to %s", *pcapFlag))
			defer pcap.Close()
		}
	}

	logger.LogInfo("Initializing services...")

	certManager, err := cert.NewCertManager(*newCACert)
	if err != nil {
		logger.LogError(fmt.Sprintf("Certificate manager initialization failed: %v", err))
		os.Exit(1)
	}

	firewallManager := firewall.NewFirewallManager(HTTP_PROXY_PORT, HTTPS_PROXY_PORT)
	if len(additionalTLSPorts) > 0 {
		firewallManager.EnableAdditionalTLSPorts(additionalTLSPorts)
	}
	if !*allowQUIC {
		firewallManager.EnableQUICBlock()
		logger.LogInfo("QUIC blocking enabled.")
	}
	if len(inspectOnlyList) > 0 {
		firewallManager.EnableInspectOnly(inspectOnlyList)
	}

	var dnsProxy *dnsproxy.DNSProxy
	if blockList != nil && blockList.Count() > 0 {
		dnsProxy, err = dnsproxy.NewDNSProxy(dnsproxy.DNS_PROXY_PORT, blockList)
		if err != nil {
			logger.LogError(fmt.Sprintf("DNS proxy initialization failed: %v", err))
			os.Exit(1)
		}
		if err := dnsProxy.Start(); err != nil {
			logger.LogError(fmt.Sprintf("DNS proxy start failed: %v", err))
			os.Exit(1)
		}
		firewallManager.EnableDNSRedirect(dnsproxy.DNS_PROXY_PORT)

		// Configure network-layer blocking for IPs
		ips := blockList.GetIPs()
		cidrs := blockList.GetCIDRs()
		allBlocked := append(ips, cidrs...)
		if len(allBlocked) > 0 {
			firewallManager.EnableIPBlocking(allBlocked)
		}

		logger.LogInfo(fmt.Sprintf("DNS drop list enabled (%d entries)", blockList.Count()))
	}

	if err := firewallManager.Setup(); err != nil {
		logger.LogError(fmt.Sprintf("Firewall rules setup failed: %v", err))
		os.Exit(1)
	}

	// Ensure cleaner shutdown of firewall rules on interrupt
	setupCleanupHandler(firewallManager)

	rewriter := rewrites.NewEngine(rewrites.DefaultDir())
	if stats, err := rewriter.LoadNow(); err != nil {
		logger.LogError(fmt.Sprintf("Rewrite rules load failed: %v", err))
	} else if stats.Enabled > 0 {
		logger.LogInfo(fmt.Sprintf("Response tampering enabled: %d/%d rule(s) enabled from %s", stats.Enabled, stats.Total, rewriter.Dir()))
	} else if stats.Total > 0 {
		logger.LogInfo(fmt.Sprintf("Response tampering: %d rule(s) loaded but none enabled (dir: %s)", stats.Total, rewriter.Dir()))
	} else {
		logger.LogInfo(fmt.Sprintf("Response tampering: no rules found in %s", rewriter.Dir()))
	}

	httpHandler := proxy.NewHTTPHandler(blockList, bypassList, rewriter)
	httpsHandler := proxy.NewHTTPSHandler(certManager, blockList, bypassList, rewriter)

	if *webFlag != "" {
		go func() {
			if err := dashboard.Start(logger.DB, *webFlag, httpsHandler, rewriter); err != nil {
				logger.LogError(fmt.Sprintf("Dashboard server failed: %v", err))
			}
		}()
	}

	logger.LogInfo("Router is active.")
	logger.LogInfo(fmt.Sprintf("HTTP  -> :%d", HTTP_PROXY_PORT))
	logger.LogInfo(fmt.Sprintf("HTTPS -> :%d", HTTPS_PROXY_PORT))
	if len(additionalTLSPorts) > 0 {
		logger.LogInfo(fmt.Sprintf("Extra TLS ports intercepted: %s", portsToString(additionalTLSPorts)))
	}
	if dnsProxy != nil {
		logger.LogInfo(fmt.Sprintf("DNS   -> :%d (drop enabled)", dnsproxy.DNS_PROXY_PORT))
	}
	if bypassList != nil {
		logger.LogInfo(fmt.Sprintf("Bypass list enabled (%d entries)", bypassList.Count()))
	}
	logger.LogInfo("CA Path: ca-cert.pem")
	logger.LogInfo("Logs: SQLite traffic.db in Logs directory")
	logger.LogInfo("Install ca-cert.pem to system trust store to prevent browser warnings.")
	logger.LogInfo("Press Ctrl+C to stop.")

	go func() {
		logger.LogInfo(fmt.Sprintf("HTTP proxy listening on :%d", HTTP_PROXY_PORT))
		httpServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", HTTP_PROXY_PORT),
			Handler: httpHandler,
		}
		if err := httpServer.ListenAndServe(); err != nil {
			logger.LogError(fmt.Sprintf("HTTP proxy error: %v", err))
		}
	}()

	go func() {
		logger.LogInfo(fmt.Sprintf("HTTPS proxy listening on :%d", HTTPS_PROXY_PORT))
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", HTTPS_PROXY_PORT))
		if err != nil {
			logger.LogError(fmt.Sprintf("HTTPS listener failed: %v", err))
			return
		}
		defer ln.Close()

		for {
			conn, err := ln.Accept()
			if err != nil {
				logger.LogError(fmt.Sprintf("Connection accept error: %v", err))
				continue
			}
			go httpsHandler.HandleConnection(conn)
		}
	}()

	select {}
}

// setupCleanupHandler ensures iptables rules are flushed on SIGINT/SIGTERM.
func setupCleanupHandler(firewallManager *firewall.FirewallManager) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		logger.LogInfo("Shutting down...")

		if err := firewallManager.Cleanup(); err != nil {
			logger.LogError(fmt.Sprintf("Firewall cleanup failed: %v", err))
		}

		logger.CloseLogger()
		logger.LogInfo("Clean shutdown complete.")
		os.Exit(0)
	}()
}

func parseAdditionalPorts(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	seen := make(map[int]struct{}, len(parts))
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", part)
		}
		// 80 and 443 are already intercepted by default.
		if port == 80 || port == 443 {
			continue
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}

	sort.Ints(ports)
	return ports, nil
}

func portsToString(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}
	return strings.Join(values, ",")
}
