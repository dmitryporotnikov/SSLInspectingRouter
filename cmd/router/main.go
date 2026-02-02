package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/banner"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/blocklist"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/cert"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/dashboard"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/dnsproxy"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/firewall"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/proxy"
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
	truncateLog := flag.Bool("truncatelog", false, "store truncated request/response bodies in logs")
	wipeDB := flag.Bool("wipedb", false, "delete the traffic database before startup")
	webFlag := flag.String("web", "", "address to serve web dashboard (e.g. :3000)")
	flag.Parse()

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

	if *webFlag != "" {
		go func() {
			if err := dashboard.Start(logger.DB, *webFlag); err != nil {
				logger.LogError(fmt.Sprintf("Dashboard server failed: %v", err))
			}
		}()
	}

	logger.LogInfo("Initializing services...")

	certManager, err := cert.NewCertManager(*newCACert)
	if err != nil {
		logger.LogError(fmt.Sprintf("Certificate manager initialization failed: %v", err))
		os.Exit(1)
	}

	firewallManager := firewall.NewFirewallManager(HTTP_PROXY_PORT, HTTPS_PROXY_PORT)
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

	httpHandler := proxy.NewHTTPHandler(blockList, bypassList)
	httpsHandler := proxy.NewHTTPSHandler(certManager, blockList, bypassList)

	logger.LogInfo("Router is active.")
	logger.LogInfo(fmt.Sprintf("HTTP  -> :%d", HTTP_PROXY_PORT))
	logger.LogInfo(fmt.Sprintf("HTTPS -> :%d", HTTPS_PROXY_PORT))
	if dnsProxy != nil {
		logger.LogInfo(fmt.Sprintf("DNS   -> :%d (drop enabled)", dnsproxy.DNS_PROXY_PORT))
	}
	if bypassList != nil {
		logger.LogInfo(fmt.Sprintf("Bypass list enabled (%d entries)", bypassList.Count()))
	}
	logger.LogInfo("CA Path: ca-cert.pem")
	logger.LogInfo("Logs: logs/http.log, logs/https.log")
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
