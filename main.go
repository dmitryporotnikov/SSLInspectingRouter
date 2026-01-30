package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

const (
	HTTP_PROXY_PORT  = 8080
	HTTPS_PROXY_PORT = 8443
)

func main() {
	dropFlag := flag.String("drop", "", "comma-separated FQDNs to drop (DNS/HTTP/HTTPS)")
	newCACert := flag.Bool("newcacert", false, "generate a new CA certificate and key")
	allowQUIC := flag.Bool("allowquic", false, "allow QUIC (UDP/443); QUIC is blocked by default")
	truncateLog := flag.Bool("truncatelog", false, "store truncated request/response bodies in logs")
	wipeDB := flag.Bool("wipedb", false, "delete the traffic database before startup")
	flag.Parse()

	SetLogTruncation(*truncateLog)
	if *wipeDB {
		if err := WipeLogDB(); err != nil {
			LogError(fmt.Sprintf("Failed to wipe log database: %v", err))
			os.Exit(1)
		}
	}
	dropList := parseDropList(*dropFlag)
	blockList := NewBlockList(dropList)

	PrintBanner()

	if os.Geteuid() != 0 {
		LogError("Root privileges required for iptables configuration and packet interception.")
		os.Exit(1)
	}

	LogInfo("Starting SSL-Inspecting Transparent Router (Ubuntu 24.04)...")

	if err := InitLogger(); err != nil {
		LogError(fmt.Sprintf("Failed to initialize logger: %v", err))
		os.Exit(1)
	}
	defer CloseLogger()

	LogInfo("Initializing services...")

	certManager, err := NewCertManager(*newCACert)
	if err != nil {
		LogError(fmt.Sprintf("Certificate manager initialization failed: %v", err))
		os.Exit(1)
	}

	firewallManager := NewFirewallManager(HTTP_PROXY_PORT, HTTPS_PROXY_PORT)
	if !*allowQUIC {
		firewallManager.EnableQUICBlock()
		LogInfo("QUIC blocking enabled.")
	}

	var dnsProxy *DNSProxy
	if blockList != nil && blockList.Count() > 0 {
		dnsProxy, err = NewDNSProxy(DNS_PROXY_PORT, blockList)
		if err != nil {
			LogError(fmt.Sprintf("DNS proxy initialization failed: %v", err))
			os.Exit(1)
		}
		if err := dnsProxy.Start(); err != nil {
			LogError(fmt.Sprintf("DNS proxy start failed: %v", err))
			os.Exit(1)
		}
		firewallManager.EnableDNSRedirect(DNS_PROXY_PORT)
		LogInfo(fmt.Sprintf("DNS drop list enabled (%d entries)", blockList.Count()))
	}

	if err := firewallManager.Setup(); err != nil {
		LogError(fmt.Sprintf("Firewall rules setup failed: %v", err))
		os.Exit(1)
	}

	// Ensure cleaner shutdown of firewall rules on interrupt
	setupCleanupHandler(firewallManager)

	httpHandler := NewHTTPHandler(blockList)
	httpsHandler := NewHTTPSHandler(certManager, blockList)

	LogInfo("Router is active.")
	LogInfo(fmt.Sprintf("HTTP  -> :%d", HTTP_PROXY_PORT))
	LogInfo(fmt.Sprintf("HTTPS -> :%d", HTTPS_PROXY_PORT))
	if dnsProxy != nil {
		LogInfo(fmt.Sprintf("DNS   -> :%d (drop enabled)", DNS_PROXY_PORT))
	}
	LogInfo("CA Path: ca-cert.pem")
	LogInfo("Logs: logs/http.log, logs/https.log")
	LogInfo("Install ca-cert.pem to system trust store to prevent browser warnings.")
	LogInfo("Press Ctrl+C to stop.")

	go func() {
		LogInfo(fmt.Sprintf("HTTP proxy listening on :%d", HTTP_PROXY_PORT))
		httpServer := &http.Server{
			Addr:    fmt.Sprintf(":%d", HTTP_PROXY_PORT),
			Handler: httpHandler,
		}
		if err := httpServer.ListenAndServe(); err != nil {
			LogError(fmt.Sprintf("HTTP proxy error: %v", err))
		}
	}()

	go func() {
		LogInfo(fmt.Sprintf("HTTPS proxy listening on :%d", HTTPS_PROXY_PORT))
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", HTTPS_PROXY_PORT))
		if err != nil {
			LogError(fmt.Sprintf("HTTPS listener failed: %v", err))
			return
		}
		defer ln.Close()

		for {
			conn, err := ln.Accept()
			if err != nil {
				LogError(fmt.Sprintf("Connection accept error: %v", err))
				continue
			}
			go httpsHandler.HandleConnection(conn)
		}
	}()

	select {}
}

// setupCleanupHandler ensures iptables rules are flushed on SIGINT/SIGTERM.
func setupCleanupHandler(firewallManager *FirewallManager) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		LogInfo("Shutting down...")

		if err := firewallManager.Cleanup(); err != nil {
			LogError(fmt.Sprintf("Firewall cleanup failed: %v", err))
		}

		CloseLogger()
		LogInfo("Clean shutdown complete.")
		os.Exit(0)
	}()
}
