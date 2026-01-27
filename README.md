# SSL Inspecting Router

This repository holds a transparent interception proxy written in Go that targets HTTP and HTTPS traffic on Linux systems. It operates by manipulating the kernel packet filtering framework to divert network flows intended for standard web ports into local userspace listeners.

The app relies on `iptables` within the `nat` table. The application injects a custom chain named `SSLPROXY` linked to the `PREROUTING` hook. This configuration intercepts TCP packets destined for port 80 and redirects them to the local HTTP handler running on port 8080. Traffic targeting port 443 is redirected to the local HTTPS handler on port 8443. The `FirewallManager` struct in `firewall.go` orchestrates these rules and ensures the environment is cleanly restored upon process termination.

Packet handling in userspace is managed by standard Go `net/http` libraries. For encrypted traffic, the proxy uses a dynamic certificate generation. It functions as a generic Certificate Authority. To successfully negotiate TLS handshakes without client rejection, the generated `ca-cert.pem` must be actively trusted by the client device. The `cert.go` file contains the logic for minting these per-host certificates on demand.

## Build and Initialization

The included `setup.sh` script automates the environmental prerequisites. It modifies kernel parameters to enable IPv4 forwarding via `sysctl` and verifies the presence of the Go compiler and netfilter userspace tools.

```bash
sudo ./setup.sh
```

If the build succeeds, a binary named `sslrouter` is produced in the project root.

## Execution

Privileged access is strictly required for both network stack manipulation and binding to the interception logic. Execute the binary as root user.

```bash
sudo ./sslrouter
```

Runtime logging provides immediate feedback on intercepted connections. The application listens for `SIGINT` and `SIGTERM` signals. Receiving these signals triggers a graceful shutdown sequence that explicitly flushes the `SSLPROXY` chain from `iptables` and removes the redirection rules, preventing network blackholing after the process exits.
