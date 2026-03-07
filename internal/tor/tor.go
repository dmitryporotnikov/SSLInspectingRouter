package tor

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultSOCKSAddress = "127.0.0.1:9050"
	socksEnvVar         = "SSLINSPECTINGROUTER_TOR_SOCKS_ADDR"
)

var ErrSOCKSUnavailable = errors.New("tor SOCKS endpoint is unavailable")

// Status describes the Tor routing runtime state.
type Status struct {
	Enabled      bool   `json:"enabled"`
	SOCKSAddress string `json:"socks_address"`
	Reachable    bool   `json:"reachable"`
	LastError    string `json:"last_error,omitempty"`
}

// Manager controls Tor SOCKS routing state for proxy egress.
type Manager struct {
	mu          sync.Mutex
	socksAddr   string
	dialTimeout time.Duration
	dial        dialFunc
	enabled     bool
	lastErr     string
}

// DefaultSOCKSAddress resolves the default Tor SOCKS endpoint.
func DefaultSOCKSAddress() string {
	if value := strings.TrimSpace(os.Getenv(socksEnvVar)); value != "" {
		return value
	}
	return defaultSOCKSAddress
}

// NewManager creates a Tor runtime manager.
func NewManager(socksAddr string) (*Manager, error) {
	normalized, err := normalizeSOCKSAddress(socksAddr)
	if err != nil {
		return nil, err
	}
	return &Manager{
		socksAddr:   normalized,
		dialTimeout: 4 * time.Second,
		dial:        defaultDial,
	}, nil
}

// SOCKSAddress returns the configured Tor SOCKS address.
func (m *Manager) SOCKSAddress() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.socksAddr
}

// Status returns current Tor runtime status.
func (m *Manager) Status() (Status, error) {
	if m == nil {
		return Status{}, errors.New("tor manager is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	reachable, err := canDialSOCKS(m.dial, m.socksAddr, m.dialTimeout)
	if err != nil {
		m.lastErr = err.Error()
	} else if reachable {
		m.lastErr = ""
	}

	return Status{
		Enabled:      m.enabled,
		SOCKSAddress: m.socksAddr,
		Reachable:    reachable,
		LastError:    m.lastErr,
	}, nil
}

// Enable turns on Tor routing after validating Tor SOCKS reachability.
func (m *Manager) Enable() (Status, error) {
	if m == nil {
		return Status{}, errors.New("tor manager is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	reachable, err := canDialSOCKS(m.dial, m.socksAddr, m.dialTimeout)
	if err != nil {
		m.lastErr = err.Error()
		return Status{
			Enabled:      m.enabled,
			SOCKSAddress: m.socksAddr,
			Reachable:    false,
			LastError:    m.lastErr,
		}, fmt.Errorf("%w at %s: %v", ErrSOCKSUnavailable, m.socksAddr, err)
	}

	m.enabled = true
	m.lastErr = ""
	return Status{
		Enabled:      true,
		SOCKSAddress: m.socksAddr,
		Reachable:    reachable,
	}, nil
}

// Disable turns off Tor routing.
func (m *Manager) Disable() (Status, error) {
	if m == nil {
		return Status{}, errors.New("tor manager is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.enabled = false
	return Status{
		Enabled:      false,
		SOCKSAddress: m.socksAddr,
		Reachable:    false,
		LastError:    m.lastErr,
	}, nil
}

func normalizeSOCKSAddress(raw string) (string, error) {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		candidate = DefaultSOCKSAddress()
	}

	host, port, err := net.SplitHostPort(candidate)
	if err != nil {
		return "", fmt.Errorf("invalid Tor SOCKS address %q", raw)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("invalid Tor SOCKS address %q", raw)
	}

	parsedPort, err := net.LookupPort("tcp", strings.TrimSpace(port))
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return "", fmt.Errorf("invalid Tor SOCKS port in %q", raw)
	}

	return net.JoinHostPort(host, port), nil
}

type dialFunc func(network, address string, timeout time.Duration) (net.Conn, error)

func defaultDial(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

func canDialSOCKS(dial dialFunc, addr string, timeout time.Duration) (bool, error) {
	if dial == nil {
		dial = defaultDial
	}
	conn, err := dial("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	_ = conn.Close()
	return true, nil
}
