package wireguard

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	defaultConfigName = "wg0.conf"
	dirEnvVar         = "SSLINSPECTINGROUTER_WIREGUARD_DIR"
)

var (
	ErrConfigNotFound = errors.New("wireguard config not found")
	ErrConfigEmpty    = errors.New("wireguard config cannot be empty")
)

// Status describes current WireGuard runtime state.
type Status struct {
	Enabled       bool
	Interface     string
	ConfigPath    string
	ConfigPresent bool
}

type cmdRunner func(name string, args ...string) ([]byte, error)

// Manager controls WireGuard tunnel state using wg-quick.
type Manager struct {
	dir       string
	preferred string

	mu                  sync.Mutex
	lastKnownIface      string
	lastKnownConfigPath string
	run                 cmdRunner
}

// DefaultDir resolves the runtime WireGuard config directory.
// Resolution order:
//  1. $SSLINSPECTINGROUTER_WIREGUARD_DIR
//  2. ./wireguard if it exists
//  3. <exeDir>/wireguard
func DefaultDir() string {
	if v := strings.TrimSpace(os.Getenv(dirEnvVar)); v != "" {
		return v
	}

	if cwd, err := os.Getwd(); err == nil {
		cwdDir := filepath.Join(cwd, "wireguard")
		if fi, err := os.Stat(cwdDir); err == nil && fi.IsDir() {
			return cwdDir
		}
	}

	exePath, err := os.Executable()
	if err != nil {
		return "wireguard"
	}
	return filepath.Join(filepath.Dir(exePath), "wireguard")
}

func defaultRunner(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

// NewManager creates a WireGuard runtime manager.
func NewManager(dir string) (*Manager, error) {
	return newManagerWithRunner(dir, defaultRunner)
}

func newManagerWithRunner(dir string, run cmdRunner) (*Manager, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		dir = DefaultDir()
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create wireguard directory: %w", err)
	}

	if run == nil {
		run = defaultRunner
	}

	return &Manager{
		dir:       dir,
		preferred: filepath.Join(dir, defaultConfigName),
		run:       run,
	}, nil
}

// Directory returns WireGuard config directory.
func (m *Manager) Directory() string {
	if m == nil {
		return ""
	}
	return m.dir
}

// SaveConfig persists WireGuard config content into wireguard/wg0.conf.
func (m *Manager) SaveConfig(raw string) (string, error) {
	if m == nil {
		return "", errors.New("wireguard manager is nil")
	}
	if strings.TrimSpace(raw) == "" {
		return "", ErrConfigEmpty
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	content := strings.ReplaceAll(raw, "\r\n", "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if err := os.WriteFile(m.preferred, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("write wireguard config: %w", err)
	}
	return m.preferred, nil
}

// LoadConfig returns currently selected WireGuard config content.
func (m *Manager) LoadConfig() (string, string, error) {
	if m == nil {
		return "", "", errors.New("wireguard manager is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	path, present, err := m.resolveConfigPathLocked()
	if err != nil {
		return "", "", err
	}
	if !present {
		return "", "", os.ErrNotExist
	}

	safePath, err := safeWireGuardConfigPath(m.dir, path)
	if err != nil {
		return "", "", err
	}
	data, err := os.ReadFile(safePath)
	if err != nil {
		return "", "", fmt.Errorf("read wireguard config: %w", err)
	}
	return safePath, string(data), nil
}

// Status returns current tunnel and config state.
func (m *Manager) Status() (Status, error) {
	if m == nil {
		return Status{}, errors.New("wireguard manager is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

// Enable brings up the configured tunnel using wg-quick.
func (m *Manager) Enable() (Status, error) {
	if m == nil {
		return Status{}, errors.New("wireguard manager is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	path, present, err := m.resolveConfigPathLocked()
	if err != nil {
		return Status{}, err
	}
	if !present {
		return Status{}, ErrConfigNotFound
	}

	iface := interfaceFromConfigPath(path)
	if iface == "" {
		return Status{}, fmt.Errorf("invalid wireguard config filename: %s", filepath.Base(path))
	}

	enabled, err := m.interfaceExistsLocked(iface)
	if err != nil {
		return Status{}, err
	}
	if enabled {
		m.lastKnownIface = iface
		m.lastKnownConfigPath = path
		return m.statusLocked()
	}

	if _, err := m.run("wg-quick", "up", path); err != nil {
		return Status{}, fmt.Errorf("wg-quick up %s failed: %w", path, err)
	}

	m.lastKnownIface = iface
	m.lastKnownConfigPath = path
	status, err := m.statusLocked()
	if err != nil {
		return status, err
	}
	if !status.Enabled {
		return status, errors.New("wireguard tunnel did not come up")
	}
	return status, nil
}

// Disable tears down the active tunnel using wg-quick.
func (m *Manager) Disable() (Status, error) {
	if m == nil {
		return Status{}, errors.New("wireguard manager is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	status, err := m.statusLocked()
	if err != nil {
		return status, err
	}
	if !status.Enabled {
		return status, nil
	}

	iface := strings.TrimSpace(status.Interface)
	if iface == "" {
		iface = strings.TrimSpace(m.lastKnownIface)
	}

	target := strings.TrimSpace(status.ConfigPath)
	if target == "" {
		target = strings.TrimSpace(m.lastKnownConfigPath)
	}
	if target == "" {
		target = iface
	}
	if target == "" {
		return status, errors.New("wireguard interface/config is unknown")
	}

	if _, err := m.run("wg-quick", "down", target); err != nil {
		// Fallback for environments that only accept interface names on down.
		if iface != "" && target != iface {
			if _, fallbackErr := m.run("wg-quick", "down", iface); fallbackErr == nil {
				target = iface
				err = nil
			}
		}
		if err != nil {
			return Status{}, fmt.Errorf("wg-quick down %s failed: %w", target, err)
		}
	}

	next, err := m.statusLocked()
	if err != nil {
		return next, err
	}
	if next.Enabled {
		return next, errors.New("wireguard tunnel is still up")
	}
	return next, nil
}

func (m *Manager) statusLocked() (Status, error) {
	path, present, err := m.resolveConfigPathLocked()
	if err != nil {
		return Status{}, err
	}

	status := Status{
		ConfigPresent: present,
		ConfigPath:    path,
	}

	iface := ""
	if present {
		iface = interfaceFromConfigPath(path)
	}
	if iface == "" {
		iface = m.lastKnownIface
	}
	status.Interface = iface

	if iface == "" {
		return status, nil
	}

	up, err := m.interfaceExistsLocked(iface)
	if err != nil {
		return status, err
	}
	status.Enabled = up
	if up {
		m.lastKnownIface = iface
	}
	return status, nil
}

func (m *Manager) resolveConfigPathLocked() (string, bool, error) {
	preferredPath, err := safeWireGuardConfigPath(m.dir, m.preferred)
	if err != nil {
		return "", false, err
	}
	if fileExists(preferredPath) {
		return preferredPath, true, nil
	}

	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("read wireguard directory: %w", err)
	}

	candidates := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.EqualFold(filepath.Ext(name), ".conf") {
			continue
		}
		path, err := safeWireGuardConfigPath(m.dir, name)
		if err != nil {
			continue
		}
		candidates = append(candidates, path)
	}
	if len(candidates) == 0 {
		return "", false, nil
	}

	sort.Strings(candidates)
	return candidates[0], true, nil
}

func (m *Manager) interfaceExistsLocked(iface string) (bool, error) {
	if strings.TrimSpace(iface) == "" {
		return false, nil
	}
	_, err := m.run("ip", "link", "show", "dev", iface)
	if err == nil {
		return true, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}

	return false, fmt.Errorf("check wireguard interface %s: %w", iface, err)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func interfaceFromConfigPath(path string) string {
	base := filepath.Base(strings.TrimSpace(path))
	if base == "" {
		return ""
	}
	if !strings.EqualFold(filepath.Ext(base), ".conf") {
		return ""
	}
	iface := strings.TrimSuffix(base, filepath.Ext(base))
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return ""
	}
	return iface
}

func safeWireGuardConfigPath(dir, candidate string) (string, error) {
	trimmedDir := strings.TrimSpace(dir)
	if trimmedDir == "" {
		return "", errors.New("wireguard directory is empty")
	}
	baseDir := filepath.Clean(trimmedDir)

	name := strings.TrimSpace(filepath.Base(candidate))
	if name == "" || name == "." {
		return "", errors.New("wireguard config filename is empty")
	}
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("invalid wireguard config filename %q", candidate)
	}
	if !strings.EqualFold(filepath.Ext(name), ".conf") {
		return "", fmt.Errorf("invalid wireguard config extension %q", candidate)
	}

	path := filepath.Join(baseDir, name)
	rel, err := filepath.Rel(baseDir, path)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("wireguard config escapes configured directory: %q", candidate)
	}
	return path, nil
}
