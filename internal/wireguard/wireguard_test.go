package wireguard

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

type fakeResult struct {
	output []byte
	err    error
}

type fakeRunner struct {
	mu        sync.Mutex
	responses map[string][]fakeResult
	calls     []string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		responses: make(map[string][]fakeResult),
		calls:     make([]string, 0),
	}
}

func (f *fakeRunner) enqueue(command string, results ...fakeResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[command] = append(f.responses[command], results...)
}

func (f *fakeRunner) run(name string, args ...string) ([]byte, error) {
	command := strings.TrimSpace(strings.Join(append([]string{name}, args...), " "))

	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, command)
	queue := f.responses[command]
	if len(queue) == 0 {
		return nil, fmt.Errorf("unexpected command: %s", command)
	}
	result := queue[0]
	f.responses[command] = queue[1:]
	return result.output, result.err
}

func TestSaveAndLoadConfig(t *testing.T) {
	dir := t.TempDir()
	manager, err := newManagerWithRunner(dir, nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	path, err := manager.SaveConfig("[Interface]\r\nPrivateKey = test-key")
	if err != nil {
		t.Fatalf("save config: %v", err)
	}

	wantPath := filepath.Join(dir, defaultConfigName)
	if path != wantPath {
		t.Fatalf("path = %q, want %q", path, wantPath)
	}

	loadedPath, loadedConfig, err := manager.LoadConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loadedPath != wantPath {
		t.Fatalf("loaded path = %q, want %q", loadedPath, wantPath)
	}
	if !strings.Contains(loadedConfig, "\nPrivateKey = test-key\n") {
		t.Fatalf("loaded config normalization missing expected newline formatting: %q", loadedConfig)
	}
}

func TestLoadConfigMissing(t *testing.T) {
	manager, err := newManagerWithRunner(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	_, _, err = manager.LoadConfig()
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestEnableDisableTunnel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(path, []byte("[Interface]\nPrivateKey = test\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	runner := newFakeRunner()
	runner.enqueue("ip link show dev wg0",
		fakeResult{err: &exec.ExitError{}}, // pre-enable: down
		fakeResult{},                       // post-enable status: up
		fakeResult{},                       // pre-disable status: up
		fakeResult{err: &exec.ExitError{}}, // post-disable status: down
	)
	runner.enqueue("wg-quick up "+path, fakeResult{})
	runner.enqueue("wg-quick down "+path, fakeResult{})

	manager, err := newManagerWithRunner(dir, runner.run)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	status, err := manager.Enable()
	if err != nil {
		t.Fatalf("enable tunnel: %v", err)
	}
	if !status.Enabled {
		t.Fatalf("enabled status = false, want true")
	}
	if status.Interface != "wg0" {
		t.Fatalf("interface = %q, want wg0", status.Interface)
	}

	status, err = manager.Disable()
	if err != nil {
		t.Fatalf("disable tunnel: %v", err)
	}
	if status.Enabled {
		t.Fatalf("enabled status after disable = true, want false")
	}

	wantCalls := []string{
		"ip link show dev wg0",
		"wg-quick up " + path,
		"ip link show dev wg0",
		"ip link show dev wg0",
		"wg-quick down " + path,
		"ip link show dev wg0",
	}
	if !reflect.DeepEqual(runner.calls, wantCalls) {
		t.Fatalf("calls = %v, want %v", runner.calls, wantCalls)
	}
}

func TestEnableRequiresConfig(t *testing.T) {
	manager, err := newManagerWithRunner(t.TempDir(), newFakeRunner().run)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	_, err = manager.Enable()
	if !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("expected ErrConfigNotFound, got %v", err)
	}
}

func TestDisableFallsBackToInterfaceWhenPathFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(path, []byte("[Interface]\nPrivateKey = test\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	runner := newFakeRunner()
	runner.enqueue("ip link show dev wg0",
		fakeResult{err: &exec.ExitError{}}, // pre-enable: down
		fakeResult{},                       // post-enable status: up
		fakeResult{},                       // pre-disable status: up
		fakeResult{err: &exec.ExitError{}}, // post-disable status: down
	)
	runner.enqueue("wg-quick up "+path, fakeResult{})
	runner.enqueue("wg-quick down "+path, fakeResult{err: &exec.ExitError{}})
	runner.enqueue("wg-quick down wg0", fakeResult{})

	manager, err := newManagerWithRunner(dir, runner.run)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	if _, err := manager.Enable(); err != nil {
		t.Fatalf("enable tunnel: %v", err)
	}
	status, err := manager.Disable()
	if err != nil {
		t.Fatalf("disable tunnel: %v", err)
	}
	if status.Enabled {
		t.Fatalf("enabled status after disable = true, want false")
	}

	wantCalls := []string{
		"ip link show dev wg0",
		"wg-quick up " + path,
		"ip link show dev wg0",
		"ip link show dev wg0",
		"wg-quick down " + path,
		"wg-quick down wg0",
		"ip link show dev wg0",
	}
	if !reflect.DeepEqual(runner.calls, wantCalls) {
		t.Fatalf("calls = %v, want %v", runner.calls, wantCalls)
	}
}
