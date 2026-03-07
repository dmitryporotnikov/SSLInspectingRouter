package tor

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestEnableDisable(t *testing.T) {
	manager, err := NewManager("127.0.0.1:9050")
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	manager.dial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return &stubConn{}, nil
	}

	status, err := manager.Enable()
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !status.Enabled {
		t.Fatalf("enabled = %v, want true", status.Enabled)
	}
	if !status.Reachable {
		t.Fatalf("reachable = %v, want true", status.Reachable)
	}

	status, err = manager.Disable()
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if status.Enabled {
		t.Fatalf("enabled after disable = %v, want false", status.Enabled)
	}
}

func TestEnableReturnsUnavailableWhenSOCKSIsDown(t *testing.T) {
	manager, err := NewManager("127.0.0.1:9050")
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	manager.dial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	status, err := manager.Enable()
	if err == nil {
		t.Fatalf("expected error, got nil (status=%+v)", status)
	}
	if !errors.Is(err, ErrSOCKSUnavailable) {
		t.Fatalf("error = %v, want ErrSOCKSUnavailable", err)
	}
	if status.Enabled {
		t.Fatalf("enabled = %v, want false", status.Enabled)
	}
	if status.Reachable {
		t.Fatalf("reachable = %v, want false", status.Reachable)
	}
}

func TestNewManagerRejectsInvalidAddress(t *testing.T) {
	_, err := NewManager("bad-address")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "invalid tor socks address") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type stubConn struct{}

func (c *stubConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *stubConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (c *stubConn) Close() error {
	return nil
}

func (c *stubConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *stubConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *stubConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *stubConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *stubConn) SetWriteDeadline(_ time.Time) error {
	return nil
}
