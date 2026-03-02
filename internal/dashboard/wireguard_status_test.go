package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/wireguard"
)

type stubWireGuardRuntime struct {
	status        wireguard.Status
	statusErr     error
	saveConfigErr error
	enableErr     error
	disableErr    error

	saveConfigCalls int
	enableCalls     int
	disableCalls    int
	savedConfig     string
}

func (s *stubWireGuardRuntime) Status() (wireguard.Status, error) {
	if s.statusErr != nil {
		return wireguard.Status{}, s.statusErr
	}
	return s.status, nil
}

func (s *stubWireGuardRuntime) SaveConfig(raw string) (string, error) {
	s.saveConfigCalls++
	s.savedConfig = raw
	if s.saveConfigErr != nil {
		return "", s.saveConfigErr
	}
	s.status.ConfigPresent = true
	if s.status.ConfigPath == "" {
		s.status.ConfigPath = "wireguard/wg0.conf"
	}
	if s.status.Interface == "" {
		s.status.Interface = "wg0"
	}
	return s.status.ConfigPath, nil
}

func (s *stubWireGuardRuntime) Enable() (wireguard.Status, error) {
	s.enableCalls++
	if s.enableErr != nil {
		return wireguard.Status{}, s.enableErr
	}
	s.status.Enabled = true
	if s.status.Interface == "" {
		s.status.Interface = "wg0"
	}
	return s.status, nil
}

func (s *stubWireGuardRuntime) Disable() (wireguard.Status, error) {
	s.disableCalls++
	if s.disableErr != nil {
		return wireguard.Status{}, s.disableErr
	}
	s.status.Enabled = false
	return s.status, nil
}

type stubEgressRuntime struct {
	egress      string
	defaultIF   string
	setErr      error
	switchCalls []string
}

func (s *stubEgressRuntime) SetEgressInterface(iface string) error {
	s.switchCalls = append(s.switchCalls, iface)
	if s.setErr != nil {
		return s.setErr
	}
	s.egress = iface
	return nil
}

func (s *stubEgressRuntime) EgressInterface() string {
	return s.egress
}

func (s *stubEgressRuntime) DefaultEgressInterface() string {
	return s.defaultIF
}

func TestHandleStatusWireGuardEnableAndConfigSave(t *testing.T) {
	db := openDashboardTestDB(t)
	s := &Server{
		db: db,
		wireguardRuntime: &stubWireGuardRuntime{
			status: wireguard.Status{
				Interface: "wg0",
			},
		},
		egressRuntime: &stubEgressRuntime{
			egress:    "eth0",
			defaultIF: "eth0",
		},
		now: time.Now,
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/status", strings.NewReader(`{"wireguard_config":"[Interface]\nPrivateKey=test","wireguard_enabled":true}`))
	req = req.WithContext(context.WithValue(req.Context(), contextUserKey, &DashboardUser{
		ID:   1,
		Role: "admin",
	}))
	recorder := httptest.NewRecorder()

	s.handleStatus(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	wireguardStub := s.wireguardRuntime.(*stubWireGuardRuntime)
	if wireguardStub.saveConfigCalls != 1 {
		t.Fatalf("saveConfig calls = %d, want 1", wireguardStub.saveConfigCalls)
	}
	if wireguardStub.enableCalls != 1 {
		t.Fatalf("enable calls = %d, want 1", wireguardStub.enableCalls)
	}

	egressStub := s.egressRuntime.(*stubEgressRuntime)
	if len(egressStub.switchCalls) != 1 || egressStub.switchCalls[0] != "wg0" {
		t.Fatalf("egress switches = %v, want [wg0]", egressStub.switchCalls)
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if enabled, _ := payload["wireguard_enabled"].(bool); !enabled {
		t.Fatalf("wireguard_enabled = %v, want true", payload["wireguard_enabled"])
	}
	if got, _ := payload["egress_interface"].(string); got != "wg0" {
		t.Fatalf("egress_interface = %q, want %q", got, "wg0")
	}
}

func TestHandleStatusWireGuardEnableWithoutConfigReturnsBadRequest(t *testing.T) {
	db := openDashboardTestDB(t)
	s := &Server{
		db: db,
		wireguardRuntime: &stubWireGuardRuntime{
			enableErr: wireguard.ErrConfigNotFound,
		},
		now: time.Now,
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/status", strings.NewReader(`{"wireguard_enabled":true}`))
	req = req.WithContext(context.WithValue(req.Context(), contextUserKey, &DashboardUser{
		ID:   1,
		Role: "admin",
	}))
	recorder := httptest.NewRecorder()

	s.handleStatus(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}
