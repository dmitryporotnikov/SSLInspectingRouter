package firewall

import (
	"sync"
	"testing"
	"time"
)

// newTestManager returns a Manager with an in-memory SQLite database
// for use in unit tests. It does not require root or any host state.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	db := openTestDB(t)
	m := &Manager{
		rules:         []Rule{},
		nextID:        1,
		outboundPorts: append([]OutboundPortEntry(nil), DefaultOutboundPorts...),
	}
	if err := m.Initialize(db); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	return m
}

func TestOutboundPortsPersistAcrossInitialize(t *testing.T) {
	db := openTestDB(t)
	m := &Manager{rules: []Rule{}, nextID: 1}
	if err := m.Initialize(db); err != nil {
		t.Fatalf("first Initialize: %v", err)
	}

	custom := []OutboundPortEntry{
		{Port: 22, Protocol: "tcp"},
		{Port: 53, Protocol: "udp"},
	}
	m.SetOutboundPorts(custom)

	// The DB write happens on a goroutine. Poll the stored value until it
	// appears (or fail after a generous timeout).
	waitForStoredOutboundPorts(t, db, 5*time.Second, func(entries []OutboundPortEntry) bool {
		return len(entries) == 2 && entries[0].Port == 22 && entries[1].Port == 53
	})

	// Re-initialize from the same DB and confirm the list round-trips.
	m2 := &Manager{rules: []Rule{}, nextID: 1}
	if err := m2.Initialize(db); err != nil {
		t.Fatalf("second Initialize: %v", err)
	}
	if got := m2.GetOutboundPorts(); len(got) != 2 || got[0].Port != 22 || got[1].Port != 53 {
		t.Fatalf("expected round-trip of custom list, got %+v", got)
	}
}

func TestSetOutboundPortsNormalizesAndDeduplicates(t *testing.T) {
	m := newTestManager(t)

	mixed := []OutboundPortEntry{
		{Port: 80, Protocol: "tcp"},
		{Port: 80, Protocol: "tcp"},    // exact duplicate
		{Port: 443, Protocol: "TCP"},   // uppercased protocol
		{Port: 0, Protocol: "tcp"},     // invalid port
		{Port: 70000, Protocol: "tcp"}, // out of range
		{Port: 22, Protocol: "icmp"},   // invalid protocol
		{Port: 53, Protocol: "udp"},
	}
	m.SetOutboundPorts(mixed)

	got := m.GetOutboundPorts()
	want := []OutboundPortEntry{
		{Port: 80, Protocol: "tcp"},
		{Port: 443, Protocol: "tcp"},
		{Port: 53, Protocol: "udp"},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d entries, got %d: %+v", len(want), len(got), got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("entry %d: expected %+v, got %+v", i, want[i], got[i])
		}
	}
}

func TestSetOutboundPortsFallsBackToDefaultsWhenEmpty(t *testing.T) {
	m := newTestManager(t)

	m.SetOutboundPorts([]OutboundPortEntry{
		{Port: 70000, Protocol: "tcp"}, // all invalid
	})

	got := m.GetOutboundPorts()
	if len(got) != len(DefaultOutboundPorts) {
		t.Fatalf("expected fallback to defaults (%d), got %+v", len(DefaultOutboundPorts), got)
	}
}

func TestInitializeSkipsLegacySeededBlockAllRule(t *testing.T) {
	db := openTestDB(t)
	m := &Manager{rules: []Rule{}, nextID: 1, db: db}
	if err := m.ensureSchema(); err != nil {
		t.Fatalf("ensureSchema failed: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := db.Exec(`
		INSERT INTO firewall_rules (id, priority, enabled, action, block_mode, match_json, created_at, updated_at)
		VALUES (0, -1000, 1, ?, ?, ?, ?, ?)
	`, ActionBlock, BlockModeSilentDrop, mustMarshalJSON(RuleMatch{}), now, now)
	if err != nil {
		t.Fatalf("insert legacy rule: %v", err)
	}

	if err := m.Initialize(db); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if got := m.GetRules(); len(got) != 0 {
		t.Fatalf("legacy seeded block-all rule loaded: %+v", got)
	}
}

func TestSetEnabledDoesNotCreateCatchAllBlockRule(t *testing.T) {
	m := newTestManager(t)

	m.SetEnabled(true)

	if got := m.GetRules(); len(got) != 0 {
		t.Fatalf("SetEnabled created rules: %+v", got)
	}
}

func TestMatchTrafficNoRuleDoesNotMatch(t *testing.T) {
	m := newTestManager(t)
	m.SetEnabled(true)

	if action, blockMode, matched := m.MatchTraffic("example.com", "10.0.0.2"); matched {
		t.Fatalf("MatchTraffic no-rule = (%q, %q, %v), want no match", action, blockMode, matched)
	}
}

func TestMatchTrafficExplicitBlockBlocksTraffic(t *testing.T) {
	m := newTestManager(t)
	m.AddRule(Rule{Enabled: true, Action: ActionBlock, BlockMode: BlockModeDisplayPage, Priority: 10, Match: RuleMatch{Host: "example.com"}})
	m.SetEnabled(true)

	action, blockMode, matched := m.MatchTraffic("example.com", "10.0.0.2")
	if !matched || action != ActionBlock || blockMode != BlockModeDisplayPage {
		t.Fatalf("MatchTraffic explicit block = (%q, %q, %v), want block display match", action, blockMode, matched)
	}
}

func TestMatchTrafficExplicitInspectAllowsTraffic(t *testing.T) {
	m := newTestManager(t)
	m.AddRule(Rule{Enabled: true, Action: ActionInspect, Priority: 10, Match: RuleMatch{Host: "example.com"}})
	m.SetEnabled(true)

	action, _, matched := m.MatchTraffic("example.com", "10.0.0.2")
	if !matched || action != ActionInspect {
		t.Fatalf("MatchTraffic explicit inspect = (%q, %v), want inspect match", action, matched)
	}
}

func TestSetEnabledFiresOnEnabledChangeCallback(t *testing.T) {
	m := newTestManager(t)

	var (
		mu        sync.Mutex
		calls     int
		lastOn    bool
		lastPorts []OutboundPortEntry
	)
	m.SetOnEnabledChange(func(enabled bool, entries []OutboundPortEntry) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		lastOn = enabled
		lastPorts = append([]OutboundPortEntry(nil), entries...)
	})

	m.SetEnabled(true)

	// Wait briefly for the async callback.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := calls
		mu.Unlock()
		if got > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls == 0 {
		t.Fatalf("expected at least one OnEnabledChange invocation")
	}
	if !lastOn {
		t.Fatalf("expected last enabled state to be true, got false")
	}
	if len(lastPorts) != len(DefaultOutboundPorts) {
		t.Fatalf("expected callback to receive default ports, got %+v", lastPorts)
	}
}

func TestIsOutboundPortAllowedTracksFirewallState(t *testing.T) {
	m := newTestManager(t)
	m.SetOutboundPorts([]OutboundPortEntry{{Port: 80, Protocol: "tcp"}})

	if !m.IsOutboundPortAllowed("tcp", 443) {
		t.Fatal("disabled firewall should allow outbound port")
	}
	m.SetEnabled(true)
	if !m.IsOutboundPortAllowed("tcp", 80) {
		t.Fatal("enabled firewall should allow configured outbound port")
	}
	if m.IsOutboundPortAllowed("tcp", 443) {
		t.Fatal("enabled firewall should reject missing outbound port")
	}
}

func TestSetOutboundPortsAppliesCallbacksInOrder(t *testing.T) {
	m := newTestManager(t)
	m.SetEnabled(true)

	var calls int
	var lastPorts []OutboundPortEntry
	m.SetOnEnabledChange(func(enabled bool, entries []OutboundPortEntry) {
		calls++
		lastPorts = append([]OutboundPortEntry(nil), entries...)
	})

	m.SetOutboundPorts([]OutboundPortEntry{{Port: 80, Protocol: "tcp"}})
	m.SetOutboundPorts([]OutboundPortEntry{{Port: 443, Protocol: "tcp"}})

	if calls != 2 {
		t.Fatalf("callback calls = %d, want 2", calls)
	}
	if len(lastPorts) != 1 || lastPorts[0].Port != 443 {
		t.Fatalf("expected last callback to receive latest port list, got %+v", lastPorts)
	}
}

func TestMatchHostRegex(t *testing.T) {
	cases := []struct {
		host, pattern string
		want          bool
	}{
		{"example.com", `^example\.com$`, true},
		{"api.example.com", `\.example\.com$`, true},
		{"example.org", `^example\.com$`, false},
		{"example.com", `[invalid`, false},
		{"", `.*`, false},
		{"example.com", ``, false},
	}
	for _, c := range cases {
		if got := matchHostRegex(c.host, c.pattern); got != c.want {
			t.Errorf("matchHostRegex(%q, %q) = %v, want %v", c.host, c.pattern, got, c.want)
		}
	}
}

func TestMatchCIDR(t *testing.T) {
	cases := []struct {
		ip, cidr string
		want     bool
	}{
		{"10.0.0.5", "10.0.0.0/8", true},
		{"192.168.1.1", "10.0.0.0/8", false},
		{"10.0.0.5", "10.0.0.0/24", true},
		{"10.0.1.5", "10.0.0.0/24", false},
		{"", "10.0.0.0/8", false},
		{"10.0.0.5", "", false},
		{"not-an-ip", "10.0.0.0/8", false},
		{"10.0.0.5", "not-a-cidr", false},
	}
	for _, c := range cases {
		if got := matchCIDR(c.ip, c.cidr); got != c.want {
			t.Errorf("matchCIDR(%q, %q) = %v, want %v", c.ip, c.cidr, got, c.want)
		}
	}
}
