package dashboard

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/dnsproxy"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/firewall"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/proxy"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/rewrites"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/tor"
	"github.com/dmitryporotnikov/sslinspectingrouter/internal/wireguard"
)

//go:embed frontend/*
var frontendFiles embed.FS

type contextKey string

const (
	contextUserKey      contextKey = "dashboard_user"
	contextTokenHashKey contextKey = "dashboard_token_hash"
)

const (
	defaultSessionCookie = "sir_session"
	defaultSessionTTL    = 24 * time.Hour
)

// Server exposes API endpoints and serves the frontend dashboard.
type Server struct {
	db                 *sql.DB
	addr               string
	httpHandler        *proxy.HTTPHandler
	httpsHandler       *proxy.HTTPSHandler
	dnsProxy           *dnsproxy.DNSProxy
	rewriter           *rewrites.Engine
	egressRuntime      EgressRuntime
	outboundPorts      OutboundPortsRuntime
	wireguardRuntime   WireGuardRuntime
	torRuntime         TorRuntime
	allowQUIC          bool
	additionalTLSPorts []int
	inspectOnlySources []string
	sniOnlyMode        bool
	pcapPath           string
	truncateLog        atomic.Bool
	sessionTTL         time.Duration
	sessionCookieName  string
	sessionSecret      []byte
	now                func() time.Time
	lastRequestCount   atomic.Int64
	lastActiveSession  atomic.Int64
}

type TLSOptions struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

type Options struct {
	TLS         TLSOptions
	HTTPHandler *proxy.HTTPHandler
	DNSProxy    *dnsproxy.DNSProxy
	Runtime     RuntimeOptions
}

type RuntimeOptions struct {
	AllowQUIC          bool
	AdditionalTLSPorts []int
	InspectOnlySources []string
	PCAPPath           string
	TruncateLog        bool
	SNIOnlyMode        bool
	Egress             EgressRuntime
	OutboundPorts      OutboundPortsRuntime
	WireGuard          WireGuardRuntime
	Tor                TorRuntime
}

type EgressRuntime interface {
	SetEgressInterface(string) error
	EgressInterface() string
	DefaultEgressInterface() string
}

// OutboundPortsRuntime applies the firewall outbound port allowlist to
// the host. The same *firewall.FirewallManager satisfies both
// EgressRuntime and OutboundPortsRuntime.
type OutboundPortsRuntime interface {
	ApplyOutboundPorts(enabled bool, entries []firewall.OutboundPortEntry) error
}

type WireGuardRuntime interface {
	Status() (wireguard.Status, error)
	SaveConfig(string) (string, error)
	Enable() (wireguard.Status, error)
	Disable() (wireguard.Status, error)
}

type TorRuntime interface {
	Status() (tor.Status, error)
	Enable() (tor.Status, error)
	Disable() (tor.Status, error)
}

func Start(db *sql.DB, addr string, httpsHandler *proxy.HTTPSHandler, rewriter *rewrites.Engine) error {
	return StartWithOptions(db, addr, httpsHandler, rewriter, Options{})
}

func StartWithOptions(db *sql.DB, addr string, httpsHandler *proxy.HTTPSHandler, rewriter *rewrites.Engine, options Options) error {
	s, err := NewServer(db, addr, httpsHandler, rewriter)
	if err != nil {
		return err
	}
	s.httpHandler = options.HTTPHandler
	s.dnsProxy = options.DNSProxy
	s.allowQUIC = options.Runtime.AllowQUIC
	s.pcapPath = strings.TrimSpace(options.Runtime.PCAPPath)
	s.additionalTLSPorts = append([]int(nil), options.Runtime.AdditionalTLSPorts...)
	s.inspectOnlySources = append([]string(nil), options.Runtime.InspectOnlySources...)
	s.sniOnlyMode = options.Runtime.SNIOnlyMode
	s.truncateLog.Store(options.Runtime.TruncateLog)
	s.egressRuntime = options.Runtime.Egress
	s.outboundPorts = options.Runtime.OutboundPorts
	s.wireguardRuntime = options.Runtime.WireGuard
	s.torRuntime = options.Runtime.Tor

	// Initialize firewall manager with database
	fm := firewall.GetManager()
	if err := fm.Initialize(db); err != nil {
		logger.LogError(fmt.Sprintf("Failed to initialize firewall: %v", err))
	}

	// Wire the firewall enabled callback to the iptables applier so the
	// SSL_OUTBOUND chain tracks firewall mode + the current allowlist.
	if s.outboundPorts != nil {
		fm.SetOnEnabledChange(func(enabled bool, entries []firewall.OutboundPortEntry) {
			if err := s.outboundPorts.ApplyOutboundPorts(enabled, entries); err != nil {
				logger.LogError(fmt.Sprintf("Failed to apply outbound ports: %v", err))
			}
		})
		// Apply the current state once at startup so a previously persisted
		// "enabled" flag is honored without requiring a dashboard toggle.
		if err := s.outboundPorts.ApplyOutboundPorts(fm.IsEnabled(), fm.GetOutboundPorts()); err != nil {
			logger.LogError(fmt.Sprintf("Failed to apply initial outbound ports: %v", err))
		}
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	if options.TLS.Enabled {
		certFile, keyFile, err := ensureDashboardTLSCert(options.TLS.CertFile, options.TLS.KeyFile)
		if err != nil {
			return err
		}
		logger.LogInfo(fmt.Sprintf("Dashboard listening on https://localhost%s", addr))
		return server.ListenAndServeTLS(certFile, keyFile)
	}

	logger.LogInfo(fmt.Sprintf("Dashboard listening on http://localhost%s", addr))
	return server.ListenAndServe()
}

func NewServer(db *sql.DB, addr string, httpsHandler *proxy.HTTPSHandler, rewriter *rewrites.Engine) (*Server, error) {
	if db == nil {
		return nil, errors.New("dashboard requires initialized database")
	}

	secret := []byte(strings.TrimSpace(os.Getenv("SIR_SESSION_SECRET")))
	if len(secret) == 0 {
		generated, err := randomSecret(32)
		if err != nil {
			return nil, fmt.Errorf("generate session secret: %w", err)
		}
		secret = generated
	}

	s := &Server{
		db:                db,
		addr:              addr,
		httpsHandler:      httpsHandler,
		rewriter:          rewriter,
		sessionTTL:        defaultSessionTTL,
		sessionCookieName: defaultSessionCookie,
		sessionSecret:     secret,
		now:               time.Now,
	}
	s.truncateLog.Store(logger.IsLogTruncationEnabled())

	if err := s.ensureAuthSchema(); err != nil {
		return nil, err
	}
	if err := s.ensureBootstrapAdmin(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/localization/languages", s.handleLocalizationLanguages)
	mux.HandleFunc("/api/v1/auth/login", s.handleAuthLogin)
	mux.Handle("/api/v1/auth/logout", s.withAuth(http.HandlerFunc(s.handleAuthLogout)))
	mux.Handle("/api/v1/auth/me", s.withAuth(http.HandlerFunc(s.handleAuthMe)))

	mux.Handle("/api/v1/status", s.withAuth(http.HandlerFunc(s.handleStatus)))
	mux.Handle("/api/v1/policy", s.withAuth(http.HandlerFunc(s.handlePolicy)))
	mux.Handle("/api/v1/firewall/status", s.withAuth(http.HandlerFunc(s.handleFirewallStatus)))
	mux.Handle("/api/v1/firewall/rules", s.withAuth(http.HandlerFunc(s.handleFirewallRules)))
	mux.Handle("/api/v1/firewall/rules/", s.withAuth(http.HandlerFunc(s.handleFirewallRuleByID)))
	mux.Handle("/api/v1/firewall/outbound-ports", s.withAuth(http.HandlerFunc(s.handleOutboundPorts)))
	mux.Handle("/api/v1/traffic", s.withAuth(http.HandlerFunc(s.handleTraffic)))
	mux.Handle("/api/v1/traffic/", s.withAuth(http.HandlerFunc(s.handleTrafficDetail)))
	mux.Handle("/api/v1/rewrites", s.withAuth(http.HandlerFunc(s.handleRewrites)))
	mux.Handle("/api/v1/rewrites/", s.withAuth(http.HandlerFunc(s.handleRewriteByID)))
	mux.Handle("/api/v1/users", s.withAdmin(http.HandlerFunc(s.handleUsers)))
	mux.Handle("/api/v1/users/", s.withAdmin(http.HandlerFunc(s.handleUserByID)))

	// Compatibility aliases for old clients.
	mux.Handle("/api/status", s.withAuth(http.HandlerFunc(s.handleStatus)))
	mux.Handle("/api/policy", s.withAuth(http.HandlerFunc(s.handlePolicy)))
	mux.Handle("/api/rewrites", s.withAuth(http.HandlerFunc(s.handleRewrites)))
	mux.Handle("/api/rewrites/", s.withAuth(http.HandlerFunc(s.handleRewriteByID)))

	mux.Handle("/", s.frontendHandler())

	return s.recoverMiddleware(mux)
}

func (s *Server) frontendHandler() http.Handler {
	fsys, err := fs.Sub(frontendFiles, "frontend")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		})
	}

	indexHTML, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		})
	}

	staticServer := http.FileServer(http.FS(fsys))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		cleaned := path.Clean(r.URL.Path)
		if cleaned == "." || cleaned == "/" {
			serveIndexHTML(w, r, indexHTML)
			return
		}

		base := path.Base(cleaned)
		if !strings.Contains(base, ".") {
			serveIndexHTML(w, r, indexHTML)
			return
		}

		staticServer.ServeHTTP(w, r)
	})
}

func serveIndexHTML(w http.ResponseWriter, r *http.Request, indexHTML []byte) {
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(indexHTML))
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.LogError(fmt.Sprintf("Dashboard panic on %s %s: %v", r.Method, r.URL.Path, recovered))
				writeJSONError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"server_time": s.now().UTC().Format(time.RFC3339Nano),
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error": message,
	})
}

func writeMethodNotAllowed(w http.ResponseWriter, allowed ...string) {
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
	}
	writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func decodeJSONBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return err
	}

	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("body must contain a single JSON object")
		}
		return err
	}
	return nil
}

func parseBoundedInt(raw string, fallback, min, max int) int {
	value := fallback
	if raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			value = parsed
		}
	}
	if value < min {
		value = min
	}
	if value > max {
		value = max
	}
	return value
}

func parsePathID(pathValue, prefix string) (int64, error) {
	idToken := strings.TrimPrefix(pathValue, prefix)
	if idToken == pathValue || idToken == "" || strings.Contains(idToken, "/") {
		return 0, errors.New("invalid resource id")
	}

	id, err := strconv.ParseInt(idToken, 10, 64)
	if err != nil || id < 1 {
		return 0, errors.New("invalid resource id")
	}
	return id, nil
}

func userFromContext(ctx context.Context) *DashboardUser {
	if ctx == nil {
		return nil
	}
	user, _ := ctx.Value(contextUserKey).(*DashboardUser)
	return user
}

func tokenHashFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	value, _ := ctx.Value(contextTokenHashKey).(string)
	return value
}
