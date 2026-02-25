package dashboard

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dmitryporotnikov/sslinspectingrouter/internal/logger"
)

const (
	passwordHashVersion    = "v1"
	passwordHashIterations = 120000
	minPasswordLength      = 8
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,64}$`)

var (
	errAuthMissingSession = errors.New("missing session")
	errAuthInvalidSession = errors.New("invalid session")
	errAuthInactiveUser   = errors.New("inactive user")
)

// DashboardUser is the authenticated user model exposed via API responses.
type DashboardUser struct {
	ID          int64   `json:"id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	Role        string  `json:"role"`
	IsActive    bool    `json:"is_active"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
	LastLoginAt *string `json:"last_login_at,omitempty"`
}

type userWithSecret struct {
	DashboardUser
	PasswordHash string
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	User      *DashboardUser `json:"user"`
	Token     string         `json:"token,omitempty"`
	ExpiresAt string         `json:"expires_at,omitempty"`
}

type createUserRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Role        string `json:"role"`
	IsActive    *bool  `json:"is_active,omitempty"`
}

type updateUserRequest struct {
	Username    *string `json:"username,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Password    *string `json:"password,omitempty"`
	Role        *string `json:"role,omitempty"`
	IsActive    *bool   `json:"is_active,omitempty"`
}

func (s *Server) ensureAuthSchema() error {
	if _, err := s.db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}

	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS Users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL,
			is_active INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			last_login_at TEXT
		);
	`); err != nil {
		return fmt.Errorf("create Users table: %w", err)
	}

	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS Sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			last_seen_at TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE
		);
	`); err != nil {
		return fmt.Errorf("create Sessions table: %w", err)
	}

	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON Sessions(token_hash)`); err != nil {
		return fmt.Errorf("create sessions token index: %w", err)
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON Sessions(expires_at)`); err != nil {
		return fmt.Errorf("create sessions expiry index: %w", err)
	}

	return nil
}

func (s *Server) ensureBootstrapAdmin() error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM Users`).Scan(&count); err != nil {
		return fmt.Errorf("count users: %w", err)
	}
	if count > 0 {
		return nil
	}

	username := strings.TrimSpace(os.Getenv("SIR_ADMIN_USER"))
	if username == "" {
		username = "admin"
	}
	normalizedUser, err := normalizeUsername(username)
	if err != nil {
		normalizedUser = "admin"
	}

	displayName := strings.TrimSpace(os.Getenv("SIR_ADMIN_NAME"))
	if displayName == "" {
		displayName = "Administrator"
	}

	password := os.Getenv("SIR_ADMIN_PASS")
	if strings.TrimSpace(password) == "" {
		password = "admin123"
	}

	passwordHash, err := hashPassword(password)
	if err != nil {
		return err
	}

	now := s.now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(`
		INSERT INTO Users (username, display_name, password_hash, role, is_active, created_at, updated_at)
		VALUES (?, ?, ?, 'admin', 1, ?, ?)
	`, normalizedUser, displayName, passwordHash, now, now); err != nil {
		return fmt.Errorf("create bootstrap admin: %w", err)
	}

	fmt.Printf("Dashboard bootstrap admin created: username=%s password=%s\n", normalizedUser, password)
	return nil
}

func randomSecret(size int) ([]byte, error) {
	if size < 1 {
		return nil, errors.New("invalid secret size")
	}
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func normalizeUsername(raw string) (string, error) {
	username := strings.TrimSpace(raw)
	if !usernamePattern.MatchString(username) {
		return "", errors.New("username must match [a-zA-Z0-9._-] and be 3-64 characters")
	}
	return username, nil
}

func normalizeRole(raw string) (string, error) {
	role := strings.ToLower(strings.TrimSpace(raw))
	switch role {
	case "admin", "operator", "viewer":
		return role, nil
	default:
		return "", errors.New("role must be one of: admin, operator, viewer")
	}
}

func hashPassword(password string) (string, error) {
	if len(password) < minPasswordLength {
		return "", fmt.Errorf("password must be at least %d characters", minPasswordLength)
	}

	salt, err := randomSecret(16)
	if err != nil {
		return "", err
	}
	derived := derivePasswordHash(password, salt, passwordHashIterations)

	return fmt.Sprintf("%s$%d$%s$%s",
		passwordHashVersion,
		passwordHashIterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(derived),
	), nil
}

func verifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 4 || parts[0] != passwordHashVersion {
		return false
	}

	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return false
	}

	storedHash, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(storedHash) == 0 {
		return false
	}

	candidate := derivePasswordHash(password, salt, iterations)
	return subtle.ConstantTimeCompare(candidate, storedHash) == 1
}

func derivePasswordHash(password string, salt []byte, iterations int) []byte {
	seed := append([]byte{}, salt...)
	seed = append(seed, []byte(password)...)
	sum := sha256.Sum256(seed)
	current := sum[:]

	for i := 1; i < iterations; i++ {
		h := sha256.New()
		_, _ = h.Write(current)
		_, _ = h.Write(salt)
		_, _ = h.Write([]byte(password))
		current = h.Sum(nil)
	}

	result := make([]byte, len(current))
	copy(result, current)
	return result
}

func (s *Server) sessionTokenHash(token string) string {
	mac := hmac.New(sha256.New, s.sessionSecret)
	_, _ = mac.Write([]byte(token))
	return base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
}

func (s *Server) createSession(userID int64) (token string, expiresAt time.Time, err error) {
	raw, err := randomSecret(32)
	if err != nil {
		return "", time.Time{}, err
	}

	token = base64.RawURLEncoding.EncodeToString(raw)
	tokenHash := s.sessionTokenHash(token)
	now := s.now().UTC()
	expiresAt = now.Add(s.sessionTTL)

	if _, err := s.db.Exec(`
		INSERT INTO Sessions (user_id, token_hash, expires_at, created_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?)
	`, userID, tokenHash, expiresAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
		return "", time.Time{}, err
	}

	_, _ = s.db.Exec(`DELETE FROM Sessions WHERE expires_at <= ?`, now.Format(time.RFC3339Nano))
	return token, expiresAt, nil
}

func (s *Server) clearUserSessions(userID int64) {
	_, _ = s.db.Exec(`DELETE FROM Sessions WHERE user_id = ?`, userID)
}

func (s *Server) revokeSession(tokenHash string) {
	if tokenHash == "" {
		return
	}
	_, _ = s.db.Exec(`DELETE FROM Sessions WHERE token_hash = ?`, tokenHash)
}

func extractBearerToken(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func (s *Server) authenticateRequest(r *http.Request) (*DashboardUser, string, error) {
	token := extractBearerToken(r.Header.Get("Authorization"))
	if token == "" {
		cookie, err := r.Cookie(s.sessionCookieName)
		if err == nil {
			token = strings.TrimSpace(cookie.Value)
		}
	}

	if token == "" {
		return nil, "", errAuthMissingSession
	}

	tokenHash := s.sessionTokenHash(token)
	now := s.now().UTC().Format(time.RFC3339Nano)

	row := s.db.QueryRow(`
		SELECT
			u.id,
			u.username,
			u.display_name,
			u.role,
			u.is_active,
			u.created_at,
			u.updated_at,
			u.last_login_at,
			s.id
		FROM Sessions s
		JOIN Users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ?
		LIMIT 1
	`, tokenHash, now)

	var (
		user       DashboardUser
		activeFlag int
		lastLogin  sql.NullString
		sessionID  int64
	)

	if err := row.Scan(
		&user.ID,
		&user.Username,
		&user.DisplayName,
		&user.Role,
		&activeFlag,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLogin,
		&sessionID,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", errAuthInvalidSession
		}
		return nil, "", fmt.Errorf("lookup session: %w", err)
	}

	user.IsActive = activeFlag == 1
	if !user.IsActive {
		s.revokeSession(tokenHash)
		return nil, "", errAuthInactiveUser
	}
	if lastLogin.Valid {
		value := lastLogin.String
		user.LastLoginAt = &value
	}

	_, _ = s.db.Exec(`UPDATE Sessions SET last_seen_at = ? WHERE id = ?`, now, sessionID)
	return &user, tokenHash, nil
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, tokenHash, err := s.authenticateRequest(r)
		if err != nil {
			if errors.Is(err, errAuthMissingSession) || errors.Is(err, errAuthInvalidSession) || errors.Is(err, errAuthInactiveUser) {
				s.clearSessionCookie(w, r.TLS != nil)
				writeJSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			logger.LogError(fmt.Sprintf("dashboard authentication error: %v", err))
			writeJSONError(w, http.StatusInternalServerError, "authentication service unavailable")
			return
		}

		ctx := context.WithValue(r.Context(), contextUserKey, user)
		ctx = context.WithValue(ctx, contextTokenHashKey, tokenHash)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withAdmin(next http.Handler) http.Handler {
	return s.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := userFromContext(r.Context())
		if user == nil || user.Role != "admin" {
			writeJSONError(w, http.StatusForbidden, "admin role required")
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}

	var payload loginRequest
	if err := decodeJSONBody(r, &payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	username, err := normalizeUsername(payload.Username)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if strings.TrimSpace(payload.Password) == "" {
		writeJSONError(w, http.StatusBadRequest, "password is required")
		return
	}

	user, err := s.findUserForLogin(username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to authenticate")
		return
	}

	if !user.IsActive {
		writeJSONError(w, http.StatusForbidden, "account is disabled")
		return
	}

	if !verifyPassword(payload.Password, user.PasswordHash) {
		writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, expiresAt, err := s.createSession(user.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	now := s.now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.Exec(`UPDATE Users SET last_login_at = ?, updated_at = ? WHERE id = ?`, now, now, user.ID); err == nil {
		user.UpdatedAt = now
		user.LastLoginAt = &now
	}

	s.setSessionCookie(w, token, expiresAt, r.TLS != nil)
	writeJSON(w, http.StatusOK, authResponse{
		User:      &user.DashboardUser,
		Token:     token,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}

	s.revokeSession(tokenHashFromContext(r.Context()))
	s.clearSessionCookie(w, r.TLS != nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}

	user := userFromContext(r.Context())
	if user == nil {
		writeJSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListUsers(w)
	case http.MethodPost:
		s.handleCreateUser(w, r)
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	userID, err := parsePathID(r.URL.Path, "/api/v1/users/")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	switch r.Method {
	case http.MethodPut:
		s.handleUpdateUser(w, r, userID)
	case http.MethodDelete:
		s.handleDeleteUser(w, r, userID)
	default:
		writeMethodNotAllowed(w, http.MethodPut, http.MethodDelete)
	}
}

func (s *Server) handleListUsers(w http.ResponseWriter) {
	rows, err := s.db.Query(`
		SELECT id, username, display_name, role, is_active, created_at, updated_at, last_login_at
		FROM Users
		ORDER BY username ASC
	`)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load users")
		return
	}
	defer rows.Close()

	users := make([]DashboardUser, 0)
	for rows.Next() {
		var (
			u         DashboardUser
			active    int
			lastLogin sql.NullString
		)
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &active, &u.CreatedAt, &u.UpdatedAt, &lastLogin); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to load users")
			return
		}
		u.IsActive = active == 1
		if lastLogin.Valid {
			value := lastLogin.String
			u.LastLoginAt = &value
		}
		users = append(users, u)
	}

	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var payload createUserRequest
	if err := decodeJSONBody(r, &payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	username, err := normalizeUsername(payload.Username)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	role := "viewer"
	if strings.TrimSpace(payload.Role) != "" {
		role, err = normalizeRole(payload.Role)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	passwordHash, err := hashPassword(payload.Password)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	displayName := strings.TrimSpace(payload.DisplayName)
	if displayName == "" {
		displayName = username
	}

	active := 1
	if payload.IsActive != nil && !*payload.IsActive {
		active = 0
	}

	now := s.now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`
		INSERT INTO Users (username, display_name, password_hash, role, is_active, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, username, displayName, passwordHash, role, active, now, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSONError(w, http.StatusConflict, "username already exists")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	id, err := res.LastInsertId()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	created, err := s.fetchUserByID(id)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load new user")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"user": created})
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request, userID int64) {
	var payload updateUserRequest
	if err := decodeJSONBody(r, &payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	setClauses := make([]string, 0, 6)
	args := make([]any, 0, 7)
	clearSessions := false

	if payload.Username != nil {
		username, err := normalizeUsername(*payload.Username)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		setClauses = append(setClauses, "username = ?")
		args = append(args, username)
	}

	if payload.DisplayName != nil {
		displayName := strings.TrimSpace(*payload.DisplayName)
		if displayName == "" {
			writeJSONError(w, http.StatusBadRequest, "display_name cannot be empty")
			return
		}
		setClauses = append(setClauses, "display_name = ?")
		args = append(args, displayName)
	}

	if payload.Password != nil {
		passwordHash, err := hashPassword(*payload.Password)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		setClauses = append(setClauses, "password_hash = ?")
		args = append(args, passwordHash)
		clearSessions = true
	}

	if payload.Role != nil {
		role, err := normalizeRole(*payload.Role)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		setClauses = append(setClauses, "role = ?")
		args = append(args, role)
	}

	if payload.IsActive != nil {
		active := 0
		if *payload.IsActive {
			active = 1
		} else {
			clearSessions = true
		}
		setClauses = append(setClauses, "is_active = ?")
		args = append(args, active)
	}

	if len(setClauses) == 0 {
		writeJSONError(w, http.StatusBadRequest, "no updates requested")
		return
	}

	now := s.now().UTC().Format(time.RFC3339Nano)
	setClauses = append(setClauses, "updated_at = ?")
	args = append(args, now)
	args = append(args, userID)

	query := fmt.Sprintf("UPDATE Users SET %s WHERE id = ?", strings.Join(setClauses, ", "))
	res, err := s.db.Exec(query, args...)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeJSONError(w, http.StatusConflict, "username already exists")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "failed to update user")
		return
	}

	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}

	if clearSessions {
		s.clearUserSessions(userID)
	}

	updated, err := s.fetchUserByID(userID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to load updated user")
		return
	}

	requester := userFromContext(r.Context())
	if requester != nil && requester.ID == userID {
		requester.Username = updated.Username
		requester.DisplayName = updated.DisplayName
		requester.Role = updated.Role
		requester.IsActive = updated.IsActive
		requester.UpdatedAt = updated.UpdatedAt
		requester.LastLoginAt = updated.LastLoginAt
		if !updated.IsActive {
			s.revokeSession(tokenHashFromContext(r.Context()))
			s.clearSessionCookie(w, r.TLS != nil)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"user": updated})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request, userID int64) {
	requester := userFromContext(r.Context())
	if requester != nil && requester.ID == userID {
		writeJSONError(w, http.StatusBadRequest, "cannot delete currently authenticated user")
		return
	}

	s.clearUserSessions(userID)
	res, err := s.db.Exec(`DELETE FROM Users WHERE id = ?`, userID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		writeJSONError(w, http.StatusNotFound, "user not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) findUserForLogin(username string) (*userWithSecret, error) {
	row := s.db.QueryRow(`
		SELECT id, username, display_name, password_hash, role, is_active, created_at, updated_at, last_login_at
		FROM Users
		WHERE lower(username) = lower(?)
		LIMIT 1
	`, username)

	var (
		user      userWithSecret
		active    int
		lastLogin sql.NullString
	)
	if err := row.Scan(
		&user.ID,
		&user.Username,
		&user.DisplayName,
		&user.PasswordHash,
		&user.Role,
		&active,
		&user.CreatedAt,
		&user.UpdatedAt,
		&lastLogin,
	); err != nil {
		return nil, err
	}
	user.IsActive = active == 1
	if lastLogin.Valid {
		value := lastLogin.String
		user.LastLoginAt = &value
	}
	return &user, nil
}

func (s *Server) fetchUserByID(id int64) (*DashboardUser, error) {
	row := s.db.QueryRow(`
		SELECT id, username, display_name, role, is_active, created_at, updated_at, last_login_at
		FROM Users
		WHERE id = ?
		LIMIT 1
	`, id)

	var (
		user      DashboardUser
		active    int
		lastLogin sql.NullString
	)
	if err := row.Scan(&user.ID, &user.Username, &user.DisplayName, &user.Role, &active, &user.CreatedAt, &user.UpdatedAt, &lastLogin); err != nil {
		return nil, err
	}
	user.IsActive = active == 1
	if lastLogin.Valid {
		value := lastLogin.String
		user.LastLoginAt = &value
	}
	return &user, nil
}
