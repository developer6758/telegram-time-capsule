// Package auth binds service sessions to verified Telegram Login identities.
// It never accepts an MTProto auth key, Telegram password or asserted user ID.
package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

var ErrUnauthorized = errors.New("unauthorized")

type Config struct {
	Issuer            string
	ClientID          string
	ClientSecret      string
	CallbackURL       string
	AllowedAlgorithms []string
	// HTTPClient supplies transport timeouts / additional trusted CA roots; callers
	// must never disable certificate verification. Nil uses a 15-second client.
	HTTPClient *http.Client
}

type Service struct {
	pool     *pgxpool.Pool
	config   Config
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
	rateMu   sync.Mutex
	rates    map[string]rateEntry
}

type rateEntry struct {
	started time.Time
	count   int
}

func New(ctx context.Context, pool *pgxpool.Pool, config Config) (*Service, error) {
	if pool == nil || !secureURL(config.Issuer) || !secureURL(config.CallbackURL) || config.ClientID == "" || config.ClientSecret == "" {
		return nil, errors.New("auth requires PostgreSQL, HTTPS issuer/callback and Telegram Login credentials")
	}
	if len(config.AllowedAlgorithms) == 0 {
		config.AllowedAlgorithms = []string{"RS256", "ES256"}
	}
	for _, alg := range config.AllowedAlgorithms {
		if alg != "RS256" && alg != "ES256" {
			return nil, errors.New("unsupported OIDC algorithm")
		}
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	ctx = oidc.ClientContext(ctx, client)
	// Preserve the configured transport and CA trust while forbidding redirect
	// downgrades. OAuth secrets must never follow a redirect to plain HTTP.
	clientCopy := *client
	priorRedirect := client.CheckRedirect
	clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) > 3 {
			return errors.New("unsafe authentication redirect")
		}
		if priorRedirect != nil {
			return priorRedirect(req, via)
		}
		return nil
	}
	client = &clientCopy
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if provider.Claims(&metadata) != nil || !secureURL(metadata.JWKSURL) {
		return nil, errors.New("OIDC JWKS must use HTTPS")
	}
	endpoints := provider.Endpoint()
	if !secureURL(endpoints.AuthURL) || !secureURL(endpoints.TokenURL) {
		return nil, errors.New("OIDC endpoints must use HTTPS")
	}
	return &Service{pool: pool, config: config, client: client,
		oauth:    oauth2.Config{ClientID: config.ClientID, ClientSecret: config.ClientSecret, Endpoint: endpoints, RedirectURL: config.CallbackURL, Scopes: []string{oidc.ScopeOpenID, "profile"}},
		verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID, SupportedSigningAlgs: config.AllowedAlgorithms}), rates: make(map[string]rateEntry)}, nil
}

func secureURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.RawQuery == ""
}

func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/auth/start", s.start)
	mux.HandleFunc("GET /v1/auth/callback", s.callback)
	mux.HandleFunc("POST /v1/auth/complete", s.complete)
	mux.HandleFunc("POST /v1/auth/refresh", s.refresh)
	mux.HandleFunc("POST /v1/auth/logout", s.logout)
}

// Authenticate is deliberately independent of caller-supplied Telegram IDs.
func (s *Service) Authenticate(r *http.Request) (string, error) {
	token, ok := bearer(r)
	if !ok {
		return "", ErrUnauthorized
	}
	hash := sha256.Sum256([]byte(token))
	var id int64
	err := s.pool.QueryRow(r.Context(), `SELECT f.telegram_user_id FROM capsule_access_tokens a
        JOIN capsule_session_families f ON f.id=a.family_id
        WHERE a.token_hash=$1 AND a.expires_at>clock_timestamp()
        AND f.expires_at>clock_timestamp() AND NOT f.revoked`, hash[:]).Scan(&id)
	if err != nil || id <= 0 {
		return "", ErrUnauthorized
	}
	return strconv.FormatInt(id, 10), nil
}

func bearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	return token, validOpaque(token)
}

func validOpaque(value string) bool {
	if len(value) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == value
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Service) allowed(r *http.Request, operation string) bool {
	// No X-Forwarded-For trust. Bound memory and apply per-socket-IP limits.
	host := r.RemoteAddr
	if pos := strings.LastIndex(host, ":"); pos >= 0 {
		host = host[:pos]
	}
	key := operation + ":" + host
	now := time.Now()
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	e := s.rates[key]
	if now.Sub(e.started) >= time.Minute {
		e = rateEntry{started: now}
	}
	if len(s.rates) > 8192 {
		for k, v := range s.rates {
			if now.Sub(v.started) >= time.Minute {
				delete(s.rates, k)
			}
		}
		if len(s.rates) > 8192 {
			return false
		}
	}
	e.count++
	s.rates[key] = e
	limit := 30
	if operation == "complete" {
		limit = 180
	}
	return e.count <= limit
}

func (s *Service) start(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(r, "start") {
		fail(w, 429, "rate_limited", true)
		return
	}
	var req struct {
		CompletionChallenge string `json:"completion_challenge"`
	}
	if decode(w, r, &req) != nil || !validOpaque(req.CompletionChallenge) {
		fail(w, 400, "malformed", false)
		return
	}
	challenge, _ := base64.RawURLEncoding.DecodeString(req.CompletionChallenge)
	id, err := randomToken()
	if err != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	state, err := randomToken()
	if err != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	verifier, err := randomToken()
	if err != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	stateHash := sha256.Sum256([]byte(state))
	var expiry time.Time
	err = s.pool.QueryRow(r.Context(), `INSERT INTO capsule_auth_transactions
        (id,completion_challenge,state_hash,pkce_verifier,nonce) VALUES($1,$2,$3,$4,$5) RETURNING expires_at`, id, challenge, stateHash[:], verifier, nonce).Scan(&expiry)
	if err != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	authURL := s.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))
	write(w, 200, map[string]any{"transaction_id": id, "authorization_url": authURL, "expires_ms": expiry.UnixMilli()})
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(r, "callback") {
		fail(w, 429, "rate_limited", true)
		return
	}
	// Reject repeated query keys before any token exchange.
	q := r.URL.Query()
	if len(q["state"]) != 1 || len(q["code"]) != 1 || len(q["error"]) > 0 || !validOpaque(q.Get("state")) || q.Get("code") == "" || len(q.Get("code")) > 4096 {
		fail(w, 400, "invalid_login", false)
		return
	}
	stateHash := sha256.Sum256([]byte(q.Get("state")))
	codeHash := sha256.Sum256([]byte(q.Get("code")))
	var id, pkce, nonce string
	var created time.Time
	// State is claimed exactly once before exchange; a failed exchange requires a
	// new login. This prevents code replay without holding a DB lock on network IO.
	err := s.pool.QueryRow(r.Context(), `UPDATE capsule_auth_transactions SET callback_started=true,code_hash=$2
        WHERE state_hash=$1 AND NOT callback_started AND NOT consumed AND expires_at>clock_timestamp()
        RETURNING id,pkce_verifier,nonce,created_at`, stateHash[:], codeHash[:]).Scan(&id, &pkce, &nonce, &created)
	if err != nil {
		fail(w, 400, "invalid_login", false)
		return
	}
	ctx := oidc.ClientContext(r.Context(), s.client)
	token, err := s.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(pkce))
	if err != nil {
		s.eraseLoginSecrets(r.Context(), id)
		fail(w, 400, "invalid_login", false)
		return
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" || len(raw) > 32768 {
		s.eraseLoginSecrets(r.Context(), id)
		fail(w, 400, "invalid_login", false)
		return
	}
	verified, err := s.verifier.Verify(ctx, raw)
	if err != nil {
		s.eraseLoginSecrets(r.Context(), id)
		fail(w, 400, "invalid_login", false)
		return
	}
	userID, err := verifiedIdentity(verified, nonce, s.config.ClientID, created, time.Now())
	if err != nil {
		s.eraseLoginSecrets(r.Context(), id)
		fail(w, 400, "invalid_login", false)
		return
	}
	numericID, _ := strconv.ParseInt(userID, 10, 64)
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	defer tx.Rollback(r.Context())
	// A provider subject must not silently switch messaging identity on a later login.
	_, err = tx.Exec(r.Context(), `INSERT INTO capsule_identities(issuer,subject,telegram_user_id) VALUES($1,$2,$3)
        ON CONFLICT(issuer,subject) DO NOTHING`, verified.Issuer, verified.Subject, numericID)
	var storedID int64
	if err == nil {
		err = tx.QueryRow(r.Context(), `SELECT telegram_user_id FROM capsule_identities WHERE issuer=$1 AND subject=$2`, verified.Issuer, verified.Subject).Scan(&storedID)
	}
	if err != nil || strconv.FormatInt(storedID, 10) != userID {
		fail(w, 400, "invalid_login", false)
		return
	}
	tag, err := tx.Exec(r.Context(), `UPDATE capsule_auth_transactions SET completed=true,issuer=$2,subject=$3,telegram_user_id=$4,pkce_verifier='',nonce=''
        WHERE id=$1 AND NOT consumed AND expires_at>clock_timestamp()`, id, verified.Issuer, verified.Subject, numericID)
	if err != nil || tag.RowsAffected() != 1 || tx.Commit(r.Context()) != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	// No token, transaction ID or user data is handed to the browser URL.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	_, _ = io.WriteString(w, "Telegram authorization completed. Return to Telegram to continue.")
}

func (s *Service) eraseLoginSecrets(ctx context.Context, id string) {
	_, _ = s.pool.Exec(ctx, `UPDATE capsule_auth_transactions SET pkce_verifier='',nonce='' WHERE id=$1`, id)
}

func verifiedIdentity(token *oidc.IDToken, nonce, clientID string, created, now time.Time) (string, error) {
	if token.Subject == "" || len(token.Subject) > 512 || subtle.ConstantTimeCompare([]byte(token.Nonce), []byte(nonce)) != 1 || nonce == "" {
		return "", ErrUnauthorized
	}
	var raw json.RawMessage
	if err := token.Claims(&raw); err != nil || !uniqueJSON(raw) {
		return "", ErrUnauthorized
	}
	var claims struct {
		ID              json.RawMessage `json:"id"`
		IssuedAt        json.RawMessage `json:"iat"`
		AuthorizedParty string          `json:"azp"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&claims) != nil {
		return "", ErrUnauthorized
	}
	issued, err := strconv.ParseInt(string(claims.IssuedAt), 10, 64)
	if err != nil || issued <= 0 || issued > now.Add(time.Minute).Unix() || issued < created.Add(-time.Minute).Unix() {
		return "", ErrUnauthorized
	}
	if (len(token.Audience) > 1 && claims.AuthorizedParty == "") || (claims.AuthorizedParty != "" && claims.AuthorizedParty != clientID) {
		return "", ErrUnauthorized
	}
	return parseTelegramID(claims.ID)
}

func parseTelegramID(raw json.RawMessage) (string, error) {
	value := string(raw)
	if len(raw) > 0 && raw[0] == '"' {
		if json.Unmarshal(raw, &value) != nil {
			return "", ErrUnauthorized
		}
	}
	if len(value) == 0 || len(value) > 19 || value[0] == '0' {
		return "", ErrUnauthorized
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return "", ErrUnauthorized
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n <= 0 {
		return "", ErrUnauthorized
	}
	return strconv.FormatInt(n, 10), nil
}

type SessionResponse struct {
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	TelegramUserID string `json:"telegram_user_id"`
	ExpiresMS      int64  `json:"expires_ms"`
}

func (s *Service) complete(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(r, "complete") {
		fail(w, 429, "rate_limited", true)
		return
	}
	var req struct {
		TransactionID      string `json:"transaction_id"`
		CompletionVerifier string `json:"completion_verifier"`
	}
	if decode(w, r, &req) != nil || !validOpaque(req.TransactionID) || !validOpaque(req.CompletionVerifier) {
		fail(w, 400, "invalid_login", false)
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	defer tx.Rollback(r.Context())
	var challenge []byte
	var issuer, subject *string
	var userID *int64
	var completed, consumed, valid bool
	err = tx.QueryRow(r.Context(), `SELECT completion_challenge,issuer,subject,telegram_user_id,completed,consumed,expires_at>clock_timestamp()
        FROM capsule_auth_transactions WHERE id=$1 FOR UPDATE`, req.TransactionID).Scan(&challenge, &issuer, &subject, &userID, &completed, &consumed, &valid)
	// The completion verifier is 32 random bytes encoded as unpadded base64url.
	verifier, _ := base64.RawURLEncoding.DecodeString(req.CompletionVerifier)
	proof := sha256.Sum256(verifier)
	if err != nil || consumed || !valid || subtle.ConstantTimeCompare(challenge, proof[:]) != 1 {
		fail(w, 400, "invalid_login", false)
		return
	}
	if !completed || issuer == nil || subject == nil || userID == nil {
		fail(w, 409, "login_pending", true)
		return
	}
	response, err := issueSession(r.Context(), tx, *issuer, *subject, *userID, "")
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE capsule_auth_transactions SET consumed=true,completion_challenge=$2 WHERE id=$1`, req.TransactionID, make([]byte, 32))
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	write(w, 200, response)
}

func issueSession(ctx context.Context, tx pgx.Tx, issuer, subject string, userID int64, family string) (SessionResponse, error) {
	var result SessionResponse
	var err error
	result.AccessToken, err = randomToken()
	if err != nil {
		return result, err
	}
	result.RefreshToken, err = randomToken()
	if err != nil {
		return result, err
	}
	result.TelegramUserID = strconv.FormatInt(userID, 10)
	if family == "" {
		family, err = randomToken()
		if err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO capsule_session_families(id,telegram_user_id,issuer,subject) VALUES($1,$2,$3,$4)`, family, userID, issuer, subject); err != nil {
			return result, err
		}
	}
	accessHash := sha256.Sum256([]byte(result.AccessToken))
	refreshHash := sha256.Sum256([]byte(result.RefreshToken))
	var expiry time.Time
	if err = tx.QueryRow(ctx, `INSERT INTO capsule_access_tokens(token_hash,family_id,expires_at)
        SELECT $1,id,LEAST(clock_timestamp()+interval '15 minutes',expires_at) FROM capsule_session_families WHERE id=$2
        RETURNING expires_at`, accessHash[:], family).Scan(&expiry); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO capsule_refresh_tokens(token_hash,family_id,expires_at)
        SELECT $1,id,expires_at FROM capsule_session_families WHERE id=$2`, refreshHash[:], family); err != nil {
		return result, err
	}
	result.ExpiresMS = expiry.UnixMilli()
	return result, nil
}

func (s *Service) refresh(w http.ResponseWriter, r *http.Request) {
	if !s.allowed(r, "refresh") {
		fail(w, 429, "rate_limited", true)
		return
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if decode(w, r, &req) != nil || !validOpaque(req.RefreshToken) {
		fail(w, 401, "unauthorized", false)
		return
	}
	hash := sha256.Sum256([]byte(req.RefreshToken))
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	defer tx.Rollback(r.Context())
	var family string
	err = tx.QueryRow(r.Context(), `SELECT family_id FROM capsule_refresh_tokens WHERE token_hash=$1`, hash[:]).Scan(&family)
	if err != nil {
		fail(w, 401, "unauthorized", false)
		return
	}
	var issuer, subject string
	var userID int64
	var revoked, valid bool
	// Consistent family-before-token locking serializes refresh and logout.
	err = tx.QueryRow(r.Context(), `SELECT issuer,subject,telegram_user_id,revoked,expires_at>clock_timestamp()
        FROM capsule_session_families WHERE id=$1 FOR UPDATE`, family).Scan(&issuer, &subject, &userID, &revoked, &valid)
	if err != nil || revoked || !valid {
		fail(w, 401, "unauthorized", false)
		return
	}
	var used, tokenValid bool
	err = tx.QueryRow(r.Context(), `SELECT used,expires_at>clock_timestamp() FROM capsule_refresh_tokens WHERE token_hash=$1 FOR UPDATE`, hash[:]).Scan(&used, &tokenValid)
	if err != nil || !tokenValid {
		fail(w, 401, "unauthorized", false)
		return
	}
	if used {
		if _, err = tx.Exec(r.Context(), `UPDATE capsule_session_families SET revoked=true WHERE id=$1`, family); err != nil || tx.Commit(r.Context()) != nil {
			fail(w, 503, "unavailable", true)
			return
		}
		fail(w, 401, "refresh_replayed", false)
		return
	}
	_, err = tx.Exec(r.Context(), `UPDATE capsule_refresh_tokens SET used=true WHERE token_hash=$1`, hash[:])
	var result SessionResponse
	if err == nil {
		result, err = issueSession(r.Context(), tx, issuer, subject, userID, family)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	write(w, 200, result)
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		fail(w, 401, "unauthorized", false)
		return
	}
	hash := sha256.Sum256([]byte(token))
	tag, err := s.pool.Exec(r.Context(), `UPDATE capsule_session_families SET revoked=true WHERE id=(
        SELECT family_id FROM capsule_access_tokens WHERE token_hash=$1 AND expires_at>clock_timestamp())`, hash[:])
	if err != nil {
		fail(w, 503, "unavailable", true)
		return
	}
	if tag.RowsAffected() != 1 {
		fail(w, 401, "unauthorized", false)
		return
	}
	write(w, 200, map[string]bool{"logged_out": true})
}

func decode(w http.ResponseWriter, r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	raw, err := io.ReadAll(r.Body)
	if err != nil || !utf8.Valid(raw) || !uniqueJSON(raw) {
		return errors.New("invalid JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// uniqueJSON rejects duplicate members at every nesting level before semantic parsing.
func uniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("depth")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("duplicate")
				}
				seen[key] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		default:
			return errors.New("delimiter")
		}
	}
	if !utf8.Valid(raw) || value(0) != nil {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
func fail(w http.ResponseWriter, status int, code string, retryable bool) {
	if status == 429 {
		w.Header().Set("Retry-After", "60")
	}
	requestID, _ := randomToken()
	write(w, status, map[string]any{"code": code, "retryable": retryable, "server_ms": time.Now().UnixMilli(), "request_id": requestID})
}
