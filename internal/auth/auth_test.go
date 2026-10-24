package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTelegramIDIsNotSubjectOrFloat(t *testing.T) {
	cases := []struct{ raw, want string }{
		{`123`, `123`}, {`"9007199254740993"`, `9007199254740993`}, {`9223372036854775807`, `9223372036854775807`},
		{`null`, ``}, {`0`, ``}, {`"0"`, ``}, {`-1`, ``}, {`1.0`, ``}, {`1e3`, ``}, {`"01"`, ``}, {`" 12"`, ``},
		{`9223372036854775808`, ``}, {`"1e3"`, ``}, {`true`, ``}, {`"+2"`, ``}, {`"opaque-subject"`, ``},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			got, err := parseTelegramID(json.RawMessage(c.raw))
			if c.want == "" {
				if err == nil {
					t.Fatal("accepted invalid identity")
				}
			} else if err != nil || got != c.want {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestStrictLoginJSON(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `{"a":[{"b":1,"b":2}]}`, `{} {}`, `[1`, "{\"a\":\"\xff\"}"} {
		if uniqueJSON([]byte(raw)) {
			t.Fatalf("accepted malformed or duplicate JSON: %q", raw)
		}
	}
	if !uniqueJSON([]byte(`{"a":[1,{"b":"שלום 👩🏽‍💻"}],"c":true}`)) {
		t.Fatal("rejected valid JSON")
	}
	var req struct {
		Value string `json:"value"`
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"value":"ok","unknown":1}`))
	if decode(httptest.NewRecorder(), r, &req) == nil {
		t.Fatal("accepted unknown auth input")
	}
}

func TestOpaqueTokenCanonical(t *testing.T) {
	token, err := randomToken()
	if err != nil || !validOpaque(token) {
		t.Fatal(err)
	}
	for _, bad := range []string{token + "=", token[:42], " " + token, strings.Repeat("_", 43), "a.b.c"} {
		if validOpaque(bad) {
			t.Fatal("accepted malformed token")
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer "+token)
	r.Header.Add("Authorization", "Bearer "+token)
	if _, ok := bearer(r); ok {
		t.Fatal("accepted repeated Authorization")
	}
}

type fakeProvider struct {
	server           *httptest.Server
	key              *rsa.PrivateKey
	mu               sync.Mutex
	nonce, challenge string
	tokenCalls       atomic.Int32
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "kid": "test", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		p.tokenCalls.Add(1)
		_ = r.ParseForm()
		p.mu.Lock()
		nonce, challenge := p.nonce, p.challenge
		p.mu.Unlock()
		verifier := r.Form.Get("code_verifier")
		sum := sha256.Sum256([]byte(verifier))
		if r.Form.Get("code") != "test-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			write(w, 400, map[string]any{"error": "invalid_grant"})
			return
		}
		claims := p.claims(nonce)
		write(w, 200, map[string]any{"access_token": "provider-token-not-returned", "token_type": "Bearer", "expires_in": 60, "id_token": p.sign(t, claims)})
	})
	p.server = httptest.NewTLSServer(mux)
	t.Cleanup(p.server.Close)
	return p
}
func (p *fakeProvider) config() Config {
	return Config{Issuer: p.server.URL, ClientID: "capsule-test", ClientSecret: "backend-held-secret", CallbackURL: "https://capsule.test/v1/auth/callback", HTTPClient: p.server.Client()}
}
func (p *fakeProvider) claims(nonce string) map[string]any {
	return map[string]any{"iss": p.server.URL, "aud": "capsule-test", "sub": "opaque-subject-not-numeric", "id": "9007199254740993", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": nonce}
}
func (p *fakeProvider) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test","typ":"JWT"}`))
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := header + "." + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestOIDCVerificationRejectsTampering(t *testing.T) {
	p := newFakeProvider(t)
	s, err := New(context.Background(), &pgxpool.Pool{}, p.config())
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := randomToken()
	created := time.Now().Add(-time.Second)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"valid", func(m map[string]any) {}},
		{"wrong_issuer", func(m map[string]any) { m["iss"] = "https://attacker.test" }},
		{"wrong_audience", func(m map[string]any) { m["aud"] = "other-client" }},
		{"expired", func(m map[string]any) { m["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"missing_id", func(m map[string]any) { delete(m, "id") }},
		{"fraction_id", func(m map[string]any) { m["id"] = 1.25 }},
		{"future_issue_time", func(m map[string]any) { m["iat"] = time.Now().Add(time.Hour).Unix() }},
		{"missing_issue_time", func(m map[string]any) { delete(m, "iat") }},
		{"quoted_issue_time", func(m map[string]any) { m["iat"] = "123" }},
		{"wrong_nonce", func(m map[string]any) { m["nonce"] = "attacker" }},
		{"missing_nonce", func(m map[string]any) { delete(m, "nonce") }},
		{"wrong_authorized_party", func(m map[string]any) { m["azp"] = "other-client" }},
		{"multi_audience_missing_azp", func(m map[string]any) { m["aud"] = []string{"capsule-test", "other"} }},
		{"empty_subject", func(m map[string]any) { m["sub"] = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := p.claims(nonce)
			test.mutate(claims)
			token, err := s.verifier.Verify(oidc.ClientContext(context.Background(), p.server.Client()), p.sign(t, claims))
			if err == nil {
				_, err = verifiedIdentity(token, nonce, s.config.ClientID, created, time.Now())
			}
			if test.name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid OIDC identity")
			}
		})
	}
	raw := p.sign(t, p.claims(nonce))
	parts := strings.Split(raw, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	if _, err := s.verifier.Verify(oidc.ClientContext(context.Background(), p.server.Client()), strings.Join(parts, ".")); err == nil {
		t.Fatal("accepted wrong signature")
	}
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + "."
	if _, err := s.verifier.Verify(oidc.ClientContext(context.Background(), p.server.Client()), none); err == nil {
		t.Fatal("accepted alg none")
	}
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CAPSULE_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("TCAP_TEST_DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("set CAPSULE_TEST_DATABASE_URL to run real PostgreSQL auth transactions")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "auth_test_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close(); _, _ = admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); admin.Close() })
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "002_auth.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(context.Background(), string(raw)); err != nil {
		t.Fatal(err)
	}
	return pool
}

func callJSON(t *testing.T, h http.Handler, method, path string, body any, bearerToken string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, reader)
	if bearerToken != "" {
		r.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPostgresLoginProofStateReplayAndRefreshFamily(t *testing.T) {
	pool := testPool(t)
	p := newFakeProvider(t)
	s, err := New(context.Background(), pool, p.config())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.Register(mux)
	verifier, _ := randomToken()
	decoded, _ := base64.RawURLEncoding.DecodeString(verifier)
	challenge := sha256.Sum256(decoded)
	start := callJSON(t, mux, "POST", "/v1/auth/start", map[string]string{"completion_challenge": base64.RawURLEncoding.EncodeToString(challenge[:])}, "")
	if start.Code != 200 {
		t.Fatalf("start %d %s", start.Code, start.Body)
	}
	var started struct {
		TransactionID string `json:"transaction_id"`
		AuthURL       string `json:"authorization_url"`
	}
	if json.Unmarshal(start.Body.Bytes(), &started) != nil {
		t.Fatal("start JSON")
	}
	authURL, err := url.Parse(started.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	q := authURL.Query()
	if q.Get("scope") != "openid profile" || q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != s.config.CallbackURL {
		t.Fatal("unsafe auth parameters")
	}
	p.mu.Lock()
	p.nonce = q.Get("nonce")
	p.challenge = q.Get("code_challenge")
	p.mu.Unlock()
	completeBody := map[string]string{"transaction_id": started.TransactionID, "completion_verifier": verifier}
	pending := callJSON(t, mux, "POST", "/v1/auth/complete", completeBody, "")
	if pending.Code != 409 {
		t.Fatalf("pending %d", pending.Code)
	}
	wrong, _ := randomToken()
	badProof := callJSON(t, mux, "POST", "/v1/auth/complete", map[string]string{"transaction_id": started.TransactionID, "completion_verifier": wrong}, "")
	if badProof.Code != 400 {
		t.Fatal("accepted callback interception")
	}
	callbackPath := "/v1/auth/callback?" + url.Values{"state": {q.Get("state")}, "code": {"test-code"}}.Encode()
	callback := callJSON(t, mux, "GET", callbackPath, nil, "")
	if callback.Code != 200 {
		t.Fatalf("callback %d %s", callback.Code, callback.Body)
	}
	if strings.Contains(callback.Body.String(), started.TransactionID) || strings.Contains(callback.Body.String(), "access_token") {
		t.Fatal("browser received sensitive result")
	}
	replay := callJSON(t, mux, "GET", callbackPath, nil, "")
	if replay.Code != 400 || p.tokenCalls.Load() != 1 {
		t.Fatal("state replay reached provider exchange")
	}
	// A captured provider code cannot be moved to another valid login state.
	secondStart := callJSON(t, mux, "POST", "/v1/auth/start", map[string]string{"completion_challenge": base64.RawURLEncoding.EncodeToString(challenge[:])}, "")
	var second struct {
		AuthURL string `json:"authorization_url"`
	}
	if secondStart.Code != 200 || json.Unmarshal(secondStart.Body.Bytes(), &second) != nil {
		t.Fatal("second start")
	}
	secondURL, _ := url.Parse(second.AuthURL)
	codeReplayPath := "/v1/auth/callback?" + url.Values{"state": {secondURL.Query().Get("state")}, "code": {"test-code"}}.Encode()
	codeReplay := callJSON(t, mux, "GET", codeReplayPath, nil, "")
	if codeReplay.Code != 400 || p.tokenCalls.Load() != 1 {
		t.Fatal("code replay reached token exchange")
	}
	completed := callJSON(t, mux, "POST", "/v1/auth/complete", completeBody, "")
	if completed.Code != 200 {
		t.Fatalf("complete %d %s", completed.Code, completed.Body)
	}
	if completed.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response cacheable")
	}
	var session SessionResponse
	if json.Unmarshal(completed.Body.Bytes(), &session) != nil || session.TelegramUserID != "9007199254740993" {
		t.Fatal("identity mismatch or float rounding")
	}
	if w := callJSON(t, mux, "POST", "/v1/auth/complete", completeBody, ""); w.Code != 400 {
		t.Fatal("completion replay accepted")
	}
	authReq := httptest.NewRequest("GET", "/", nil)
	authReq.Header.Set("Authorization", "Bearer "+session.AccessToken)
	if id, err := s.Authenticate(authReq); err != nil || id != session.TelegramUserID {
		t.Fatal("service session not authenticated")
	}
	// A user-ID assertion never authenticates without a bearer.
	assertion := httptest.NewRequest("GET", "/", nil)
	assertion.Header.Set("X-Telegram-User-Id", session.TelegramUserID)
	if _, err := s.Authenticate(assertion); err == nil {
		t.Fatal("asserted identity authenticated")
	}
	refreshed := callJSON(t, mux, "POST", "/v1/auth/refresh", map[string]string{"refresh_token": session.RefreshToken}, "")
	if refreshed.Code != 200 {
		t.Fatalf("refresh %d %s", refreshed.Code, refreshed.Body)
	}
	var rotated SessionResponse
	_ = json.Unmarshal(refreshed.Body.Bytes(), &rotated)
	if rotated.RefreshToken == session.RefreshToken || rotated.AccessToken == session.AccessToken {
		t.Fatal("tokens not rotated")
	}
	reuse := callJSON(t, mux, "POST", "/v1/auth/refresh", map[string]string{"refresh_token": session.RefreshToken}, "")
	if reuse.Code != 401 {
		t.Fatal("refresh replay accepted")
	}
	authReq.Header.Set("Authorization", "Bearer "+rotated.AccessToken)
	if _, err := s.Authenticate(authReq); err == nil {
		t.Fatal("refresh replay did not revoke family")
	}
	var plainTokenCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM capsule_access_tokens WHERE encode(token_hash,'escape')=$1`, session.AccessToken).Scan(&plainTokenCount); err != nil || plainTokenCount != 0 {
		t.Fatal("plaintext session token stored")
	}
}

func seededSession(t *testing.T, pool *pgxpool.Pool, id int64) SessionResponse {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	result, err := issueSession(ctx, tx, "https://test-issuer.example", "test-subject", id, "")
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPostgresLogoutIsDeviceScopedAndExpiryEnforced(t *testing.T) {
	pool := testPool(t)
	s := &Service{pool: pool, rates: make(map[string]rateEntry)}
	mux := http.NewServeMux()
	s.Register(mux)
	first := seededSession(t, pool, 123456)
	otherDevice := seededSession(t, pool, 123456)
	authReq := httptest.NewRequest("GET", "/", nil)
	authReq.Header.Set("Authorization", "Bearer "+first.AccessToken)
	if _, err := s.Authenticate(authReq); err != nil {
		t.Fatal("valid access denied")
	}
	loggedOut := callJSON(t, mux, "POST", "/v1/auth/logout", nil, first.AccessToken)
	if loggedOut.Code != 200 {
		t.Fatal("logout failed")
	}
	if _, err := s.Authenticate(authReq); err == nil {
		t.Fatal("logged out access accepted")
	}
	if w := callJSON(t, mux, "POST", "/v1/auth/refresh", map[string]string{"refresh_token": first.RefreshToken}, ""); w.Code != 401 {
		t.Fatal("logged out refresh accepted")
	}
	authReq.Header.Set("Authorization", "Bearer "+otherDevice.AccessToken)
	if _, err := s.Authenticate(authReq); err != nil {
		t.Fatal("logout affected other device")
	}
	hash := sha256.Sum256([]byte(otherDevice.AccessToken))
	if _, err := pool.Exec(context.Background(), `UPDATE capsule_access_tokens SET expires_at=clock_timestamp()-interval '1 millisecond' WHERE token_hash=$1`, hash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(authReq); err == nil {
		t.Fatal("expired access accepted")
	}
}

func TestPostgresConcurrentRefreshReplayRevokesFamily(t *testing.T) {
	pool := testPool(t)
	s := &Service{pool: pool, rates: make(map[string]rateEntry)}
	mux := http.NewServeMux()
	s.Register(mux)
	session := seededSession(t, pool, 456789)
	responses := make(chan *httptest.ResponseRecorder, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			responses <- callJSON(t, mux, "POST", "/v1/auth/refresh", map[string]string{"refresh_token": session.RefreshToken}, "")
		}()
	}
	close(start)
	one, two := <-responses, <-responses
	if one.Code != 200 {
		one, two = two, one
	}
	if one.Code != 200 || two.Code != 401 {
		t.Fatalf("refresh race responses %d/%d", one.Code, two.Code)
	}
	var rotated SessionResponse
	if err := json.Unmarshal(one.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	authReq := httptest.NewRequest("GET", "/", nil)
	authReq.Header.Set("Authorization", "Bearer "+rotated.AccessToken)
	if _, err := s.Authenticate(authReq); err == nil {
		t.Fatal("concurrent refresh replay left family active")
	}
}

func TestPostgresExpiredAndIncorrectCompletionStayUnauthorized(t *testing.T) {
	pool := testPool(t)
	s := &Service{pool: pool, rates: make(map[string]rateEntry)}
	mux := http.NewServeMux()
	s.Register(mux)
	verifier, _ := randomToken()
	v, _ := base64.RawURLEncoding.DecodeString(verifier)
	proof := sha256.Sum256(v)
	id, _ := randomToken()
	state := sha256.Sum256([]byte(id))
	_, err := pool.Exec(context.Background(), `INSERT INTO capsule_auth_transactions(id,completion_challenge,state_hash,pkce_verifier,nonce,expires_at,completed,issuer,subject,telegram_user_id)
        VALUES($1,$2,$3,'','','2000-01-01',true,'https://issuer.test','subject',123)`, id, proof[:], state[:])
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]string{"transaction_id": id, "completion_verifier": verifier}
	if w := callJSON(t, mux, "POST", "/v1/auth/complete", body, ""); w.Code != 400 {
		t.Fatal("expired transaction accepted")
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM capsule_session_families`).Scan(&count); err != nil || count != 0 {
		t.Fatal("session issued for expired transaction")
	}
}
