// Package e2e verifies the shipping authentication and capsule HTTP handlers together.
// Only the external identity provider is simulated; all service sessions, authorization,
// encryption, database transactions and deadlines use their real implementations.
package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/developer6758/telegram-time-capsule/internal/auth"
	"github.com/developer6758/telegram-time-capsule/internal/protocol"
	"github.com/developer6758/telegram-time-capsule/internal/server"
	"github.com/developer6758/telegram-time-capsule/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

const clientID = "capsule-e2e-client"
const clientSecret = "test-only-backend-held-secret"

type authorizationCode struct{ id, nonce, challenge, redirect string }

// testIssuer performs a real RSA-signed OIDC code exchange with PKCE. Its account
// picker is a deterministic test fixture, not an application authentication mode.
type testIssuer struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	codes  map[string]authorizationCode
}

func newIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &testIssuer{key: key, codes: map[string]authorizationCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "use": "sig", "kid": "e2e-test", "alg": "RS256", "n": protocol.Encode(key.N.Bytes()), "e": protocol.Encode(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		id := q.Get("test_identity")
		if !protocol.ValidID(id) || q.Get("client_id") != clientID || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
			http.Error(w, "invalid test authorization", 400)
			return
		}
		callback, err := url.Parse(q.Get("redirect_uri"))
		if err != nil || callback.Scheme != "https" {
			http.Error(w, "invalid test callback", 400)
			return
		}
		code := protocol.RandomID()
		p.mu.Lock()
		p.codes[code] = authorizationCode{id, q.Get("nonce"), q.Get("code_challenge"), callback.String()}
		p.mu.Unlock()
		params := callback.Query()
		params.Set("code", code)
		params.Set("state", q.Get("state"))
		callback.RawQuery = params.Encode()
		http.Redirect(w, r, callback.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", 400)
			return
		}
		id, secret, basic := r.BasicAuth()
		if !basic {
			id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		p.mu.Lock()
		grant, found := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		p.mu.Unlock()
		pkce := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !found || id != clientID || secret != clientSecret || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != grant.redirect || protocol.Encode(pkce[:]) != grant.challenge {
			w.WriteHeader(400)
			writeJSON(w, map[string]any{"error": "invalid_grant"})
			return
		}
		claims, err := json.Marshal(map[string]any{"iss": p.server.URL, "sub": "opaque-subject-" + grant.id, "id": grant.id, "aud": clientID, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "nonce": grant.nonce})
		if err != nil {
			http.Error(w, "claims", 500)
			return
		}
		signing := protocol.Encode([]byte(`{"alg":"RS256","kid":"e2e-test","typ":"JWT"}`)) + "." + protocol.Encode(claims)
		digest := sha256.Sum256([]byte(signing))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			http.Error(w, "signing", 500)
			return
		}
		writeJSON(w, map[string]any{"access_token": "test-provider-token-never-used-as-service-token", "token_type": "Bearer", "expires_in": 60, "id_token": signing + "." + protocol.Encode(signature)})
	})
	p.server = httptest.NewTLSServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func isolatedDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CAPSULE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CAPSULE_TEST_DATABASE_URL is required for real PostgreSQL HTTP integration")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "e2e_" + strings.ToLower(strings.ReplaceAll(protocol.RandomID(), "-", "_"))
	if _, err = admin.Exec(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(); _, _ = admin.Exec(ctx, `DROP SCHEMA "`+schema+`" CASCADE`); admin.Close() })
	if err := migrations.Apply(ctx, db); err != nil {
		t.Fatal(err)
	}
	return db
}

type apiClient struct {
	client *http.Client
	origin string
}

func (a apiClient) request(t *testing.T, method, path, token, idempotency string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	r, err := http.NewRequest(method, a.origin+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if idempotency != "" {
		r.Header.Set("Idempotency-Key", idempotency)
	}
	// A deliberately impossible client clock must have no influence on release.
	r.Header.Set("X-Client-Time", "9999999999999999")
	response, err := a.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 100001))
	if err != nil || len(data) > 100000 {
		t.Fatal("invalid bounded API response")
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("API response may be cached")
	}
	return response.StatusCode, data
}

func decodeJSON[T any](t *testing.T, data []byte) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func (a apiClient) login(t *testing.T, identity string) auth.SessionResponse {
	t.Helper()
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		t.Fatal(err)
	}
	challenge := sha256.Sum256(verifierBytes)
	status, data := a.request(t, "POST", "/v1/auth/start", "", "", map[string]string{"completion_challenge": protocol.Encode(challenge[:])})
	if status != 200 {
		t.Fatalf("start status %d", status)
	}
	started := decodeJSON[struct {
		TransactionID    string `json:"transaction_id"`
		AuthorizationURL string `json:"authorization_url"`
	}](t, data)
	proof := map[string]string{"transaction_id": started.TransactionID, "completion_verifier": protocol.Encode(verifierBytes)}
	status, data = a.request(t, "POST", "/v1/auth/complete", "", "", proof)
	if status != 409 || !bytes.Contains(data, []byte(`"login_pending"`)) {
		t.Fatal("login completed before browser authorization")
	}
	flow, err := url.Parse(started.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	q := flow.Query()
	q.Set("test_identity", identity)
	flow.RawQuery = q.Encode()
	response, err := a.client.Get(flow.String())
	if err != nil {
		t.Fatal(err)
	}
	callback, err := io.ReadAll(io.LimitReader(response.Body, 10000))
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || bytes.Contains(callback, []byte("access_token")) || bytes.Contains(callback, []byte(started.TransactionID)) {
		t.Fatal("unsafe browser callback")
	}
	status, data = a.request(t, "POST", "/v1/auth/complete", "", "", proof)
	if status != 200 {
		t.Fatalf("complete status %d", status)
	}
	session := decodeJSON[auth.SessionResponse](t, data)
	if session.TelegramUserID != identity || session.AccessToken == "" || session.RefreshToken == "" || session.ExpiresMS <= time.Now().UnixMilli() {
		t.Fatal("invalid verified session contract")
	}
	status, _ = a.request(t, "POST", "/v1/auth/complete", "", "", proof)
	if status != 400 {
		t.Fatal("login completion proof replay accepted")
	}
	return session
}

func TestHTTPSVerifiedSessionsEnforceCapsuleDeadline(t *testing.T) {
	db := isolatedDatabase(t)
	issuer := newIssuer(t)
	mux := http.NewServeMux()
	var handler atomic.Pointer[http.Handler]
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if current := handler.Load(); current != nil {
			(*current).ServeHTTP(w, r)
		} else {
			http.Error(w, "test service initializing", http.StatusServiceUnavailable)
		}
	}))
	api.StartTLS()
	t.Cleanup(api.Close)
	login, err := auth.New(context.Background(), db, auth.Config{Issuer: issuer.server.URL, ClientID: clientID, ClientSecret: clientSecret, CallbackURL: api.URL + "/v1/auth/callback", AllowedAlgorithms: []string{"RS256"}, HTTPClient: issuer.server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrapping := make([]byte, 32)
	if _, err := rand.Read(wrapping); err != nil {
		t.Fatal(err)
	}
	capsules, err := server.New(db, server.Config{ServiceID: "e2e", SigningKeyID: "s1", SigningKey: signing, WrappingKeyID: "w1", WrappingKeys: map[string][]byte{"w1": wrapping}}, login.Authenticate)
	if err != nil {
		t.Fatal(err)
	}
	login.Register(mux)
	capsules.Register(mux)
	combined := capsules.Middleware(mux)
	handler.Store(&combined)
	trust := x509.NewCertPool()
	trust.AddCert(api.Certificate())
	trust.AddCert(issuer.server.Certificate())
	client := apiClient{client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS12}}, Timeout: 10 * time.Second}, origin: api.URL}
	t.Cleanup(client.client.CloseIdleConnections)
	status, _ := client.request(t, "POST", "/v1/capsules/reserve", "", protocol.RandomID(), struct{}{})
	if status != 401 {
		t.Fatal("capsule route did not require issued service session")
	}
	sender := client.login(t, "9007199254740993")
	recipient := client.login(t, "9007199254740995")
	stranger := client.login(t, "9007199254740997")
	reserve := server.ReserveRequest{RecipientID: recipient.TelegramUserID, DurationS: 2, Layout: protocol.Layout{V: 1, Samples: []protocol.Sample{{ConstraintEM: 14, WidthEM: 12, HeightEM: 2.5}, {ConstraintEM: 20, WidthEM: 18, HeightEM: 1.25}, {ConstraintEM: 28, WidthEM: 18, HeightEM: 1.25}}}}
	status, data := client.request(t, "POST", "/v1/capsules/reserve", sender.AccessToken, protocol.RandomID(), reserve)
	if status != 200 {
		t.Fatalf("reserve status %d", status)
	}
	reserved := decodeJSON[server.ReserveResponse](t, data)
	binding, err := protocol.Decode(reserved.BindingB64URL, 1, 4096)
	if err != nil {
		t.Fatal(err)
	}
	bound := decodeJSON[protocol.Binding](t, binding)
	if bound.SenderID != sender.TelegramUserID || bound.RecipientID != recipient.TelegramUserID {
		t.Fatal("verified principal was not bound losslessly")
	}
	text := "Private synthetic content 👩‍🚀 é שלום مرحبا " + protocol.RandomID()
	payload, err := json.Marshal(map[string]any{"v": 1, "text": text, "entities": []any{map[string]any{"type": "bold", "offset": 0, "length": 7}}})
	if err != nil {
		t.Fatal(err)
	}
	padded := make([]byte, 512)
	if _, err := rand.Read(padded); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(padded, uint32(len(payload)))
	copy(padded[4:], payload)
	contentKey, nonce := make([]byte, 32), make([]byte, 12)
	if _, err := rand.Read(contentKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(contentKey)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	encrypted := gcm.Seal(nil, nonce, padded, protocol.PayloadAAD(binding))
	sealRequest := server.SealRequest{BindingSHA256: protocol.Digest(binding), Nonce: protocol.Encode(nonce), Ciphertext: protocol.Encode(encrypted[:512]), Tag: protocol.Encode(encrypted[512:]), ContentKey: protocol.Encode(contentKey)}
	path := "/v1/capsules/" + reserved.CapsuleID
	status, data = client.request(t, "POST", path+"/seal", sender.AccessToken, protocol.RandomID(), sealRequest)
	if status != 200 {
		t.Fatalf("seal status %d", status)
	}
	sealed := decodeJSON[server.SealResponse](t, data)
	if strings.Contains(sealed.Carrier, text) || strings.Contains(sealed.Carrier, sealRequest.ContentKey) || strings.Contains(sealed.Carrier, base64.StdEncoding.EncodeToString(contentKey)) {
		t.Fatal("plaintext or key entered carrier")
	}
	descriptorBytes, err := protocol.Decode(sealed.DescriptorB64URL, 1, 4096)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := protocol.Decode(sealed.SignatureDERB64URL, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(protocol.SignatureInput(sealed.KID, descriptorBytes))
	if !ecdsa.VerifyASN1(&signing.PublicKey, digest[:], signature) {
		t.Fatal("descriptor signature failed")
	}
	descriptor := decodeJSON[protocol.Descriptor](t, descriptorBytes)
	if descriptor.BindingSHA256 != protocol.Digest(binding) || descriptor.PayloadSHA256 != protocol.Digest(append(append(bytes.Clone(nonce), encrypted[:512]...), encrypted[512:]...)) || descriptor.UnlockMS != descriptor.CreatedMS+2000 {
		t.Fatal("signed immutable capsule contract mismatch")
	}
	open := server.ReleaseRequest{OpenOperationID: protocol.RandomID(), KnownRevision: sealed.Revision}
	for _, token := range []string{sender.AccessToken, recipient.AccessToken} {
		status, data = client.request(t, "POST", path+"/release", token, "", open)
		if status != 409 || !bytes.Contains(data, []byte(`"not_ready"`)) || bytes.Contains(data, []byte(`"content_key"`)) {
			t.Fatal("issued participant obtained early release")
		}
	}
	status, data = client.request(t, "POST", path+"/release", stranger.AccessToken, "", open)
	if status != 404 || bytes.Contains(data, []byte(`"content_key"`)) {
		t.Fatal("stranger obtained key or capsule existence")
	}
	status, data = client.request(t, "GET", path, recipient.AccessToken, "", nil)
	if status != 200 || bytes.Contains(data, []byte(`"content_key"`)) || bytes.Contains(data, []byte(text)) {
		t.Fatal("metadata disclosed secret")
	}
	// Wait for the real persisted deadline; never modify DB time or unlock_ms.
	if delay := time.Until(time.UnixMilli(descriptor.UnlockMS + 10)); delay > 0 {
		time.Sleep(delay)
	}
	status, data = client.request(t, "POST", path+"/release", recipient.AccessToken, "", open)
	if status != 200 {
		t.Fatalf("authorized deadline release status %d", status)
	}
	released := decodeJSON[server.ReleaseResponse](t, data)
	if released.ServerMS < descriptor.UnlockMS || released.BindingB64URL != reserved.BindingB64URL || released.ContentKey != sealRequest.ContentKey {
		t.Fatal("release contract mismatch")
	}
	releasedKey, err := protocol.Decode(released.ContentKey, 32, 32)
	if err != nil {
		t.Fatal(err)
	}
	releasedNonce, err := protocol.Decode(released.Nonce, 12, 12)
	if err != nil {
		t.Fatal(err)
	}
	releasedCT, err := protocol.Decode(released.Ciphertext, 512, 65536)
	if err != nil {
		t.Fatal(err)
	}
	releasedTag, err := protocol.Decode(released.Tag, 16, 16)
	if err != nil {
		t.Fatal(err)
	}
	decryptBlock, err := aes.NewCipher(releasedKey)
	if err != nil {
		t.Fatal(err)
	}
	decryptGCM, err := cipher.NewGCM(decryptBlock)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := decryptGCM.Open(nil, releasedNonce, append(releasedCT, releasedTag...), protocol.PayloadAAD(binding))
	if err != nil {
		t.Fatal("authorized authenticated decryption failed")
	}
	length := int(binary.BigEndian.Uint32(opened[:4]))
	if length > len(opened)-4 || !bytes.Equal(opened[4:4+length], payload) {
		t.Fatal("exact Unicode/entity payload was not preserved")
	}
	status, _ = client.request(t, "POST", path+"/revoke", sender.AccessToken, protocol.RandomID(), struct{}{})
	if status != 200 {
		t.Fatal("sender could not revoke")
	}
	status, data = client.request(t, "POST", path+"/release", recipient.AccessToken, "", open)
	if status != 410 || bytes.Contains(data, []byte(`"content_key"`)) {
		t.Fatal("idempotent retry bypassed revocation")
	}
	status, _ = client.request(t, "POST", "/v1/auth/logout", recipient.AccessToken, "", struct{}{})
	if status != 200 {
		t.Fatal("recipient could not log out")
	}
	status, _ = client.request(t, "GET", path, recipient.AccessToken, "", nil)
	if status != 401 {
		t.Fatal("logout did not revoke actual service token")
	}
}
