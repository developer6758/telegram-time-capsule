package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/developer6758/telegram-time-capsule/internal/protocol"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This launches the actual HTTPS executable, with normal CA verification and an
// isolated database schema. The local TLS discovery issuer is a test fixture;
// passing this test does not establish real Telegram Login.
func TestExecutableTLSStartup(t *testing.T) {
	dsn := os.Getenv("CAPSULE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CAPSULE_TEST_DATABASE_URL required for executable integration")
	}
	directory := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	schema := "capsule_binary_" + strings.ToLower(strings.ReplaceAll(protocol.RandomID(), "-", "_"))
	if _, err = db.Exec(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(context.Background(), `DROP SCHEMA "`+schema+`" CASCADE`)
	databaseURL, err := url.Parse(dsn)
	if err != nil || databaseURL.Scheme != "postgres" {
		t.Fatal("test database must be a PostgreSQL URL")
	}
	query := databaseURL.Query()
	query.Set("search_path", schema)
	databaseURL.RawQuery = query.Encode()

	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer.URL, "authorization_endpoint": issuer.URL + "/authorize",
			"token_endpoint": issuer.URL + "/token", "jwks_uri": issuer.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer issuer.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Certificate().Raw})
	private, err := x509.MarshalPKCS8PrivateKey(issuer.TLS.Certificates[0].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificateFile, tlsKeyFile := filepath.Join(directory, "tls.crt"), filepath.Join(directory, "tls.key")
	if os.WriteFile(certificateFile, certificate, 0600) != nil || os.WriteFile(tlsKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600) != nil {
		t.Fatal("TLS fixture write failed")
	}
	signing, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingDER, err := x509.MarshalPKCS8PrivateKey(signing)
	if err != nil {
		t.Fatal(err)
	}
	signingFile, wrappingFile := filepath.Join(directory, "signing.pem"), filepath.Join(directory, "wrapping.json")
	wrapping := make([]byte, 32)
	if _, err = rand.Read(wrapping); err != nil {
		t.Fatal(err)
	}
	wrappingJSON, _ := json.Marshal(map[string]string{"wrap-v1": protocol.Encode(wrapping)})
	if os.WriteFile(signingFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: signingDER}), 0600) != nil || os.WriteFile(wrappingFile, wrappingJSON, 0600) != nil {
		t.Fatal("key fixture write failed")
	}
	binaryFile := filepath.Join(directory, "capsuled")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binaryFile, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("binary build failed: %v %s", err, output)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	command := exec.CommandContext(ctx, binaryFile)
	command.Env = append(os.Environ(),
		"CAPSULE_DATABASE_URL="+databaseURL.String(), "CAPSULE_SERVICE_ID=binary-test",
		"CAPSULE_SIGNING_KID=sign-v1", "CAPSULE_WRAPPING_KID=wrap-v1",
		"CAPSULE_SIGNING_KEY_FILE="+signingFile, "CAPSULE_WRAPPING_KEYS_FILE="+wrappingFile,
		"CAPSULE_TLS_CERT_FILE="+certificateFile, "CAPSULE_TLS_KEY_FILE="+tlsKeyFile,
		"CAPSULE_LISTEN="+address, "CAPSULE_OIDC_ISSUER="+issuer.URL,
		"CAPSULE_OIDC_CLIENT_ID=binary-test-client", "CAPSULE_OIDC_CLIENT_SECRET=binary-test-secret",
		"CAPSULE_OIDC_CALLBACK_URL=https://"+address+"/v1/auth/callback", "SSL_CERT_FILE="+certificateFile)
	var logs bytes.Buffer
	command.Stdout = &logs
	command.Stderr = &logs
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = command.Wait() }()
	client := issuer.Client()
	client.Timeout = time.Second
	endpoint := "https://" + address
	deadline := time.Now().Add(10 * time.Second)
	var response *http.Response
	for time.Now().Before(deadline) {
		response, err = client.Get(endpoint + "/health/ready")
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("HTTPS executable did not start: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"ready":true`)) || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("readiness failed: %d", response.StatusCode)
	}
	response, err = client.Get(endpoint + "/v1/time")
	if err != nil {
		t.Fatal(err)
	}
	var clock map[string]any
	err = json.NewDecoder(response.Body).Decode(&clock)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || clock["clock_healthy"] != true {
		t.Fatal("time endpoint failed")
	}
	response, err = client.Get(endpoint + "/v1/capsules/unknown-capsule")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("unauthenticated request was accepted")
	}
	// Verify the listener does not accidentally accept cleartext HTTP.
	response, err = http.Get("http://" + address + "/health/ready")
	if err == nil {
		response.Body.Close()
		if response.StatusCode == http.StatusOK {
			t.Fatal("cleartext HTTP accepted")
		}
	}
}
