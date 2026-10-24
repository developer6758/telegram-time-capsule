package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratedIOSConfigurationAndNoKeyOverwrite(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "keys")
	previousArguments := os.Args
	t.Cleanup(func() { os.Args = previousArguments })
	os.Args = []string{"capsulectl", "init-keys", directory}
	if err := run(); err != nil {
		t.Fatal(err)
	}
	var configuration struct {
		Service          string            `json:"service"`
		BaseURL          string            `json:"base_url"`
		VerificationKeys map[string]string `json:"verification_keys"`
	}
	raw, err := os.ReadFile(filepath.Join(directory, "ios-configuration.json"))
	if err != nil || json.Unmarshal(raw, &configuration) != nil {
		t.Fatal("missing iOS configuration")
	}
	der, err := base64.StdEncoding.Strict().DecodeString(configuration.VerificationKeys["sign-v1"])
	if err != nil {
		t.Fatal("iOS trust key is not standard base64")
	}
	public, err := x509.ParsePKIXPublicKey(der)
	key, ok := public.(*ecdsa.PublicKey)
	if err != nil || !ok || key.Curve != elliptic.P256() || configuration.Service != "time-capsule-dev" || configuration.BaseURL != "https://capsule.example.invalid" {
		t.Fatal("invalid iOS trust configuration")
	}
	before, err := os.ReadFile(filepath.Join(directory, "signing.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if run() == nil {
		t.Fatal("existing key directory was overwritten")
	}
	after, err := os.ReadFile(filepath.Join(directory, "signing.pem"))
	if err != nil || string(before) != string(after) {
		t.Fatal("signing key changed on refused initialization")
	}
}
