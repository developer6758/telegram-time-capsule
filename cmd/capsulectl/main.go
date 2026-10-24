package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/developer6758/telegram-time-capsule/internal/protocol"
	"os"
	"path/filepath"
)

func run() error {
	if len(os.Args) != 3 || os.Args[1] != "init-keys" {
		return fmt.Errorf("usage: capsulectl init-keys DIRECTORY (new directory only)")
	}
	dir := os.Args[2]
	if e := os.Mkdir(dir, 0700); e != nil {
		return e
	}
	sign, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	der, e := x509.MarshalPKCS8PrivateKey(sign)
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "signing.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); e != nil {
		return e
	}
	wrap := make([]byte, 32)
	if _, e = rand.Read(wrap); e != nil {
		return e
	}
	b, _ := json.MarshalIndent(map[string]string{"wrap-v1": protocol.Encode(wrap)}, "", "  ")
	if e = os.WriteFile(filepath.Join(dir, "wrapping.json"), b, 0600); e != nil {
		return e
	}
	pub, e := x509.MarshalPKIXPublicKey(&sign.PublicKey)
	if e != nil {
		return e
	}
	b, _ = json.MarshalIndent(map[string]any{"service_id": "time-capsule-dev", "signing_keys": map[string]string{"sign-v1": protocol.Encode(pub)}}, "", "  ")
	if e = os.WriteFile(filepath.Join(dir, "public-trust.json"), b, 0644); e != nil {
		return e
	}
	b, _ = json.MarshalIndent(map[string]any{
		"service": "time-capsule-dev", "base_url": "https://capsule.example.invalid",
		"verification_keys": map[string]string{"sign-v1": base64.StdEncoding.EncodeToString(pub)},
	}, "", "  ")
	if e = os.WriteFile(filepath.Join(dir, "ios-configuration.json"), b, 0644); e != nil {
		return e
	}
	fmt.Println("Generated persistent signing/wrapping keys, public-trust.json and ios-configuration.json; set the owned HTTPS origin and retain private files securely.")
	return nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
