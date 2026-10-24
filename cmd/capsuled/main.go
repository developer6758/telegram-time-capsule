// capsuled runs the authenticated release service. There is no developer auth or clock override.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/developer6758/telegram-time-capsule/internal/auth"
	"github.com/developer6758/telegram-time-capsule/internal/protocol"
	"github.com/developer6758/telegram-time-capsule/internal/server"
	"github.com/developer6758/telegram-time-capsule/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func required(k string) (string, error) {
	v := os.Getenv(k)
	if v == "" {
		return "", fmt.Errorf("missing %s", k)
	}
	return v, nil
}
func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dsn, e := required("CAPSULE_DATABASE_URL")
	if e != nil {
		return e
	}
	db, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return errors.New("invalid database configuration")
	}
	defer db.Close()
	if e = migrations.Apply(ctx, db); e != nil {
		return e
	}
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		return nil
	}
	signingPath, e := required("CAPSULE_SIGNING_KEY_FILE")
	if e != nil {
		return e
	}
	b, e := os.ReadFile(signingPath)
	if e != nil {
		return errors.New("cannot read signing key")
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return errors.New("invalid signing PEM")
	}
	v, e := x509.ParsePKCS8PrivateKey(p.Bytes)
	if e != nil {
		return errors.New("invalid signing key")
	}
	signing, ok := v.(*ecdsa.PrivateKey)
	if !ok || signing.Curve.Params().Name != "P-256" {
		return errors.New("signing key must be P-256")
	}
	wrappingPath, e := required("CAPSULE_WRAPPING_KEYS_FILE")
	if e != nil {
		return e
	}
	b, e = os.ReadFile(wrappingPath)
	if e != nil {
		return errors.New("cannot read wrapping keyring")
	}
	encoded := map[string]string{}
	if protocol.StrictJSON(b, &encoded) != nil {
		return errors.New("invalid wrapping keyring")
	}
	wrapping := map[string][]byte{}
	for k, v := range encoded {
		key, e := protocol.Decode(v, 32, 32)
		if e != nil {
			return errors.New("invalid wrapping key")
		}
		wrapping[k] = key
	}
	issuer, e := required("CAPSULE_OIDC_ISSUER")
	if e != nil {
		return e
	}
	client, e := required("CAPSULE_OIDC_CLIENT_ID")
	if e != nil {
		return e
	}
	secret, e := required("CAPSULE_OIDC_CLIENT_SECRET")
	if e != nil {
		return e
	}
	callback, e := required("CAPSULE_OIDC_CALLBACK_URL")
	if e != nil {
		return e
	}
	a, e := auth.New(ctx, db, auth.Config{Issuer: issuer, ClientID: client, ClientSecret: secret, CallbackURL: callback})
	if e != nil {
		return fmt.Errorf("OIDC setup failed: %w", e)
	}
	s, e := server.New(db, server.Config{ServiceID: os.Getenv("CAPSULE_SERVICE_ID"), SigningKeyID: os.Getenv("CAPSULE_SIGNING_KID"), SigningKey: signing, WrappingKeyID: os.Getenv("CAPSULE_WRAPPING_KID"), WrappingKeys: wrapping}, a.Authenticate)
	if e != nil {
		return e
	}
	mux := http.NewServeMux()
	s.Register(mux)
	a.Register(mux)
	cert, e := required("CAPSULE_TLS_CERT_FILE")
	if e != nil {
		return e
	}
	tlskey, e := required("CAPSULE_TLS_KEY_FILE")
	if e != nil {
		return e
	}
	listen := os.Getenv("CAPSULE_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:8443"
	}
	host, _, e := net.SplitHostPort(listen)
	if e != nil || strings.TrimSpace(host) == "" {
		return errors.New("explicit listen host required")
	}
	h := &http.Server{Addr: listen, Handler: s.Middleware(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	errch := make(chan error, 1)
	go func() { errch <- h.ListenAndServeTLS(cert, tlskey) }()
	log.Print("capsule service started with TLS; request bodies and credentials are not logged")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			return h.Shutdown(shutdown)
		case e := <-errch:
			if errors.Is(e, http.ErrServerClosed) {
				return nil
			}
			return e
		case <-ticker.C:
			req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/health/ready", nil)
			if e != nil {
				return e
			}
			w := &healthSink{header: http.Header{}}
			mux.ServeHTTP(w, req)
		}
	}
}

type healthSink struct{ header http.Header }

func (w *healthSink) Header() http.Header         { return w.header }
func (w *healthSink) Write(b []byte) (int, error) { return len(b), nil }
func (w *healthSink) WriteHeader(int)             {}
func main() {
	if e := run(); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
