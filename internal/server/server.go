package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/developer6758/telegram-time-capsule/internal/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Config struct {
	ServiceID, SigningKeyID, WrappingKeyID string
	SigningKey                             *ecdsa.PrivateKey
	WrappingKeys                           map[string][]byte
}
type Server struct {
	DB           *pgxpool.Pool
	Config       Config
	Authenticate func(*http.Request) (string, error)
	clock        Clock
	rates        *limiter
}
type Clock struct {
	mu         sync.Mutex
	sample     time.Time
	databaseMS int64
	unhealthy  bool
}

func (c *Clock) Check(ms int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if !c.sample.IsZero() {
		expected := c.databaseMS + now.Sub(c.sample).Milliseconds()
		if math.Abs(float64(ms-expected)) > 2000 {
			c.unhealthy = true
		}
	}
	c.sample = now
	c.databaseMS = ms
	return !c.unhealthy
}
func (c *Clock) Healthy() bool { c.mu.Lock(); defer c.mu.Unlock(); return !c.unhealthy }
func New(db *pgxpool.Pool, c Config, authenticate func(*http.Request) (string, error)) (*Server, error) {
	if !protocol.ValidKeyID(c.SigningKeyID) || !protocol.ValidKeyID(c.WrappingKeyID) || !protocol.ValidOpaque(c.ServiceID) || c.SigningKey == nil || c.SigningKey.Curve != elliptic.P256() || len(c.WrappingKeys[c.WrappingKeyID]) != 32 {
		return nil, errors.New("invalid service keys/config")
	}
	for k, v := range c.WrappingKeys {
		if !protocol.ValidKeyID(k) || len(v) != 32 {
			return nil, errors.New("invalid wrapping keyring")
		}
	}
	return &Server{DB: db, Config: c, Authenticate: authenticate, rates: &limiter{entries: map[string]rateEntry{}}}, nil
}
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) { write(w, 200, map[string]bool{"live": true}) })
	mux.HandleFunc("GET /health/ready", s.ready)
	mux.HandleFunc("GET /v1/time", s.serverTime)
	mux.HandleFunc("POST /v1/capsules/reserve", s.authorized(s.reserve))
	mux.HandleFunc("POST /v1/capsules/metadata-batch", s.authorized(s.batch))
	mux.HandleFunc("GET /v1/capsules/{id}", s.authorized(s.metadata))
	mux.HandleFunc("POST /v1/capsules/{id}/seal", s.authorized(s.seal))
	mux.HandleFunc("POST /v1/capsules/{id}/release", s.authorized(s.release))
	mux.HandleFunc("POST /v1/capsules/{id}/revoke", s.authorized(s.revoke))
	mux.HandleFunc("POST /v1/capsules/{id}/hide", s.authorized(s.hide))
	mux.HandleFunc("POST /v1/capsules/{id}/opened", s.authorized(s.opened))
}

// Middleware is used for both capsule and OIDC endpoints. Forwarding headers are intentionally not trusted.
func (s *Server) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !s.rates.allow(host) {
			w.Header().Set("Retry-After", "2")
			fail(w, 429, "rate_limited", true, 0)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 100000)
		next.ServeHTTP(w, r)
	})
}
func (s *Server) authorized(f func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Authenticate == nil {
			fail(w, 401, "unauthorized", false, 0)
			return
		}
		id, e := s.Authenticate(r)
		if e != nil || !protocol.ValidID(id) {
			fail(w, 401, "unauthorized", false, 0)
			return
		}
		if r.PathValue("id") != "" && !protocol.ValidOpaque(r.PathValue("id")) {
			fail(w, 404, "not_found", false, 0)
			return
		}
		f(w, r, id)
	}
}
func read(r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return errors.New("content type")
	}
	b, e := io.ReadAll(r.Body)
	if e != nil {
		return e
	}
	return protocol.StrictJSON(b, v)
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, code string, retry bool, serverMS int64) {
	write(w, status, map[string]any{"code": code, "retryable": retry, "server_ms": serverMS, "request_id": protocol.RandomID()})
}
func dbtime(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (int64, error) {
	var n int64
	e := q.QueryRow(ctx, "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint").Scan(&n)
	return n, e
}
func (s *Server) begin(w http.ResponseWriter, r *http.Request) (pgx.Tx, int64, bool) {
	tx, e := s.DB.Begin(r.Context())
	if e != nil {
		fail(w, 503, "unavailable", true, 0)
		return nil, 0, false
	}
	n, e := dbtime(r.Context(), tx)
	if e != nil {
		_ = tx.Rollback(r.Context())
		fail(w, 503, "unavailable", true, 0)
		return nil, 0, false
	}
	if !s.clock.Check(n) {
		_ = tx.Rollback(r.Context())
		fail(w, 503, "clock_unhealthy", true, n)
		return nil, n, false
	}
	return tx, n, true
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(r.Context(), "SELECT DISTINCT wrapping_kid FROM capsules WHERE state='sealed'")
	if err != nil {
		fail(w, 503, "unavailable", true, 0)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var kid string
		if rows.Scan(&kid) != nil || len(s.Config.WrappingKeys[kid]) != 32 {
			fail(w, 503, "missing_wrapping_key", false, 0)
			return
		}
	}
	if rows.Err() != nil {
		fail(w, 503, "unavailable", true, 0)
		return
	}
	n, e := dbtime(r.Context(), s.DB)
	if e != nil || !s.clock.Check(n) {
		fail(w, 503, "unavailable", true, 0)
		return
	}
	write(w, 200, map[string]any{"ready": true, "clock_healthy": true})
}
func (s *Server) serverTime(w http.ResponseWriter, r *http.Request) {
	n, e := dbtime(r.Context(), s.DB)
	if e != nil || !s.clock.Check(n) {
		fail(w, 503, "clock_unhealthy", true, 0)
		return
	}
	write(w, 200, map[string]any{"server_ms": n, "clock_healthy": true})
}
func key(r *http.Request) (string, bool) {
	k := r.Header.Get("Idempotency-Key")
	return k, protocol.ValidOpaque(k) && len(k) >= 16
}
func requestDigest(v any) []byte { b, _ := json.Marshal(v); h := sha256.Sum256(b); return h[:] }
func idem(ctx context.Context, tx pgx.Tx, principal, op, k string, digest []byte) ([]byte, error) {
	// A transaction-scoped advisory lock serializes a scoped mutation before the unique record exists.
	_, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", principal+"\x1f"+op+"\x1f"+k)
	if e != nil {
		return nil, e
	}
	var d, b []byte
	e = tx.QueryRow(ctx, "SELECT request_digest,response FROM capsule_idempotency WHERE principal=$1 AND operation=$2 AND key=$3", principal, op, k).Scan(&d, &b)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(d, digest) {
		return nil, errConflict
	}
	return b, nil
}

var errConflict = errors.New("idempotency conflict")

func saveIdem(ctx context.Context, tx pgx.Tx, p, op, k string, d []byte, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO capsule_idempotency(principal,operation,key,request_digest,response) VALUES($1,$2,$3,$4,$5)", p, op, k, d, b)
	return e
}
func finish(w http.ResponseWriter, r *http.Request, tx pgx.Tx, n int64, v any) {
	if e := tx.Commit(r.Context()); e != nil {
		fail(w, 503, "unavailable", true, n)
		return
	}
	write(w, 200, v)
}
func internal(w http.ResponseWriter, n int64) { fail(w, 503, "unavailable", true, n) }

type ReserveRequest struct {
	RecipientID string          `json:"recipient_id"`
	DurationS   int64           `json:"duration_s"`
	Layout      protocol.Layout `json:"layout"`
}
type ReserveResponse struct {
	CapsuleID     string `json:"capsule_id"`
	BindingB64URL string `json:"binding_b64url"`
	ExpiresMS     int64  `json:"expires_ms"`
	ServerMS      int64  `json:"server_ms"`
}

func (s *Server) reserve(w http.ResponseWriter, r *http.Request, p string) {
	var q ReserveRequest
	k, ok := key(r)
	if !ok || read(r, &q) != nil || !protocol.ValidID(q.RecipientID) || q.RecipientID == p || q.DurationS < 1 || q.DurationS > protocol.MaxDuration || q.Layout.Validate() != nil {
		fail(w, 400, "invalid_request", false, 0)
		return
	}
	tx, n, ok := s.begin(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	d := requestDigest(q)
	cached, e := idem(r.Context(), tx, p, "reserve", k, d)
	if errors.Is(e, errConflict) {
		fail(w, 409, "idempotency_conflict", false, n)
		return
	}
	if e != nil {
		internal(w, n)
		return
	}
	if cached != nil {
		finish(w, r, tx, n, json.RawMessage(cached))
		return
	}
	id := protocol.RandomID()
	b, _ := json.Marshal(protocol.Binding{V: 1, Service: s.Config.ServiceID, CapsuleID: id, SenderID: p, RecipientID: q.RecipientID, DurationS: q.DurationS, Layout: q.Layout})
	v := ReserveResponse{id, protocol.Encode(b), n + 600000, n}
	_, e = tx.Exec(r.Context(), "INSERT INTO capsules(id,sender_id,recipient_id,binding,binding_sha256,duration_s,expires_at,state) VALUES($1,$2,$3,$4,$5,$6,to_timestamp($7::double precision/1000),'reserved')", id, p, q.RecipientID, b, protocol.Digest(b), q.DurationS, v.ExpiresMS)
	if e != nil {
		internal(w, n)
		return
	}
	_, e = tx.Exec(r.Context(), "INSERT INTO capsule_participants(capsule_id,user_id) VALUES($1,$2),($1,$3)", id, p, q.RecipientID)
	if e != nil || saveIdem(r.Context(), tx, p, "reserve", k, d, v) != nil {
		internal(w, n)
		return
	}
	finish(w, r, tx, n, v)
}

type SealRequest struct {
	BindingSHA256 string `json:"binding_sha256"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
	Tag           string `json:"tag"`
	ContentKey    string `json:"content_key"`
}
type SealResponse struct {
	Carrier            string `json:"carrier"`
	DescriptorB64URL   string `json:"descriptor_b64url"`
	SignatureDERB64URL string `json:"signature_der_b64url"`
	KID                string `json:"kid"`
	Revision           int64  `json:"revision"`
	ServerMS           int64  `json:"server_ms"`
}

func (s *Server) seal(w http.ResponseWriter, r *http.Request, p string) {
	var q SealRequest
	k, ok := key(r)
	if !ok || read(r, &q) != nil {
		fail(w, 400, "invalid_request", false, 0)
		return
	}
	nonce, e1 := protocol.Decode(q.Nonce, 12, 12)
	ct, e2 := protocol.Decode(q.Ciphertext, 512, 65536)
	tag, e3 := protocol.Decode(q.Tag, 16, 16)
	content, e4 := protocol.Decode(q.ContentKey, 32, 32)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !protocol.ValidBucket(len(ct)) {
		fail(w, 400, "invalid_ciphertext", false, 0)
		return
	}
	defer clear(content)
	tx, n, ok := s.begin(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	id := r.PathValue("id")
	var sender, state, bhash string
	var binding, seald, descriptor, sig []byte
	var expires int64
	var rev int64
	var kid *string
	e := tx.QueryRow(r.Context(), "SELECT sender_id,state,binding,binding_sha256,floor(extract(epoch FROM expires_at)*1000)::bigint,seal_digest,descriptor,signature,kid,revision FROM capsules WHERE id=$1 FOR UPDATE", id).Scan(&sender, &state, &binding, &bhash, &expires, &seald, &descriptor, &sig, &kid, &rev)
	if errors.Is(e, pgx.ErrNoRows) || e == nil && sender != p {
		fail(w, 404, "not_found", false, n)
		return
	}
	if e != nil {
		internal(w, n)
		return
	}
	if state == "revoked" {
		fail(w, 410, "unavailable", false, n)
		return
	}
	d := requestDigest(q)
	cached, e := idem(r.Context(), tx, p, "seal:"+id, k, d)
	if errors.Is(e, errConflict) {
		fail(w, 409, "idempotency_conflict", false, n)
		return
	}
	if e != nil {
		internal(w, n)
		return
	}
	if cached != nil {
		finish(w, r, tx, n, json.RawMessage(cached))
		return
	}
	if state == "sealed" {
		if !bytes.Equal(seald, d) {
			fail(w, 409, "already_sealed", false, n)
			return
		}
		v := SealResponse{protocol.CarrierPrefix + *kid + "." + protocol.Encode(descriptor) + "." + protocol.Encode(sig), protocol.Encode(descriptor), protocol.Encode(sig), *kid, rev, n}
		finish(w, r, tx, n, v)
		return
	}
	// Sealing assigns its deadline after blocking row/idempotency locks have been acquired.
	n, e = dbtime(r.Context(), tx)
	if e != nil || !s.clock.Check(n) {
		fail(w, 503, "clock_unhealthy", true, n)
		return
	}
	if n >= expires {
		fail(w, 410, "reservation_expired", false, n)
		return
	}
	if q.BindingSHA256 != bhash {
		fail(w, 409, "binding_mismatch", false, n)
		return
	}
	var b protocol.Binding
	if protocol.StrictJSON(binding, &b) != nil {
		internal(w, n)
		return
	}
	payload := append(append(append([]byte{}, nonce...), ct...), tag...)
	desc := protocol.Descriptor{V: 1, Service: b.Service, CapsuleID: id, SenderID: b.SenderID, RecipientID: b.RecipientID, CreatedMS: n, UnlockMS: n + b.DurationS*1000, DurationS: b.DurationS, BindingSHA256: bhash, PayloadSHA256: protocol.Digest(payload), Layout: b.Layout}
	descriptor, sig, carrier, e := protocol.Sign(s.Config.SigningKey, s.Config.SigningKeyID, desc)
	if e != nil {
		internal(w, n)
		return
	}
	wrapped, wn, e := protocol.Wrap(s.Config.WrappingKeys[s.Config.WrappingKeyID], content, s.Config.WrappingKeyID, id)
	if e != nil {
		internal(w, n)
		return
	}
	_, e = tx.Exec(r.Context(), "UPDATE capsules SET state='sealed',created_ms=$2,unlock_ms=$3,descriptor=$4,signature=$5,kid=$6,nonce=$7,ciphertext=$8,tag=$9,wrapped_key=$10,wrapping_kid=$11,wrapping_nonce=$12,seal_digest=$13,revision=revision+1 WHERE id=$1", id, n, desc.UnlockMS, descriptor, sig, s.Config.SigningKeyID, nonce, ct, tag, wrapped, s.Config.WrappingKeyID, wn, d)
	v := SealResponse{carrier, protocol.Encode(descriptor), protocol.Encode(sig), s.Config.SigningKeyID, rev + 1, n}
	if e != nil || saveIdem(r.Context(), tx, p, "seal:"+id, k, d, v) != nil {
		internal(w, n)
		return
	}
	finish(w, r, tx, n, v)
}

type ReleaseRequest struct {
	OpenOperationID string `json:"open_operation_id"`
	KnownRevision   int64  `json:"known_revision"`
}
type ReleaseResponse struct {
	BindingB64URL string `json:"binding_b64url"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
	Tag           string `json:"tag"`
	ContentKey    string `json:"content_key"`
	ServerMS      int64  `json:"server_ms"`
	Revision      int64  `json:"revision"`
}

func (s *Server) release(w http.ResponseWriter, r *http.Request, p string) {
	var q ReleaseRequest
	if read(r, &q) != nil || !protocol.ValidOpaque(q.OpenOperationID) || len(q.OpenOperationID) < 16 || q.KnownRevision < 0 {
		fail(w, 400, "invalid_request", false, 0)
		return
	}
	tx, n, ok := s.begin(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	id := r.PathValue("id")
	var state string
	var b, nonce, ct, tag, wrapped, wn []byte
	var wkid *string
	var unlock *int64
	var rev int64
	// Lock ordering is always capsule, then participant. Revocation uses the same order.
	e := tx.QueryRow(r.Context(), "SELECT state,binding,nonce,ciphertext,tag,wrapped_key,wrapping_kid,wrapping_nonce,unlock_ms,revision FROM capsules WHERE id=$1 AND (sender_id=$2 OR recipient_id=$2) FOR UPDATE", id, p).Scan(&state, &b, &nonce, &ct, &tag, &wrapped, &wkid, &wn, &unlock, &rev)
	if errors.Is(e, pgx.ErrNoRows) {
		fail(w, 404, "not_found", false, n)
		return
	}
	if e != nil {
		internal(w, n)
		return
	}
	var hidden bool
	e = tx.QueryRow(r.Context(), "SELECT hidden FROM capsule_participants WHERE capsule_id=$1 AND user_id=$2 FOR UPDATE", id, p).Scan(&hidden)
	if e != nil {
		internal(w, n)
		return
	}
	if state == "revoked" || hidden {
		fail(w, 410, "unavailable", false, n)
		return
	}
	if state != "sealed" || unlock == nil {
		fail(w, 409, "not_sealed", true, n)
		return
	}
	// Obtain a fresh DB time after all blocking locks, never a client time or transaction start timestamp.
	n, e = dbtime(r.Context(), tx)
	if e != nil || !s.clock.Check(n) {
		fail(w, 503, "clock_unhealthy", true, n)
		return
	}
	if n < *unlock {
		write(w, 409, map[string]any{"code": "not_ready", "retryable": true, "server_ms": n, "unlock_ms": *unlock, "request_id": protocol.RandomID()})
		return
	}
	wrappingKey := s.Config.WrappingKeys[*wkid]
	if len(wrappingKey) != 32 {
		internal(w, n)
		return
	}
	content, e := protocol.Unwrap(wrappingKey, wrapped, wn, *wkid, id)
	if e != nil || len(content) != 32 {
		internal(w, n)
		return
	}
	defer clear(content)
	_, e = tx.Exec(r.Context(), "INSERT INTO capsule_events(capsule_id,event) VALUES($1,'release')", id)
	if e != nil {
		internal(w, n)
		return
	}
	v := ReleaseResponse{protocol.Encode(b), protocol.Encode(nonce), protocol.Encode(ct), protocol.Encode(tag), protocol.Encode(content), n, rev}
	finish(w, r, tx, n, v)
}

type Metadata struct {
	CapsuleID string `json:"capsule_id"`
	Carrier   string `json:"carrier,omitempty"`
	State     string `json:"state"`
	Revision  int64  `json:"revision"`
	ServerMS  int64  `json:"server_ms"`
	Hidden    bool   `json:"hidden"`
	Opened    bool   `json:"opened"`
}

func getMetadata(ctx context.Context, tx pgx.Tx, id, p string, n int64) (Metadata, error) {
	var v Metadata
	var d, sig []byte
	var kid *string
	e := tx.QueryRow(ctx, "SELECT c.id,c.state,c.revision,c.descriptor,c.signature,c.kid,p.hidden,p.opened FROM capsules c JOIN capsule_participants p ON c.id=p.capsule_id WHERE c.id=$1 AND p.user_id=$2", id, p).Scan(&v.CapsuleID, &v.State, &v.Revision, &d, &sig, &kid, &v.Hidden, &v.Opened)
	v.ServerMS = n
	if e == nil && kid != nil {
		v.Carrier = protocol.CarrierPrefix + *kid + "." + protocol.Encode(d) + "." + protocol.Encode(sig)
	}
	return v, e
}
func (s *Server) metadata(w http.ResponseWriter, r *http.Request, p string) {
	tx, n, ok := s.begin(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	v, e := getMetadata(r.Context(), tx, r.PathValue("id"), p, n)
	if errors.Is(e, pgx.ErrNoRows) {
		fail(w, 404, "not_found", false, n)
		return
	}
	if e != nil {
		internal(w, n)
		return
	}
	finish(w, r, tx, n, v)
}
func (s *Server) batch(w http.ResponseWriter, r *http.Request, p string) {
	var q struct {
		CapsuleIDs []string `json:"capsule_ids"`
	}
	if read(r, &q) != nil || len(q.CapsuleIDs) > 100 {
		fail(w, 400, "invalid_request", false, 0)
		return
	}
	for _, id := range q.CapsuleIDs {
		if !protocol.ValidOpaque(id) {
			fail(w, 400, "invalid_request", false, 0)
			return
		}
	}
	tx, n, ok := s.begin(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	items := []Metadata{}
	for _, id := range q.CapsuleIDs {
		v, e := getMetadata(r.Context(), tx, id, p, n)
		if errors.Is(e, pgx.ErrNoRows) {
			continue
		}
		if e != nil {
			internal(w, n)
			return
		}
		items = append(items, v)
	}
	finish(w, r, tx, n, map[string]any{"capsules": items, "server_ms": n})
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request, p string) {
	s.mutate(w, r, p, "revoke")
}
func (s *Server) hide(w http.ResponseWriter, r *http.Request, p string) { s.mutate(w, r, p, "hide") }
func (s *Server) opened(w http.ResponseWriter, r *http.Request, p string) {
	s.mutate(w, r, p, "opened")
}
func (s *Server) mutate(w http.ResponseWriter, r *http.Request, p, op string) {
	var q struct{}
	k, ok := key(r)
	if !ok || read(r, &q) != nil {
		fail(w, 400, "invalid_request", false, 0)
		return
	}
	tx, n, ok := s.begin(w, r)
	if !ok {
		return
	}
	defer tx.Rollback(r.Context())
	id := r.PathValue("id")
	var sender, state string
	e := tx.QueryRow(r.Context(), "SELECT sender_id,state FROM capsules WHERE id=$1 AND (sender_id=$2 OR recipient_id=$2) FOR UPDATE", id, p).Scan(&sender, &state)
	if errors.Is(e, pgx.ErrNoRows) || e == nil && op == "revoke" && sender != p {
		fail(w, 404, "not_found", false, n)
		return
	}
	if e != nil {
		internal(w, n)
		return
	}
	d := requestDigest(q)
	cached, e := idem(r.Context(), tx, p, op+":"+id, k, d)
	if e != nil {
		internal(w, n)
		return
	}
	if cached != nil {
		finish(w, r, tx, n, json.RawMessage(cached))
		return
	}
	var hidden bool
	e = tx.QueryRow(r.Context(), "SELECT hidden FROM capsule_participants WHERE capsule_id=$1 AND user_id=$2 FOR UPDATE", id, p).Scan(&hidden)
	if e != nil {
		internal(w, n)
		return
	}
	switch op {
	case "revoke":
		if state != "revoked" {
			_, e = tx.Exec(r.Context(), "UPDATE capsules SET state='revoked',wrapped_key=NULL,wrapping_nonce=NULL,nonce=NULL,ciphertext=NULL,tag=NULL,revision=revision+1,revoked_at=clock_timestamp() WHERE id=$1", id)
		}
	case "hide":
		_, e = tx.Exec(r.Context(), "UPDATE capsule_participants SET hidden=true WHERE capsule_id=$1 AND user_id=$2", id, p)
	case "opened":
		if state != "sealed" || hidden {
			fail(w, 410, "unavailable", false, n)
			return
		}
		_, e = tx.Exec(r.Context(), "UPDATE capsule_participants SET opened=true WHERE capsule_id=$1 AND user_id=$2", id, p)
	}
	if e != nil {
		internal(w, n)
		return
	}
	v, e := getMetadata(r.Context(), tx, id, p, n)
	if e != nil || saveIdem(r.Context(), tx, p, op+":"+id, k, d, v) != nil {
		internal(w, n)
		return
	}
	finish(w, r, tx, n, v)
}

type rateEntry struct {
	tokens float64
	last   time.Time
}
type limiter struct {
	mu      sync.Mutex
	entries map[string]rateEntry
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := time.Now()
	e, ok := l.entries[key]
	if !ok {
		e = rateEntry{tokens: 60, last: n}
	}
	e.tokens = math.Min(60, e.tokens+n.Sub(e.last).Seconds()*5)
	e.last = n
	allowed := e.tokens >= 1
	if allowed {
		e.tokens--
	}
	if len(l.entries) > 10000 {
		for k, v := range l.entries {
			if n.Sub(v.last) > time.Minute {
				delete(l.entries, k)
			}
		}
		if len(l.entries) > 10000 && !ok {
			return false
		}
	}
	l.entries[key] = e
	return allowed
}
