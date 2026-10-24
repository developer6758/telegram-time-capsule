package server

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/developer6758/telegram-time-capsule/internal/protocol"
	"github.com/developer6758/telegram-time-capsule/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func setup(t *testing.T) (*Server, *pgxpool.Pool, http.Handler) {
	t.Helper()
	dsn := os.Getenv("CAPSULE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CAPSULE_TEST_DATABASE_URL required for PostgreSQL integration")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	schema := "capsule_test_" + strings.ToLower(strings.ReplaceAll(protocol.RandomID(), "-", "_"))
	if _, e = admin.Exec(ctx, `CREATE SCHEMA "`+schema+`"`); e != nil {
		t.Fatal(e)
	}
	c, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	c.ConnConfig.RuntimeParams["search_path"] = schema
	db, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close(); _, _ = admin.Exec(ctx, `DROP SCHEMA "`+schema+`" CASCADE`); admin.Close() })
	if e = migrations.Apply(ctx, db); e != nil {
		t.Fatal(e)
	}
	sign, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrap := make([]byte, 32)
	rand.Read(wrap)
	s, e := New(db, Config{ServiceID: "test", SigningKeyID: "s1", SigningKey: sign, WrappingKeyID: "w1", WrappingKeys: map[string][]byte{"w1": wrap}}, func(r *http.Request) (string, error) {
		switch r.Header.Get("Authorization") {
		case "Bearer sender":
			return "111", nil
		case "Bearer recipient":
			return "222", nil
		case "Bearer stranger":
			return "333", nil
		}
		return "", errors.New("invalid token")
	})
	if e != nil {
		t.Fatal(e)
	}
	m := http.NewServeMux()
	s.Register(m)
	return s, db, s.Middleware(m)
}
func call(t *testing.T, h http.Handler, p, method, path string, v any, k string) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(v)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if p != "" {
		r.Header.Set("Authorization", "Bearer "+p)
	}
	if k != "" {
		r.Header.Set("Idempotency-Key", k)
	}
	r.Header.Set("X-Client-Time", "9999999999999999")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cache enabled")
	}
	var out map[string]any
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	return w.Code, out
}
func reserveFixture(t *testing.T, h http.Handler, duration int64) (string, []byte) {
	t.Helper()
	v := ReserveRequest{RecipientID: "222", DurationS: duration, Layout: protocol.Layout{V: 1, Samples: []protocol.Sample{{ConstraintEM: 14, WidthEM: 8, HeightEM: 1.25}, {ConstraintEM: 20, WidthEM: 8, HeightEM: 1.25}, {ConstraintEM: 28, WidthEM: 8, HeightEM: 1.25}}}}
	status, out := call(t, h, "sender", "POST", "/v1/capsules/reserve", v, protocol.RandomID())
	if status != 200 {
		t.Fatalf("reserve %d %v", status, out)
	}
	b, e := protocol.Decode(out["binding_b64url"].(string), 1, 5000)
	if e != nil {
		t.Fatal(e)
	}
	return out["capsule_id"].(string), b
}
func sealFixture(t *testing.T, h http.Handler, id string, b []byte) (SealRequest, map[string]any) {
	t.Helper()
	k := make([]byte, 32)
	n := make([]byte, 12)
	rand.Read(k)
	rand.Read(n)
	payload := []byte(`{"v":1,"text":"Synthetic private capsule 👩‍🚀 שלום","entities":[]}`)
	padded := make([]byte, 512)
	rand.Read(padded)
	binary.BigEndian.PutUint32(padded, uint32(len(payload)))
	copy(padded[4:], payload)
	block, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(block)
	sealed := g.Seal(nil, n, padded, protocol.PayloadAAD(b))
	q := SealRequest{protocol.Digest(b), protocol.Encode(n), protocol.Encode(sealed[:512]), protocol.Encode(sealed[512:]), protocol.Encode(k)}
	status, out := call(t, h, "sender", "POST", "/v1/capsules/"+id+"/seal", q, protocol.RandomID())
	if status != 200 {
		t.Fatalf("seal %d %v", status, out)
	}
	if strings.Contains(out["carrier"].(string), string(payload)) || strings.Contains(out["carrier"].(string), q.ContentKey) {
		t.Fatal("carrier contains secret")
	}
	return q, out
}
func waitDeadline(t *testing.T, db *pgxpool.Pool, id string) {
	t.Helper()
	var wait float64
	if e := db.QueryRow(context.Background(), "SELECT greatest(0,unlock_ms-floor(extract(epoch FROM clock_timestamp())*1000))::double precision FROM capsules WHERE id=$1", id).Scan(&wait); e != nil {
		t.Fatal(e)
	}
	time.Sleep(time.Duration(wait+10) * time.Millisecond)
}
func TestPostgresDelayedReleaseRestartAndRevoke(t *testing.T) {
	s, db, h := setup(t)
	id, b := reserveFixture(t, h, 1)
	q, seal := sealFixture(t, h, id, b)
	path := "/v1/capsules/" + id
	open := ReleaseRequest{protocol.RandomID(), 2}
	for _, principal := range []string{"sender", "recipient"} {
		status, out := call(t, h, principal, "POST", path+"/release", open, "")
		if status != 409 || out["code"] != "not_ready" || out["content_key"] != nil {
			t.Fatalf("early release: %d %v", status, out)
		}
	}
	status, out := call(t, h, "stranger", "POST", path+"/release", open, "")
	if status != 404 || out["content_key"] != nil {
		t.Fatal("stranger learned key/existence")
	}
	status, _ = call(t, h, "", "GET", path, nil, "")
	if status != 401 {
		t.Fatal("unauthenticated metadata")
	}
	// Identical retry preserves immutable descriptor and deadline, with a distinct HTTP idempotency key.
	status, out = call(t, h, "sender", "POST", path+"/seal", q, protocol.RandomID())
	if status != 200 || out["carrier"] != seal["carrier"] {
		t.Fatal("seal retry changed descriptor")
	}
	q.Tag = protocol.Encode(make([]byte, 16))
	status, _ = call(t, h, "sender", "POST", path+"/seal", q, protocol.RandomID())
	if status != 409 {
		t.Fatal("changed seal accepted")
	}
	waitDeadline(t, db, id)
	restarted, e := New(db, s.Config, s.Authenticate)
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	restarted.Register(mux)
	h = restarted.Middleware(mux)
	status, out = call(t, h, "recipient", "POST", path+"/release", open, "")
	if status != 200 {
		t.Fatalf("release %d %v", status, out)
	}
	key, _ := protocol.Decode(out["content_key"].(string), 32, 32)
	nonce, _ := protocol.Decode(out["nonce"].(string), 12, 12)
	ct, _ := protocol.Decode(out["ciphertext"].(string), 512, 512)
	tag, _ := protocol.Decode(out["tag"].(string), 16, 16)
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	plaintext, e := g.Open(nil, nonce, append(ct, tag...), protocol.PayloadAAD(b))
	if e != nil || binary.BigEndian.Uint32(plaintext) > 508 {
		t.Fatal("authorized decrypt failed")
	}
	var rawWrapped []byte
	if e = db.QueryRow(context.Background(), "SELECT wrapped_key FROM capsules WHERE id=$1", id).Scan(&rawWrapped); e != nil || bytes.Contains(rawWrapped, key) {
		t.Fatal("key not wrapped")
	}
	var rows int
	db.QueryRow(context.Background(), "SELECT count(*) FROM capsule_idempotency WHERE convert_from(response,'UTF8') LIKE '%content_key%' ").Scan(&rows)
	if rows != 0 {
		t.Fatal("key cached in idempotency")
	}
	status, _ = call(t, h, "sender", "POST", path+"/revoke", struct{}{}, protocol.RandomID())
	if status != 200 {
		t.Fatal("revoke failed")
	}
	status, out = call(t, h, "recipient", "POST", path+"/release", open, "")
	if status != 410 || out["content_key"] != nil {
		t.Fatal("replayed key after revoke")
	}
	var destroyed bool
	db.QueryRow(context.Background(), "SELECT wrapped_key IS NULL AND ciphertext IS NULL FROM capsules WHERE id=$1", id).Scan(&destroyed)
	if !destroyed {
		t.Fatal("revocation retained live key/payload")
	}
}
func TestPostgresIdempotencyAndParticipantHide(t *testing.T) {
	_, db, h := setup(t)
	_ = db
	k := protocol.RandomID()
	v := ReserveRequest{RecipientID: "222", DurationS: 1, Layout: protocol.Layout{V: 1, Samples: []protocol.Sample{{ConstraintEM: 14, WidthEM: 8, HeightEM: 1.25}, {ConstraintEM: 20, WidthEM: 8, HeightEM: 1.25}, {ConstraintEM: 28, WidthEM: 8, HeightEM: 1.25}}}}
	status, out := call(t, h, "sender", "POST", "/v1/capsules/reserve", v, k)
	if status != 200 {
		t.Fatal(out)
	}
	status, retry := call(t, h, "sender", "POST", "/v1/capsules/reserve", v, k)
	if status != 200 || out["capsule_id"] != retry["capsule_id"] {
		t.Fatal("reserve duplicated")
	}
	v.DurationS = 2
	status, _ = call(t, h, "sender", "POST", "/v1/capsules/reserve", v, k)
	if status != 409 {
		t.Fatal("idempotency mismatch accepted")
	}
	id := out["capsule_id"].(string)
	b, _ := protocol.Decode(out["binding_b64url"].(string), 1, 5000)
	sealFixture(t, h, id, b)
	status, _ = call(t, h, "recipient", "POST", "/v1/capsules/"+id+"/hide", struct{}{}, protocol.RandomID())
	if status != 200 {
		t.Fatal("hide")
	}
	waitDeadline(t, db, id)
	open := ReleaseRequest{protocol.RandomID(), 2}
	status, out = call(t, h, "recipient", "POST", "/v1/capsules/"+id+"/release", open, "")
	if status != 410 || out["content_key"] != nil {
		t.Fatal("hidden participant release")
	}
	status, _ = call(t, h, "sender", "POST", "/v1/capsules/"+id+"/release", open, "")
	if status != 200 {
		t.Fatal("hide revoked sender")
	}
}
func TestPostgresReleaseRevokeLinearization(t *testing.T) {
	_, db, h := setup(t)
	ids := []string{}
	for i := 0; i < 8; i++ {
		id, b := reserveFixture(t, h, 1)
		sealFixture(t, h, id, b)
		ids = append(ids, id)
	}
	waitDeadline(t, db, ids[len(ids)-1])
	for _, id := range ids {
		var wg sync.WaitGroup
		codes := make(chan int, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			code, _ := call(t, h, "recipient", "POST", "/v1/capsules/"+id+"/release", ReleaseRequest{protocol.RandomID(), 2}, "")
			codes <- code
		}()
		go func() {
			defer wg.Done()
			code, _ := call(t, h, "sender", "POST", "/v1/capsules/"+id+"/revoke", struct{}{}, protocol.RandomID())
			codes <- code
		}()
		wg.Wait()
		close(codes)
		for code := range codes {
			if code != 200 && code != 410 {
				t.Fatal(fmt.Sprintf("race unexpected %d", code))
			}
		}
		code, out := call(t, h, "recipient", "POST", "/v1/capsules/"+id+"/release", ReleaseRequest{protocol.RandomID(), 2}, "")
		if code != 410 || out["content_key"] != nil {
			t.Fatal("post-revoke release")
		}
	}
}
func TestClockFailClosed(t *testing.T) {
	var c Clock
	if !c.Check(10000) {
		t.Fatal("initial clock")
	}
	if c.Check(20000) || c.Check(10001) {
		t.Fatal("clock jump did not latch unhealthy")
	}
}
func TestHTTPRejectsMalformedAndUnexpectedFields(t *testing.T) {
	_, _, h := setup(t)
	for _, body := range []string{`{"recipient_id":"222","duration_s":1,"duration_s":10}`, `{"sender_id":"333"}`, `{"duration_s":31536001}`, `{"recipient_id":"9223372036854775808"}`} {
		r := httptest.NewRequest("POST", "/v1/capsules/reserve", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer sender")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", protocol.RandomID())
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("malformed status %d", w.Code)
		}
	}
}
