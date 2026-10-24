package server

// This opt-in two-process test retains a temporary schema between prepare and
// verify. A PostgreSQL process/container restart is performed by the developer
// between invocations, outside the application and its HTTP API.
import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/developer6758/telegram-time-capsule/internal/protocol"
	"github.com/developer6758/telegram-time-capsule/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"os"
	"strings"
	"testing"
)

type restartFixture struct{ Schema, ID, Signing, Wrapping, Carrier string }

func TestPostgresExternalRestart(t *testing.T) {
	phase := os.Getenv("CAPSULE_DURABILITY_PHASE")
	file := os.Getenv("CAPSULE_DURABILITY_FILE")
	dsn := os.Getenv("CAPSULE_TEST_DATABASE_URL")
	if (phase != "prepare" && phase != "verify") || file == "" || dsn == "" {
		t.Skip("two-phase external PostgreSQL restart test; see docs/BUILD_AND_TEST.md")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	var f restartFixture
	var signing *ecdsa.PrivateKey
	var wrapping []byte
	if phase == "prepare" {
		f.Schema = "capsule_restart_" + strings.ToLower(strings.ReplaceAll(protocol.RandomID(), "-", "_"))
		if _, e = admin.Exec(ctx, `CREATE SCHEMA "`+f.Schema+`"`); e != nil {
			t.Fatal(e)
		}
		signing, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		der, _ := x509.MarshalPKCS8PrivateKey(signing)
		f.Signing = protocol.Encode(der)
		wrapping = make([]byte, 32)
		rand.Read(wrapping)
		f.Wrapping = protocol.Encode(wrapping)
	} else {
		b, e := os.ReadFile(file)
		if e != nil || json.Unmarshal(b, &f) != nil {
			t.Fatal("invalid restart fixture")
		}
		der, e := protocol.Decode(f.Signing, 1, 1000)
		if e != nil {
			t.Fatal(e)
		}
		key, e := x509.ParsePKCS8PrivateKey(der)
		if e != nil {
			t.Fatal(e)
		}
		signing = key.(*ecdsa.PrivateKey)
		wrapping, e = protocol.Decode(f.Wrapping, 32, 32)
		if e != nil {
			t.Fatal(e)
		}
	}
	config, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	config.ConnConfig.RuntimeParams["search_path"] = f.Schema
	db, e := pgxpool.NewWithConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if e = migrations.Apply(ctx, db); e != nil {
		t.Fatal(e)
	}
	s, e := New(db, Config{ServiceID: "test", SigningKeyID: "s1", SigningKey: signing, WrappingKeyID: "w1", WrappingKeys: map[string][]byte{"w1": wrapping}}, func(r *http.Request) (string, error) {
		switch r.Header.Get("Authorization") {
		case "Bearer sender":
			return "111", nil
		case "Bearer recipient":
			return "222", nil
		}
		return "", errors.New("invalid test credential")
	})
	if e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	s.Register(mux)
	h := s.Middleware(mux)
	if phase == "prepare" {
		id, b := reserveFixture(t, h, 1)
		_, out := sealFixture(t, h, id, b)
		f.ID = id
		f.Carrier = out["carrier"].(string)
		data, _ := json.Marshal(f)
		if e = os.WriteFile(file, data, 0600); e != nil {
			t.Fatal(e)
		}
		t.Log("sealed test capsule; restart PostgreSQL, then run verify with the same protected fixture")
		return
	}
	defer admin.Exec(ctx, `DROP SCHEMA "`+f.Schema+`" CASCADE`)
	status, metadata := call(t, h, "recipient", "GET", "/v1/capsules/"+f.ID, nil, "")
	if status != 200 || metadata["carrier"] != f.Carrier {
		t.Fatal("descriptor/deadline did not survive restart")
	}
	waitDeadline(t, db, f.ID)
	status, out := call(t, h, "recipient", "POST", "/v1/capsules/"+f.ID+"/release", ReleaseRequest{protocol.RandomID(), 2}, "")
	if status != 200 || out["content_key"] == nil {
		t.Fatalf("restart release failed status %d", status)
	}
	os.Remove(file)
}
