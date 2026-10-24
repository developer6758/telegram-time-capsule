// Package migrations applies the embedded, versioned PostgreSQL schema.
package migrations

import (
	"context"
	"embed"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"sort"
)

//go:embed *.sql
var files embed.FS

func Apply(ctx context.Context, db *pgxpool.Pool) error {
	tx, e := db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(872432747294)"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS capsule_schema_migrations(version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())"); e != nil {
		return e
	}
	entries, e := files.ReadDir(".")
	if e != nil {
		return e
	}
	names := []string{}
	for _, v := range entries {
		names = append(names, v.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		var done bool
		if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM capsule_schema_migrations WHERE version=$1)", name).Scan(&done); e != nil {
			return e
		}
		if done {
			continue
		}
		b, e := files.ReadFile(name)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, string(b)); e != nil {
			return fmt.Errorf("migration %s: %w", name, e)
		}
		if _, e = tx.Exec(ctx, "INSERT INTO capsule_schema_migrations(version) VALUES($1)", name); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
