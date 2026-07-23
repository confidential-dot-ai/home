// Package secretspolicy provides the CDS-side persistence and HTTP handlers for
// the secrets release policy — the operator-key-gated map from an attested
// workload digest to the KV paths that workload may read. It mirrors
// internal/allowlist: a SQLite store with an ETag version, served read-only to
// consumers and mutated only through an operator-key-authorized write path.
package secretspolicy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// Store persists the secrets policy: one row per workload digest, holding the
// JSON-encoded list of allowed path globs, plus a monotonically-bumped version
// that consumers use as a pull ETag.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS secrets_policy (
	digest TEXT PRIMARY KEY,
	allow  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secrets_policy_version (
	version TEXT NOT NULL DEFAULT '1'
);
INSERT INTO secrets_policy_version (version)
	SELECT '1' WHERE NOT EXISTS (SELECT 1 FROM secrets_policy_version);
`

// OpenStore opens (or creates) a SQLite-backed secrets-policy store at path.
func OpenStore(path string) (Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return Store{}, fmt.Errorf("open secrets-policy db: %w", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return Store{}, fmt.Errorf("init secrets-policy schema: %w", err)
	}
	return Store{db: db}, nil
}

// OpenInMemory opens an in-memory store, for tests.
func OpenInMemory() (Store, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return Store{}, err
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return Store{}, err
	}
	return Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// ListAll returns the current version and the digest→allow-globs map.
func (s *Store) ListAll() (string, map[string][]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var version string
	if err := s.db.QueryRow("SELECT version FROM secrets_policy_version").Scan(&version); err != nil {
		return "", nil, err
	}
	rows, err := s.db.Query("SELECT digest, allow FROM secrets_policy")
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()

	out := map[string][]string{}
	for rows.Next() {
		var digest, allowJSON string
		if err := rows.Scan(&digest, &allowJSON); err != nil {
			return "", nil, err
		}
		var allow []string
		if err := json.Unmarshal([]byte(allowJSON), &allow); err != nil {
			continue // validated on insert; skip a corrupt row
		}
		out[digest] = allow
	}
	return version, out, rows.Err()
}

// Lookup returns the allow globs for a single workload digest (lowercase hex),
// or nil when the digest is not in the policy.
func (s *Store) Lookup(digest string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var allowJSON string
	err := s.db.QueryRow("SELECT allow FROM secrets_policy WHERE digest = ?",
		strings.ToLower(strings.TrimSpace(digest))).Scan(&allowJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var allow []string
	if err := json.Unmarshal([]byte(allowJSON), &allow); err != nil {
		return nil, err
	}
	return allow, nil
}

func bumpVersionTx(tx *sql.Tx) error {
	_, err := tx.Exec("UPDATE secrets_policy_version SET version = CAST(CAST(version AS INTEGER) + 1 AS TEXT)")
	return err
}

// Put inserts or replaces one workload digest's allow set and bumps the version.
func (s *Store) Put(digest string, allow []string) error {
	allowJSON, err := json.Marshal(allow)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("INSERT OR REPLACE INTO secrets_policy (digest, allow) VALUES (?, ?)",
		strings.ToLower(strings.TrimSpace(digest)), string(allowJSON)); err != nil {
		return err
	}
	if err := bumpVersionTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Replace atomically swaps the whole policy for entries (digest→allow) and bumps
// the version. An empty map clears the policy (deny everything); the handler
// rejects a nil map so only an explicit empty set reaches here.
func (s *Store) Replace(entries map[string][]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM secrets_policy"); err != nil {
		return err
	}
	for digest, allow := range entries {
		allowJSON, err := json.Marshal(allow)
		if err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO secrets_policy (digest, allow) VALUES (?, ?)",
			strings.ToLower(strings.TrimSpace(digest)), string(allowJSON)); err != nil {
			return err
		}
	}
	if err := bumpVersionTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Delete removes the named digests atomically, returning false (and deleting
// nothing) if any is absent.
func (s *Store) Delete(digests []string) (bool, error) {
	if len(digests) == 0 {
		return true, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	placeholders := make([]string, len(digests))
	args := make([]any, len(digests))
	for i, d := range digests {
		placeholders[i] = "?"
		args[i] = strings.ToLower(strings.TrimSpace(d))
	}
	in := strings.Join(placeholders, ", ")

	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM secrets_policy WHERE digest IN ("+in+")", args...).Scan(&count); err != nil {
		return false, err
	}
	if count != len(digests) {
		return false, nil
	}
	if _, err := tx.Exec("DELETE FROM secrets_policy WHERE digest IN ("+in+")", args...); err != nil {
		return false, err
	}
	if err := bumpVersionTx(tx); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
