package allowlist

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	_ "modernc.org/sqlite"
)

// Store provides persistent storage for the CDS allowlist using SQLite.
//
// Two layers share the version counter (the worker pull ETag): the floor table
// `allowlist(digest, image)` admits by digest alone, and `workload_entry` holds
// one canonical allowlist.Workload JSON per named entry, with
// `workload_entry_digest` indexing each container digest for membership.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

// roleInit / roleMain label the two container partitions in the digest index.
const (
	roleInit = "init"
	roleMain = "main"
)

// ErrInvalidWorkload marks a workload rejected by allowlist validation (a
// malformed name or container), so the handler answers 422 rather than 500.
var ErrInvalidWorkload = errors.New("invalid workload entry")

const workloadTablesSQL = `
CREATE TABLE IF NOT EXISTS workload_entry (
	name       TEXT PRIMARY KEY,
	entry_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workload_entry_digest (
	digest     TEXT NOT NULL,
	entry_name TEXT NOT NULL,
	role       TEXT NOT NULL,
	PRIMARY KEY (digest, entry_name, role)
);
`

const initSQL = `
CREATE TABLE IF NOT EXISTS allowlist (
	digest TEXT PRIMARY KEY,
	image  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS allowlist_version (
	version TEXT NOT NULL DEFAULT '1'
);
INSERT INTO allowlist_version (version)
	SELECT '1' WHERE NOT EXISTS (SELECT 1 FROM allowlist_version);
` + workloadTablesSQL

// OpenStore opens (or creates) a SQLite-backed allowlist store at the given path.
func OpenStore(path string) (Store, error) {
	_, err := os.Stat(path)
	isNew := os.IsNotExist(err)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return Store{}, fmt.Errorf("open allowlist db: %w", err)
	}

	if isNew {
		slog.Warn("allowlist db did not exist, creating", "path", path)
	}

	if _, err := db.Exec(initSQL); err != nil {
		db.Close()
		return Store{}, fmt.Errorf("init allowlist schema: %w", err)
	}

	return Store{db: db}, nil
}

// OpenInMemory opens an in-memory allowlist store, useful for testing.
func OpenInMemory() (Store, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return Store{}, err
	}

	initMemSQL := `
CREATE TABLE allowlist (
	digest TEXT PRIMARY KEY,
	image  TEXT NOT NULL
);
CREATE TABLE allowlist_version (
	version TEXT NOT NULL DEFAULT '1'
);
INSERT INTO allowlist_version (version) VALUES ('1');
` + workloadTablesSQL
	if _, err := db.Exec(initMemSQL); err != nil {
		db.Close()
		return Store{}, err
	}

	return Store{db: db}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// row holds a single row from the floor allowlist query.
type row struct {
	version   string
	digestStr sql.NullString
	image     sql.NullString
}

// ListAll returns the current version string and the floor digests. It reports
// only the floor layer; use LoadAll for the full document including workloads.
func (s *Store) ListAll() (string, map[types.Digest]string, error) {
	rawRows, err := s.queryAll()
	if err != nil {
		return "", nil, err
	}

	version := "1"
	digests := make(map[types.Digest]string, len(rawRows))
	for _, r := range rawRows {
		version = r.version
		if r.digestStr.Valid && r.image.Valid {
			d, err := types.ParseDigest(r.digestStr.String)
			if err != nil {
				// Data was validated on insert; skip corrupt rows
				slog.Warn("allowlist: skipping corrupt row",
					"digest", r.digestStr.String, "image", r.image.String, "err", err)
				continue
			}
			digests[d] = r.image.String
		}
	}

	return version, digests, nil
}

// LoadAll builds the full allowlist document — floor plus every workload entry —
// and returns it with the version string (the ETag). It backs GET /allowlist
// and the handoff snapshot.
func (s *Store) LoadAll() (*pkgallowlist.Allowlist, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var version string
	if err := s.db.QueryRow("SELECT version FROM allowlist_version LIMIT 1").Scan(&version); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, "", err
		}
		version = "1"
	}

	digests, err := s.loadFloorTx()
	if err != nil {
		return nil, "", err
	}
	workloads, err := s.loadWorkloadsTx()
	if err != nil {
		return nil, "", err
	}

	return &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Digests:   digests,
		Workloads: workloads,
	}, version, nil
}

func (s *Store) loadFloorTx() (map[string]string, error) {
	rows, err := s.db.Query("SELECT digest, image FROM allowlist")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	digests := map[string]string{}
	for rows.Next() {
		var digest, image string
		if err := rows.Scan(&digest, &image); err != nil {
			return nil, err
		}
		digests[digest] = image
	}
	return digests, rows.Err()
}

func (s *Store) loadWorkloadsTx() (map[string]pkgallowlist.Workload, error) {
	rows, err := s.db.Query("SELECT name, entry_json FROM workload_entry")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	workloads := map[string]pkgallowlist.Workload{}
	for rows.Next() {
		var name, entryJSON string
		if err := rows.Scan(&name, &entryJSON); err != nil {
			return nil, err
		}
		var w pkgallowlist.Workload
		if err := json.Unmarshal([]byte(entryJSON), &w); err != nil {
			return nil, fmt.Errorf("decode workload %q: %w", name, err)
		}
		workloads[name] = w
	}
	return workloads, rows.Err()
}

// Contains reports whether digest is admitted: present in the floor OR indexed
// as a workload container. It is the coarse per-digest gate the /attest handler
// applies to every claimed container image (docs/ratls.md).
func (s *Store) Contains(digest types.Digest) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var one int
	err := s.db.QueryRow(
		`SELECT 1 FROM allowlist WHERE digest = ?
		 UNION ALL
		 SELECT 1 FROM workload_entry_digest WHERE digest = ?
		 LIMIT 1`,
		digest.String(), digest.String(),
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// queryAll reads all floor rows under the lock and returns them as a slice.
func (s *Store) queryAll() ([]row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`
		SELECT wv.version, w.digest, w.image
		FROM allowlist_version wv
		LEFT JOIN allowlist w ON 1=1
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.version, &r.digestStr, &r.image); err != nil {
			return nil, err
		}
		result = append(result, r)
	}

	return result, rows.Err()
}

// bumpVersionTx increments the store version within tx. The version is the
// worker pull ETag, so it is bumped once per mutation that changes the set.
func bumpVersionTx(tx *sql.Tx) error {
	_, err := tx.Exec(
		"UPDATE allowlist_version SET version = CAST(CAST(version AS INTEGER) + 1 AS TEXT)",
	)
	return err
}

// Add inserts or replaces a floor digest and increments the version.
func (s *Store) Add(digest types.Digest, image string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		"INSERT OR REPLACE INTO allowlist (digest, image) VALUES (?, ?)",
		digest.String(), image,
	); err != nil {
		return err
	}
	if err := bumpVersionTx(tx); err != nil {
		return err
	}

	return tx.Commit()
}

// SeedDigests adds every floor digest not already present, in a single
// transaction, and returns the number added. It is additive and idempotent:
// existing entries are left untouched and the version is bumped at most once —
// and only when at least one digest was new, so a re-seed that adds nothing does
// not force every worker to re-pull.
func (s *Store) SeedDigests(digests map[types.Digest]string) (int, error) {
	if len(digests) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var added int64
	for digest, image := range digests {
		res, err := tx.Exec(
			"INSERT OR IGNORE INTO allowlist (digest, image) VALUES (?, ?)",
			digest.String(), image,
		)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		added += n
	}

	if added > 0 {
		if err := bumpVersionTx(tx); err != nil {
			return 0, err
		}
	}

	return int(added), tx.Commit()
}

// SeedWorkloads adds every workload entry whose name is not already present, in
// a single transaction, and returns the number added. Additive and idempotent
// like SeedDigests: an existing entry is left untouched and the version is
// bumped at most once, only when at least one entry was new.
func (s *Store) SeedWorkloads(workloads map[string]pkgallowlist.Workload) (int, error) {
	if len(workloads) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var added int
	for name, w := range workloads {
		entryJSON, err := json.Marshal(w)
		if err != nil {
			return 0, err
		}
		res, err := tx.Exec(
			"INSERT OR IGNORE INTO workload_entry (name, entry_json) VALUES (?, ?)",
			name, string(entryJSON),
		)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}
		if err := indexWorkloadTx(tx, name, w); err != nil {
			return 0, err
		}
		added++
	}

	if added > 0 {
		if err := bumpVersionTx(tx); err != nil {
			return 0, err
		}
	}

	return added, tx.Commit()
}

// PutWorkload upserts one named workload entry and rebuilds its digest index in
// a single transaction, then bumps the version. The name and containers are
// validated against the frozen allowlist rules; a rejection wraps
// ErrInvalidWorkload.
func (s *Store) PutWorkload(name string, w pkgallowlist.Workload) error {
	norm, err := normalizeEntry(name, w)
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

	if err := putWorkloadTx(tx, name, norm); err != nil {
		return err
	}
	if err := bumpVersionTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteWorkload removes one named entry and its index rows, bumping the version
// only when the entry existed. Returns false if absent.
func (s *Store) DeleteWorkload(name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	res, err := tx.Exec("DELETE FROM workload_entry WHERE name = ?", name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	if _, err := tx.Exec("DELETE FROM workload_entry_digest WHERE entry_name = ?", name); err != nil {
		return false, err
	}
	if err := bumpVersionTx(tx); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// ReplaceAll atomically swaps the entire allowlist — floor and workloads — for
// the given document and bumps the version. An empty document clears everything.
func (s *Store) ReplaceAll(al *pkgallowlist.Allowlist) error {
	if al == nil {
		return fmt.Errorf("allowlist is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := replaceContentsTx(tx, al); err != nil {
		return err
	}
	if err := bumpVersionTx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// RestoreSnapshot atomically replaces floor and workloads with an attested
// handoff snapshot while preserving the peer's version — state transfer, not an
// operator mutation, so it does not bump the ETag.
func (s *Store) RestoreSnapshot(version string, al *pkgallowlist.Allowlist) error {
	parsedVersion, err := strconv.ParseUint(version, 10, 64)
	if err != nil || parsedVersion == 0 {
		return fmt.Errorf("invalid allowlist snapshot version %q", version)
	}
	if al == nil {
		return fmt.Errorf("allowlist snapshot is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := replaceContentsTx(tx, al); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE allowlist_version SET version = ?", version); err != nil {
		return err
	}
	return tx.Commit()
}

// Replace atomically swaps the floor layer for digests and bumps the version,
// leaving workload entries intact. An empty map clears the floor.
func (s *Store) Replace(digests map[types.Digest]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM allowlist"); err != nil {
		return err
	}
	for digest, image := range digests {
		if _, err := tx.Exec(
			"INSERT INTO allowlist (digest, image) VALUES (?, ?)",
			digest.String(), image,
		); err != nil {
			return err
		}
	}
	if err := bumpVersionTx(tx); err != nil {
		return err
	}

	return tx.Commit()
}

// Delete removes all given floor digests atomically. Returns false (and deletes
// nothing) if any digest is not present.
func (s *Store) Delete(digests []types.Digest) (bool, error) {
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
		args[i] = d.String()
	}
	inClause := strings.Join(placeholders, ", ")

	var count int
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM allowlist WHERE digest IN (%s)", inClause)
	if err := tx.QueryRow(countSQL, args...).Scan(&count); err != nil {
		return false, err
	}

	if count != len(digests) {
		return false, nil
	}

	deleteSQL := fmt.Sprintf("DELETE FROM allowlist WHERE digest IN (%s)", inClause)
	if _, err := tx.Exec(deleteSQL, args...); err != nil {
		return false, err
	}

	if err := bumpVersionTx(tx); err != nil {
		return false, err
	}

	return true, tx.Commit()
}

// replaceContentsTx clears both layers and reloads them from al, without
// touching the version. Callers set the version (bump or restore).
func replaceContentsTx(tx *sql.Tx, al *pkgallowlist.Allowlist) error {
	for _, stmt := range []string{
		"DELETE FROM allowlist",
		"DELETE FROM workload_entry",
		"DELETE FROM workload_entry_digest",
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	for digest, image := range al.Digests {
		if _, err := tx.Exec("INSERT INTO allowlist (digest, image) VALUES (?, ?)", digest, image); err != nil {
			return err
		}
	}
	for name, w := range al.Workloads {
		entryJSON, err := json.Marshal(w)
		if err != nil {
			return err
		}
		if _, err := tx.Exec("INSERT INTO workload_entry (name, entry_json) VALUES (?, ?)", name, string(entryJSON)); err != nil {
			return err
		}
		if err := indexWorkloadTx(tx, name, w); err != nil {
			return err
		}
	}
	return nil
}

// putWorkloadTx upserts one entry's canonical JSON and rebuilds its index rows.
func putWorkloadTx(tx *sql.Tx, name string, w pkgallowlist.Workload) error {
	entryJSON, err := json.Marshal(w)
	if err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT OR REPLACE INTO workload_entry (name, entry_json) VALUES (?, ?)", name, string(entryJSON)); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM workload_entry_digest WHERE entry_name = ?", name); err != nil {
		return err
	}
	return indexWorkloadTx(tx, name, w)
}

// indexWorkloadTx writes one (digest, name, role) index row per container. A
// digest repeated within a role (same image, different argv) collapses to one
// row via the primary key.
func indexWorkloadTx(tx *sql.Tx, name string, w pkgallowlist.Workload) error {
	for _, part := range []struct {
		role string
		cs   []pkgallowlist.Container
	}{{roleInit, w.InitContainers}, {roleMain, w.Containers}} {
		for _, c := range part.cs {
			if _, err := tx.Exec(
				"INSERT OR IGNORE INTO workload_entry_digest (digest, entry_name, role) VALUES (?, ?, ?)",
				c.Digest.String(), name, part.role,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

// normalizeEntry validates name and w through the frozen allowlist validator and
// returns the canonical entry to store. A rejection wraps ErrInvalidWorkload.
func normalizeEntry(name string, w pkgallowlist.Workload) (pkgallowlist.Workload, error) {
	probe := &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{name: w},
	}
	canon, err := probe.Canonical()
	if err != nil {
		return pkgallowlist.Workload{}, fmt.Errorf("%w: %v", ErrInvalidWorkload, err)
	}
	parsed, err := pkgallowlist.ParseJSON(canon)
	if err != nil {
		return pkgallowlist.Workload{}, fmt.Errorf("%w: %v", ErrInvalidWorkload, err)
	}
	return parsed.Workloads[name], nil
}
