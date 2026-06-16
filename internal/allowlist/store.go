package allowlist

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/types"
	_ "modernc.org/sqlite"
)

// Store provides persistent storage for the image digest allowlist using SQLite.
type Store struct {
	mu sync.Mutex
	db *sql.DB
}

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
`

// OpenStore opens (or creates) a SQLite-backed allowlist store at the given path.
func OpenStore(path string) (Store, error) {
	_, err := os.Stat(path)
	isNew := os.IsNotExist(err)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return Store{}, fmt.Errorf("open allowlist db: %w", err)
	}

	if isNew {
		slog.Warn("WHITELIST DATABASE DID NOT EXIST, CREATING NEW FILE", "path", path)
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
`
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

// row holds a single row from the allowlist query.
type row struct {
	version   string
	digestStr sql.NullString
	image     sql.NullString
}

// ListAll returns the current version string and all allowlisted digests.
// The mutex is only held while reading rows from SQLite; parsing happens outside the lock.
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
				continue
			}
			digests[d] = r.image.String
		}
	}

	return version, digests, nil
}

// queryAll reads all rows under the lock and returns them as a slice.
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

// Add inserts or replaces a digest in the allowlist and increments the version.
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

// SeedDigests adds every digest not already present, in a single transaction,
// and returns the number added. It is additive and idempotent: existing entries
// are left untouched and the version is bumped at most once — and only when at
// least one digest was new. The version is the worker pull ETag, so a re-seed
// that adds nothing must not bump it (which would force every worker to
// re-pull). Operator entries added at runtime via POST /allowlist are never
// removed.
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

	// INSERT OR IGNORE is the skip-if-present: an existing digest (e.g. one an
	// operator added at runtime via POST /allowlist) is left untouched, and
	// RowsAffected reports 0 for it so it does not count toward the bump.
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

// Delete removes all given digests atomically. Returns false (and deletes nothing)
// if any digest is not present.
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
