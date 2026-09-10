package database

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	goosedb "github.com/pressly/goose/v3/database"
)

// These named queries are the migration-engine exception to application sqlc:
// Goose's public Store uses database/sql, while read-only readiness uses pgx.
// There is one ledger, owned by Goose; checksum is an atomic integrity extension
// of its rows, not another version table or migration executor.
const (
	migrationTablesSQL = `SELECT to_regclass('goose_db_version') IS NOT NULL,
		to_regclass('schema_migrations') IS NOT NULL`
	migrationRowsSQL           = `SELECT version_id, is_applied, checksum FROM goose_db_version ORDER BY id`
	migrationChecksumColumnSQL = `ALTER TABLE goose_db_version ADD COLUMN checksum text`
	migrationChecksumSQL       = `UPDATE goose_db_version SET checksum=$2 WHERE version_id=$1`
	migrationSessionLockSQL    = `SELECT pg_advisory_lock($1)`
	migrationSessionUnlockSQL  = `SELECT pg_advisory_unlock($1)`
)

type ledgerRows interface {
	Next() bool
	Scan(...any) error
	Err() error
}

// Both startup and GET readiness enforce exactly the same forward-only ledger
// policy, including Goose's zero row. Missing, duplicate, reordered, down,
// unknown and modified rows all fail closed.
func validateLedger(rows ledgerRows, migrations []migration) (int, error) {
	n := -1
	for rows.Next() {
		var version int
		var applied bool
		var checksum sql.NullString
		if err := rows.Scan(&version, &applied, &checksum); err != nil {
			return 0, err
		}
		if !applied {
			return 0, errSchema
		}
		if n == -1 {
			if version != 0 || !checksum.Valid || checksum.String != "" {
				return 0, errSchema
			}
		} else if n >= len(migrations) || version != migrations[n].version ||
			!checksum.Valid || checksum.String != migrations[n].sum {
			return 0, errSchema
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, errSchema
	}
	return n, nil
}

func schemaVersions(ctx context.Context, tx pgx.Tx, migrations []migration) (int, error) {
	var present, legacy bool
	if err := tx.QueryRow(ctx, migrationTablesSQL).Scan(&present, &legacy); err != nil {
		return 0, err
	}
	if legacy {
		return 0, errSchema
	}
	if !present {
		return 0, nil
	}
	rows, err := tx.Query(ctx, migrationRowsSQL)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	return validateLedger(rows, migrations)
}

type checksumStore struct {
	goosedb.Store
	migrations []migration
}

var _ goosedb.StoreExtender = (*checksumStore)(nil)

func (s *checksumStore) TableExists(ctx context.Context, db goosedb.DBTxConn) (bool, error) {
	var present, legacy bool
	if err := db.QueryRowContext(ctx, migrationTablesSQL).Scan(&present, &legacy); err != nil {
		return false, err
	}
	if legacy {
		return false, errSchema
	}
	return present, nil
}

func (s *checksumStore) CreateVersionTable(ctx context.Context, db goosedb.DBTxConn) error {
	if _, ok := db.(*sql.Tx); !ok {
		return errSchema
	}
	if err := s.Store.CreateVersionTable(ctx, db); err != nil {
		return err
	}
	_, err := db.ExecContext(ctx, migrationChecksumColumnSQL)
	return err
}

func (s *checksumStore) Insert(ctx context.Context, db goosedb.DBTxConn, req goosedb.InsertRequest) error {
	// Goose must supply its migration transaction, including version zero.
	if _, ok := db.(*sql.Tx); !ok {
		return errSchema
	}
	checksum := ""
	if req.Version != 0 {
		found := false
		for _, m := range s.migrations {
			if int64(m.version) == req.Version {
				checksum, found = m.sum, true
				break
			}
		}
		if !found {
			return errSchema
		}
	}
	if err := s.Store.Insert(ctx, db, req); err != nil {
		return err
	}
	result, err := db.ExecContext(ctx, migrationChecksumSQL, req.Version, checksum)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return errSchema
	}
	return err
}

func (s *checksumStore) Delete(context.Context, goosedb.DBTxConn, int64) error {
	return errSchema // No automated down migrations.
}

func (s *checksumStore) ListMigrations(ctx context.Context, db goosedb.DBTxConn) ([]*goosedb.ListMigrationsResult, error) {
	rows, err := db.QueryContext(ctx, migrationRowsSQL)
	if err != nil {
		return nil, err
	}
	_, err = validateLedger(rows, s.migrations)
	closeErr := rows.Close()
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	return s.Store.ListMigrations(ctx, db)
}

// Goose holds this session on the same connection as its SQL transactions.
// Session and transaction advisory locks conflict for the same PostgreSQL key.
type migrationLocker struct{}

func (migrationLocker) SessionLock(ctx context.Context, conn *sql.Conn) error {
	_, err := conn.ExecContext(ctx, migrationSessionLockSQL, MigrationLock)
	if err != nil {
		// Acquisition may have reached PostgreSQL before cancellation. Never
		// return an ambiguously locked connection to database/sql.
		discardMigrationConnection(conn)
	}
	return err
}

func (migrationLocker) SessionUnlock(ctx context.Context, conn *sql.Conn) error {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var unlocked bool
	err := conn.QueryRowContext(ctx, migrationSessionUnlockSQL, MigrationLock).Scan(&unlocked)
	if err == nil && !unlocked {
		err = errSchema
	}
	if err != nil {
		discardMigrationConnection(conn)
	}
	return err
}

func discardMigrationConnection(conn *sql.Conn) {
	// Close the underlying session, bounded even when the operation expired.
	// If database/sql already discarded it, Raw returns ErrConnDone; the
	// dedicated adapter's driver Close has already closed the native session.
	_ = conn.Raw(func(driverConn any) error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return driverConn.(*stdlib.Conn).Conn().Close(ctx)
	})
}
