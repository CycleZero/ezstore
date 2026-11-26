// Package gormstore is the GORM implementation of repository.Store. It is the
// only package that knows SQL, column names or driver specific behaviour.
package gormstore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"ezstore/internal/repository"
)

type store struct {
	db      *gorm.DB
	dialect string
}

var _ repository.Store = (*store)(nil)

// Open connects to SQLite or MySQL and returns a Store. The caller is
// responsible for calling Migrate before serving traffic.
func Open(driver, dsn string) (repository.Store, error) {
	gormLogger := logger.Default.LogMode(logger.Silent)
	if os.Getenv("EZSTORE_DEBUG") != "" {
		gormLogger = logger.Default.LogMode(logger.Info)
	}
	var dialector gorm.Dialector
	switch driver {
	case "sqlite":
		dialector = sqlite.Open(withSQLitePragmas(dsn))
	case "mysql":
		dialector = mysql.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported driver %q", driver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger:                                   gormLogger,
		DisableForeignKeyConstraintWhenMigrating: true,
		SkipDefaultTransaction:                   true,
	})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", driver, err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(8)
	sqlDB.SetMaxIdleConns(4)

	return &store{db: db, dialect: db.Dialector.Name()}, nil
}

// withSQLitePragmas enables WAL and a busy timeout so concurrent readers do not
// fail while a writer holds the database lock.
func withSQLitePragmas(dsn string) string {
	if strings.Contains(dsn, "_pragma=") {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
}

func (s *store) Secrets() repository.SecretRepository { return &secretRepo{s: s} }
func (s *store) Tokens() repository.TokenRepository   { return &tokenRepo{s: s} }
func (s *store) Audit() repository.AuditRepository    { return &auditRepo{s: s} }

// Transaction runs fn inside one database transaction. SQLite serialises
// writers itself; MySQL needs explicit row locks, which lockQuery adds.
func (s *store) Transaction(ctx context.Context, fn func(repository.Store) error) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return fn(&store{db: tx, dialect: s.dialect})
	})
}

func (s *store) Migrate(ctx context.Context) error {
	return s.db.WithContext(ctx).AutoMigrate(
		&secretModel{}, &versionModel{}, &tokenModel{}, &auditModel{},
	)
}

func (s *store) Ping(ctx context.Context) error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

func (s *store) Dialect() string { return s.dialect }

func (s *store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// lockQuery adds SELECT ... FOR UPDATE on MySQL. SQLite has no such clause and
// does not need one, because a write transaction already holds the database
// lock.
func (s *store) lockQuery(q *gorm.DB) *gorm.DB {
	if s.dialect == "mysql" {
		return q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	return q
}

func encodeTags(tags map[string]string) string {
	if len(tags) == 0 {
		return "{}"
	}
	raw, err := json.Marshal(tags)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func decodeTags(raw string) map[string]string {
	out := map[string]string{}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func encodeStrings(in []string) string {
	if len(in) == 0 {
		return "[]"
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return "[]"
	}
	return string(raw)
}

func decodeStrings(raw string) []string {
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}
