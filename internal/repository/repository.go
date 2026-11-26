// Package repository defines the persistence contracts of ezstore.
//
// The interfaces speak domain types only. No GORM type, SQL string or column
// name crosses this boundary, which keeps the service layer independent of the
// database and lets tests swap in a fake store.
package repository

import (
	"context"

	"ezstore/internal/domain"
)

// Store is the unit of work used by every service. Transaction hands the
// callback a Store bound to a single database transaction.
type Store interface {
	Secrets() SecretRepository
	Tokens() TokenRepository
	Audit() AuditRepository

	Transaction(ctx context.Context, fn func(Store) error) error

	Migrate(ctx context.Context) error
	Ping(ctx context.Context) error
	Dialect() string
	Close() error
}

// SecretRepository stores secrets and their immutable version history.
type SecretRepository interface {
	// Find returns a secret by name. Missing rows return domain.ErrNotFound.
	Find(ctx context.Context, name string, includeDeleted bool) (*domain.Secret, error)
	Create(ctx context.Context, s *domain.Secret) error
	// Update rewrites the mutable columns and clears the soft delete marker.
	Update(ctx context.Context, s *domain.Secret) error
	// Delete soft deletes by default; hard also removes every version.
	Delete(ctx context.Context, name string, hard bool) error
	List(ctx context.Context, prefix string, limit int) ([]domain.Secret, error)

	AddVersion(ctx context.Context, secretName string, v *domain.VersionRecord) error
	FindVersion(ctx context.Context, secretName string, version int64) (*domain.VersionRecord, error)
	ListVersions(ctx context.Context, secretName string, limit int) ([]domain.VersionInfo, error)
	// PruneVersions deletes all but the newest keep versions.
	PruneVersions(ctx context.Context, secretName string, keep int64) error
}

// TokenRepository stores API tokens. Only hashes are persisted.
type TokenRepository interface {
	Create(ctx context.Context, t *domain.Token, hash string) error
	FindByName(ctx context.Context, name string) (*domain.Token, string, error)
	FindByHash(ctx context.Context, hash string) (*domain.Token, error)
	List(ctx context.Context) ([]domain.Token, error)
	Delete(ctx context.Context, name string) error
}

// AuditRepository is an append-only, hash-chained log.
type AuditRepository interface {
	// Last returns the newest entry, or nil when the log is empty.
	Last(ctx context.Context) (*domain.AuditEntry, error)
	Append(ctx context.Context, e *domain.AuditEntry) error
	Tail(ctx context.Context, limit int) ([]domain.AuditEntry, error)
	All(ctx context.Context) ([]domain.AuditEntry, error)
}
