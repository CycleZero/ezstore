// Package domain holds the entities, invariants and sentinel errors of
// ezstore. It has no dependency on storage or transport so that both the HTTP
// API and the MCP server can share exactly the same rules.
package domain

import "time"

// Secret is a named secret at its current version. Value is never part of the
// listing model; it is only returned by an explicit read.
type Secret struct {
	Name           string
	Tags           map[string]string
	CurrentVersion int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Deleted        bool
}

// SecretValue is a decrypted secret version.
type SecretValue struct {
	Name      string
	Version   int64
	Value     []byte
	Tags      map[string]string
	CreatedAt time.Time
}

// VersionInfo describes one historical version without exposing its value.
type VersionInfo struct {
	Version   int64
	Checksum  string
	CreatedAt time.Time
	CreatedBy string
}

// VersionRecord is the persisted form of a single encrypted version.
type VersionRecord struct {
	SecretID   string
	Version    int64
	Nonce      []byte
	Ciphertext []byte
	Checksum   string
	CreatedAt  time.Time
	CreatedBy  string
}

// Token is an API credential bound to a set of scopes and permissions.
type Token struct {
	ID        string
	Name      string
	Scopes    []string
	Perms     []string
	CreatedAt time.Time
	ExpiresAt *time.Time
	Enabled   bool
}

// Expired reports whether the token is past its expiry.
func (t Token) Expired(now time.Time) bool {
	return t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)
}

// AuditEntry is one append-only record in the tamper-evident log.
type AuditEntry struct {
	Seq      uint64
	TS       time.Time
	Actor    string
	Op       string
	Name     string
	OK       bool
	Detail   string
	PrevHash string
	Hash     string
}

// Audit operation names.
const (
	OpGet      = "get"
	OpPut      = "put"
	OpList     = "list"
	OpDelete   = "delete"
	OpPurge    = "purge"
	OpHistory  = "history"
	OpRollback = "rollback"
)
