package gormstore

import (
	"time"

	"gorm.io/gorm"

	"ezstore/internal/domain"
)

// secretModel is the GORM mapping of a secret. Persistence fields such as the
// primary key stay unexported from the domain.
type secretModel struct {
	ID             string `gorm:"primaryKey;size:32"`
	Name           string `gorm:"uniqueIndex;size:191;not null"`
	Tags           string `gorm:"type:text;not null"`
	CurrentVersion int64  `gorm:"not null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`
}

func (secretModel) TableName() string { return "ezstore_secrets" }

type versionModel struct {
	SecretID   string `gorm:"primaryKey;size:32"`
	Version    int64  `gorm:"primaryKey;autoIncrement:false"`
	Nonce      []byte `gorm:"not null"`
	Ciphertext []byte `gorm:"not null"`
	Checksum   string `gorm:"size:64;not null"`
	CreatedAt  time.Time
	CreatedBy  string `gorm:"size:64;not null"`
}

func (versionModel) TableName() string { return "ezstore_secret_versions" }

type tokenModel struct {
	ID        string `gorm:"primaryKey;size:32"`
	Name      string `gorm:"uniqueIndex;size:191;not null"`
	Hash      string `gorm:"uniqueIndex;size:64;not null"`
	Scopes    string `gorm:"type:text;not null"`
	Perms     string `gorm:"type:text;not null"`
	CreatedAt time.Time
	ExpiresAt *time.Time
	Enabled   bool `gorm:"not null"`
}

func (tokenModel) TableName() string { return "ezstore_tokens" }

type auditModel struct {
	Seq uint64 `gorm:"primaryKey;autoIncrement"`
	// TS is Unix milliseconds. An integer avoids the fractional-second
	// truncation differences between SQLite and MySQL, which would otherwise
	// break hash chain verification.
	TS       int64  `gorm:"column:ts;index;not null"`
	Actor    string `gorm:"size:191;not null"`
	Op       string `gorm:"size:32;not null"`
	Name     string `gorm:"size:191;not null"`
	OK       bool   `gorm:"not null"`
	Detail   string `gorm:"type:text;not null"`
	PrevHash string `gorm:"size:64;not null"`
	Hash     string `gorm:"size:64;not null"`
}

func (auditModel) TableName() string { return "ezstore_audit" }

func toSecret(m secretModel) *domain.Secret {
	return &domain.Secret{
		Name:           m.Name,
		Tags:           decodeTags(m.Tags),
		CurrentVersion: m.CurrentVersion,
		CreatedAt:      m.CreatedAt,
		UpdatedAt:      m.UpdatedAt,
		Deleted:        m.DeletedAt.Valid,
	}
}

func toVersion(m versionModel) *domain.VersionRecord {
	return &domain.VersionRecord{
		Version:    m.Version,
		Nonce:      m.Nonce,
		Ciphertext: m.Ciphertext,
		Checksum:   m.Checksum,
		CreatedAt:  m.CreatedAt,
		CreatedBy:  m.CreatedBy,
	}
}

func toToken(m tokenModel) *domain.Token {
	return &domain.Token{
		ID:        m.ID,
		Name:      m.Name,
		Scopes:    decodeStrings(m.Scopes),
		Perms:     decodeStrings(m.Perms),
		CreatedAt: m.CreatedAt,
		ExpiresAt: m.ExpiresAt,
		Enabled:   m.Enabled,
	}
}

func toAudit(m auditModel) domain.AuditEntry {
	return domain.AuditEntry{
		Seq:      m.Seq,
		TS:       time.UnixMilli(m.TS).UTC(),
		Actor:    m.Actor,
		Op:       m.Op,
		Name:     m.Name,
		OK:       m.OK,
		Detail:   m.Detail,
		PrevHash: m.PrevHash,
		Hash:     m.Hash,
	}
}
