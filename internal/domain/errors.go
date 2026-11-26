package domain

import "errors"

// Sentinel errors. Callers use errors.Is to map them onto transport-specific
// results, so the domain never knows about HTTP status codes or MCP payloads.
var (
	ErrNotFound          = errors.New("not found")
	ErrPermissionDenied  = errors.New("permission denied")
	ErrUnauthenticated   = errors.New("unauthenticated")
	ErrInvalidName       = errors.New("invalid secret name")
	ErrInvalidArgument   = errors.New("invalid argument")
	ErrValueTooLarge     = errors.New("value too large")
	ErrConflict          = errors.New("conflict")
	ErrTokenExpired      = errors.New("token expired")
	ErrNoScopes          = errors.New("token has no scopes")
	ErrInternalInvariant = errors.New("internal invariant violated")
)

// MaxValueBytes caps a single secret value. The default MySQL BLOB column used
// by GORM tops out at 64 KiB, and a value larger than this is almost always a
// mistake for an agent-facing store.
const MaxValueBytes = 60 * 1024

// MaxNameBytes bounds the name column so the unique index fits every backend.
const MaxNameBytes = 191
