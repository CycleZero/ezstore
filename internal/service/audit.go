// Package service holds the business rules of ezstore: authorisation checks,
// version bookkeeping, encryption and audit. Transports (HTTP, MCP, CLI) are
// thin adapters over this layer.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"ezstore/internal/domain"
	"ezstore/internal/repository"
)

// AuditService maintains the append-only, hash-chained audit log.
type AuditService struct {
	store repository.Store
}

// NewAuditService wires an AuditService to a store.
func NewAuditService(store repository.Store) *AuditService {
	return &AuditService{store: store}
}

// Record appends one entry inside the caller's transaction, linking it to the
// previous hash so tampering with any row invalidates every later row.
func (a *AuditService) Record(ctx context.Context, tx repository.Store, actor domain.Actor, op, name string, ok bool, detail string) error {
	last, err := tx.Audit().Last(ctx)
	if err != nil {
		return fmt.Errorf("audit head: %w", err)
	}
	prev := ""
	if last != nil {
		prev = last.Hash
	}
	entry := &domain.AuditEntry{
		TS:       time.Now().UTC().Truncate(time.Millisecond),
		Actor:    actor.Name,
		Op:       op,
		Name:     name,
		OK:       ok,
		Detail:   detail,
		PrevHash: prev,
	}
	entry.Hash = hashEntry(entry)
	return tx.Audit().Append(ctx, entry)
}

// recordFailure writes a denial or error entry in its own transaction so it
// survives the caller's rollback. Failures here are ignored on purpose: losing
// an audit line must not change the result the caller already saw.
func (a *AuditService) recordFailure(ctx context.Context, actor domain.Actor, op, name string, cause error) {
	if cause == nil {
		return
	}
	_ = a.store.Transaction(ctx, func(tx repository.Store) error {
		return a.Record(ctx, tx, actor, op, name, false, cause.Error())
	})
}

// Tail returns the newest entries in chronological order.
func (a *AuditService) Tail(ctx context.Context, actor domain.Actor, limit int) ([]domain.AuditEntry, error) {
	if !actor.CanAdmin() {
		return nil, fmt.Errorf("%w: reading the audit log requires the admin permission", domain.ErrPermissionDenied)
	}
	return a.store.Audit().Tail(ctx, limit)
}

// Verify recomputes the chain. It returns the number of verified entries and
// the sequence number of the first broken link.
func (a *AuditService) Verify(ctx context.Context, actor domain.Actor) (int, error) {
	if !actor.CanAdmin() {
		return 0, fmt.Errorf("%w: verifying the audit log requires the admin permission", domain.ErrPermissionDenied)
	}
	entries, err := a.store.Audit().All(ctx)
	if err != nil {
		return 0, err
	}
	prev := ""
	for i := range entries {
		e := entries[i]
		if e.PrevHash != prev {
			return i, fmt.Errorf("audit chain broken at seq %d: prev_hash does not match", e.Seq)
		}
		if hashEntry(&e) != e.Hash {
			return i, fmt.Errorf("audit chain broken at seq %d: record hash does not match", e.Seq)
		}
		prev = e.Hash
	}
	return len(entries), nil
}

// hashEntry is the canonical serialisation of an audit record. It must only
// use fields that round-trip through the database byte for byte, which is why
// the timestamp is hashed as Unix milliseconds.
func hashEntry(e *domain.AuditEntry) string {
	h := sha256.New()
	parts := []string{
		e.PrevHash,
		strconv.FormatInt(e.TS.UnixMilli(), 10),
		e.Actor,
		e.Op,
		e.Name,
		strconv.FormatBool(e.OK),
		e.Detail,
	}
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0x1f})
	}
	return hex.EncodeToString(h.Sum(nil))
}
