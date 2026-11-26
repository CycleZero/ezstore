package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"ezstore/internal/crypto"
	"ezstore/internal/domain"
	"ezstore/internal/repository"
)

// SecretService implements secret CRUD, versioning and access control.
type SecretService struct {
	store  repository.Store
	cipher *crypto.Cipher
	audit  *AuditService
	retain int
}

// NewSecretService wires a SecretService. retain > 0 keeps only that many
// versions per secret; 0 keeps every version.
func NewSecretService(store repository.Store, cipher *crypto.Cipher, audit *AuditService, retain int) *SecretService {
	return &SecretService{store: store, cipher: cipher, audit: audit, retain: retain}
}

// Put stores a new version of a secret and returns the version number.
func (s *SecretService) Put(ctx context.Context, actor domain.Actor, name string, value []byte, tags map[string]string) (version int64, err error) {
	if err = s.authorize(actor, domain.PermWrite, name); err != nil {
		return 0, err
	}
	if err = domain.ValidateValue(value); err != nil {
		return 0, err
	}
	if err = s.store.Transaction(ctx, func(tx repository.Store) error {
		var inner error
		version, inner = s.putTx(ctx, tx, actor, name, value, tags, true, domain.OpPut)
		return inner
	}); err != nil {
		s.audit.recordFailure(ctx, actor, domain.OpPut, name, err)
		return 0, err
	}
	return version, nil
}

// Get returns and decrypts one version. version 0 means "current".
func (s *SecretService) Get(ctx context.Context, actor domain.Actor, name string, version int64) (*domain.SecretValue, error) {
	if err := s.authorize(actor, domain.PermRead, name); err != nil {
		return nil, err
	}
	var out *domain.SecretValue
	err := s.store.Transaction(ctx, func(tx repository.Store) error {
		meta, err := tx.Secrets().Find(ctx, name, false)
		if err != nil {
			return err
		}
		want := meta.CurrentVersion
		if version > 0 {
			want = version
		}
		rec, err := tx.Secrets().FindVersion(ctx, name, want)
		if err != nil {
			return err
		}
		plain, err := s.open(name, rec)
		if err != nil {
			return err
		}
		out = &domain.SecretValue{
			Name:      name,
			Version:   rec.Version,
			Value:     plain,
			Tags:      meta.Tags,
			CreatedAt: rec.CreatedAt,
		}
		return s.audit.Record(ctx, tx, actor, domain.OpGet, name, true, fmt.Sprintf("version=%d", want))
	})
	if err != nil {
		s.audit.recordFailure(ctx, actor, domain.OpGet, name, err)
		return nil, err
	}
	return out, nil
}

// List returns secrets visible to the actor, without their values.
func (s *SecretService) List(ctx context.Context, actor domain.Actor, prefix, tag string, limit int) ([]domain.Secret, error) {
	if err := domain.ValidatePrefix(prefix); err != nil {
		return nil, err
	}
	if !actor.Has(domain.PermRead) {
		return nil, fmt.Errorf("%w: listing requires the read permission", domain.ErrPermissionDenied)
	}
	all, err := s.store.Secrets().List(ctx, prefix, 0)
	if err != nil {
		return nil, err
	}
	key, want, hasValue := parseTagFilter(tag)
	out := make([]domain.Secret, 0, len(all))
	for _, item := range all {
		if !actor.Can(domain.PermRead, item.Name) {
			continue
		}
		if key != "" {
			got, ok := item.Tags[key]
			if !ok || (hasValue && got != want) {
				continue
			}
		}
		out = append(out, item)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	err = s.store.Transaction(ctx, func(tx repository.Store) error {
		return s.audit.Record(ctx, tx, actor, domain.OpList, prefix, true, fmt.Sprintf("count=%d", len(out)))
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// History lists version metadata for a secret, newest first.
func (s *SecretService) History(ctx context.Context, actor domain.Actor, name string, limit int) ([]domain.VersionInfo, error) {
	if err := s.authorize(actor, domain.PermRead, name); err != nil {
		return nil, err
	}
	versions, err := s.store.Secrets().ListVersions(ctx, name, limit)
	if err != nil {
		return nil, err
	}
	err = s.store.Transaction(ctx, func(tx repository.Store) error {
		return s.audit.Record(ctx, tx, actor, domain.OpHistory, name, true, fmt.Sprintf("count=%d", len(versions)))
	})
	if err != nil {
		return nil, err
	}
	return versions, nil
}

// Rollback copies an old version into a brand new version. History is never
// rewritten, so a rollback is itself auditable and reversible.
func (s *SecretService) Rollback(ctx context.Context, actor domain.Actor, name string, version int64) (int64, error) {
	if version <= 0 {
		return 0, fmt.Errorf("%w: version must be positive", domain.ErrInvalidArgument)
	}
	if err := s.authorize(actor, domain.PermWrite, name); err != nil {
		return 0, err
	}
	var created int64
	err := s.store.Transaction(ctx, func(tx repository.Store) error {
		rec, err := tx.Secrets().FindVersion(ctx, name, version)
		if err != nil {
			return err
		}
		plain, err := s.open(name, rec)
		if err != nil {
			return err
		}
		var inner error
		created, inner = s.putTx(ctx, tx, actor, name, plain, nil, false, "")
		if inner != nil {
			return inner
		}
		return s.audit.Record(ctx, tx, actor, domain.OpRollback, name, true, fmt.Sprintf("from=%d to=%d", version, created))
	})
	if err != nil {
		s.audit.recordFailure(ctx, actor, domain.OpRollback, name, err)
		return 0, err
	}
	return created, nil
}

// Delete soft deletes a secret, or removes it and its history when hard is set.
func (s *SecretService) Delete(ctx context.Context, actor domain.Actor, name string, hard bool) error {
	op := domain.OpDelete
	if hard {
		op = domain.OpPurge
	}
	if err := s.authorize(actor, domain.PermDelete, name); err != nil {
		s.audit.recordFailure(ctx, actor, op, name, err)
		return err
	}
	err := s.store.Transaction(ctx, func(tx repository.Store) error {
		if err := tx.Secrets().Delete(ctx, name, hard); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, actor, op, name, true, "")
	})
	if err != nil {
		s.audit.recordFailure(ctx, actor, op, name, err)
	}
	return err
}

// putTx performs the write inside an existing transaction. keepTags controls
// whether tags are merged with the previous version (Put) or inherited as-is
// (Rollback). auditOp is the operation name to record; an empty string lets the
// caller write its own, more specific, audit entry.
func (s *SecretService) putTx(ctx context.Context, tx repository.Store, actor domain.Actor, name string, value []byte, tags map[string]string, keepTags bool, auditOp string) (int64, error) {
	var version int64
	existing, err := tx.Secrets().Find(ctx, name, true)
	switch {
	case err == nil:
		version = existing.CurrentVersion + 1
		existing.CurrentVersion = version
		if keepTags && len(tags) > 0 {
			existing.Tags = mergeTags(existing.Tags, tags)
		}
		existing.Deleted = false
		if err := tx.Secrets().Update(ctx, existing); err != nil {
			return 0, err
		}
	case errors.Is(err, domain.ErrNotFound):
		version = 1
		created := &domain.Secret{Name: name, Tags: tags, CurrentVersion: version}
		if err := tx.Secrets().Create(ctx, created); err != nil {
			return 0, err
		}
	default:
		return 0, err
	}

	nonce, ciphertext, err := s.cipher.Seal(value, crypto.AAD(name, version))
	if err != nil {
		return 0, fmt.Errorf("encrypt: %w", err)
	}
	rec := &domain.VersionRecord{
		Version:    version,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		Checksum:   crypto.Checksum(value),
		CreatedAt:  time.Now().UTC(),
		CreatedBy:  actor.ID,
	}
	if err := tx.Secrets().AddVersion(ctx, name, rec); err != nil {
		return 0, err
	}
	if s.retain > 0 {
		if err := tx.Secrets().PruneVersions(ctx, name, int64(s.retain)); err != nil {
			return 0, err
		}
	}
	if auditOp != "" {
		if err := s.audit.Record(ctx, tx, actor, auditOp, name, true, fmt.Sprintf("version=%d", version)); err != nil {
			return 0, err
		}
	}
	return version, nil
}

// open decrypts a stored version and verifies its checksum.
func (s *SecretService) open(name string, rec *domain.VersionRecord) ([]byte, error) {
	plain, err := s.cipher.Open(rec.Nonce, rec.Ciphertext, crypto.AAD(name, rec.Version))
	if err != nil {
		return nil, err
	}
	if got := crypto.Checksum(plain); got != rec.Checksum {
		return nil, fmt.Errorf("%w: checksum mismatch for %q v%d", domain.ErrInternalInvariant, name, rec.Version)
	}
	return plain, nil
}

func (s *SecretService) authorize(actor domain.Actor, perm domain.Perm, name string) error {
	if err := domain.ValidateName(name); err != nil {
		return err
	}
	if !actor.Can(perm, name) {
		return fmt.Errorf("%w: %s on %q", domain.ErrPermissionDenied, perm, name)
	}
	return nil
}

func mergeTags(old, patch map[string]string) map[string]string {
	out := make(map[string]string, len(old)+len(patch))
	for k, v := range old {
		out[k] = v
	}
	for k, v := range patch {
		out[k] = v
	}
	return out
}

// parseTagFilter understands "key" (presence) and "key=value" (match).
func parseTagFilter(tag string) (key, value string, hasValue bool) {
	if tag == "" {
		return "", "", false
	}
	if i := strings.IndexByte(tag, '='); i >= 0 {
		return tag[:i], tag[i+1:], true
	}
	return tag, "", false
}
