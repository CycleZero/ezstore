package gormstore

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"ezstore/internal/domain"
)

type secretRepo struct{ s *store }

func (r *secretRepo) Find(ctx context.Context, name string, includeDeleted bool) (*domain.Secret, error) {
	q := r.s.db.WithContext(ctx)
	if includeDeleted {
		q = q.Unscoped()
	}
	var m secretModel
	if err := q.Where("name = ?", name).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: secret %q", domain.ErrNotFound, name)
		}
		return nil, err
	}
	out := toSecret(m)
	return out, nil
}

func (r *secretRepo) Create(ctx context.Context, s *domain.Secret) error {
	m := secretModel{
		ID:             domain.NewID(),
		Name:           s.Name,
		Tags:           encodeTags(s.Tags),
		CurrentVersion: s.CurrentVersion,
	}
	if err := r.s.db.WithContext(ctx).Create(&m).Error; err != nil {
		if isDuplicate(err) {
			return fmt.Errorf("%w: secret %q already exists", domain.ErrConflict, s.Name)
		}
		return err
	}
	return nil
}

func (r *secretRepo) Update(ctx context.Context, s *domain.Secret) error {
	res := r.s.db.WithContext(ctx).Unscoped().Model(&secretModel{}).
		Where("name = ?", s.Name).
		Updates(map[string]any{
			"tags":            encodeTags(s.Tags),
			"current_version": s.CurrentVersion,
			"deleted_at":      nil,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: secret %q", domain.ErrNotFound, s.Name)
	}
	return nil
}

func (r *secretRepo) Delete(ctx context.Context, name string, hard bool) error {
	if hard {
		var m secretModel
		err := r.s.db.WithContext(ctx).Unscoped().Where("name = ?", name).First(&m).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("%w: secret %q", domain.ErrNotFound, name)
		}
		if err != nil {
			return err
		}
		if err := r.s.db.WithContext(ctx).Where("secret_id = ?", m.ID).
			Delete(&versionModel{}).Error; err != nil {
			return err
		}
		return r.s.db.WithContext(ctx).Unscoped().Delete(&m).Error
	}

	res := r.s.db.WithContext(ctx).Where("name = ?", name).Delete(&secretModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: secret %q", domain.ErrNotFound, name)
	}
	return nil
}

func (r *secretRepo) List(ctx context.Context, prefix string, limit int) ([]domain.Secret, error) {
	q := r.s.db.WithContext(ctx).Model(&secretModel{}).Order("name asc")
	if prefix != "" {
		lo, hi := prefixRange(prefix)
		q = q.Where("name >= ? AND name < ?", lo, hi)
	}
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []secretModel
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Secret, 0, len(rows))
	for _, m := range rows {
		out = append(out, *toSecret(m))
	}
	return out, nil
}

func (r *secretRepo) AddVersion(ctx context.Context, secretName string, v *domain.VersionRecord) error {
	id, err := r.secretID(ctx, secretName, true)
	if err != nil {
		return err
	}
	m := versionModel{
		SecretID:   id,
		Version:    v.Version,
		Nonce:      v.Nonce,
		Ciphertext: v.Ciphertext,
		Checksum:   v.Checksum,
		CreatedBy:  v.CreatedBy,
	}
	if v.CreatedAt.IsZero() {
		m.CreatedAt = timeNow()
	} else {
		m.CreatedAt = v.CreatedAt
	}
	return r.s.db.WithContext(ctx).Create(&m).Error
}

func (r *secretRepo) FindVersion(ctx context.Context, secretName string, version int64) (*domain.VersionRecord, error) {
	id, err := r.secretID(ctx, secretName, true)
	if err != nil {
		return nil, err
	}
	var m versionModel
	err = r.s.db.WithContext(ctx).
		Where("secret_id = ? AND version = ?", id, version).
		First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%w: secret %q version %d", domain.ErrNotFound, secretName, version)
	}
	if err != nil {
		return nil, err
	}
	return toVersion(m), nil
}

func (r *secretRepo) ListVersions(ctx context.Context, secretName string, limit int) ([]domain.VersionInfo, error) {
	id, err := r.secretID(ctx, secretName, true)
	if err != nil {
		return nil, err
	}
	q := r.s.db.WithContext(ctx).Model(&versionModel{}).
		Where("secret_id = ?", id).
		Order("version desc")
	if limit > 0 {
		q = q.Limit(limit)
	}
	var rows []versionModel
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.VersionInfo, 0, len(rows))
	for _, m := range rows {
		out = append(out, domain.VersionInfo{
			Version:   m.Version,
			Checksum:  m.Checksum,
			CreatedAt: m.CreatedAt,
			CreatedBy: m.CreatedBy,
		})
	}
	return out, nil
}

func (r *secretRepo) PruneVersions(ctx context.Context, secretName string, keep int64) error {
	if keep <= 0 {
		return nil
	}
	id, err := r.secretID(ctx, secretName, true)
	if err != nil {
		return err
	}
	var max int64
	row := r.s.db.WithContext(ctx).Model(&versionModel{}).
		Select("COALESCE(MAX(version), 0)").
		Where("secret_id = ?", id).Row()
	if err := row.Scan(&max); err != nil {
		return err
	}
	cutoff := max - keep
	if cutoff <= 0 {
		return nil
	}
	return r.s.db.WithContext(ctx).
		Where("secret_id = ? AND version <= ?", id, cutoff).
		Delete(&versionModel{}).Error
}

// secretID resolves the surrogate primary key for a name, including soft
// deleted rows, because their history must stay reachable.
func (r *secretRepo) secretID(ctx context.Context, name string, includeDeleted bool) (string, error) {
	q := r.s.db.WithContext(ctx).Unscoped().Model(&secretModel{}).Select("id")
	if !includeDeleted {
		q = q.Where("deleted_at IS NULL")
	}
	var id string
	row := q.Where("name = ?", name).Row()
	if err := row.Scan(&id); err != nil {
		return "", fmt.Errorf("%w: secret %q", domain.ErrNotFound, name)
	}
	return id, nil
}
