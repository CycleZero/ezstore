package gormstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"

	"ezstore/internal/domain"
)

// timeNow is a seam for tests that need deterministic timestamps.
var timeNow = func() time.Time { return time.Now() }

type tokenRepo struct{ s *store }

func (r *tokenRepo) Create(ctx context.Context, t *domain.Token, hash string) error {
	m := tokenModel{
		ID:        t.ID,
		Name:      t.Name,
		Hash:      hash,
		Scopes:    encodeStrings(t.Scopes),
		Perms:     encodeStrings(t.Perms),
		ExpiresAt: t.ExpiresAt,
		Enabled:   t.Enabled,
	}
	if err := r.s.db.WithContext(ctx).Create(&m).Error; err != nil {
		if isDuplicate(err) {
			return fmt.Errorf("%w: token %q already exists", domain.ErrConflict, t.Name)
		}
		return err
	}
	return nil
}

func (r *tokenRepo) FindByName(ctx context.Context, name string) (*domain.Token, string, error) {
	var m tokenModel
	if err := r.s.db.WithContext(ctx).Where("name = ?", name).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", fmt.Errorf("%w: token %q", domain.ErrNotFound, name)
		}
		return nil, "", err
	}
	return toToken(m), m.Hash, nil
}

func (r *tokenRepo) FindByHash(ctx context.Context, hash string) (*domain.Token, error) {
	var m tokenModel
	if err := r.s.db.WithContext(ctx).Where("hash = ?", hash).First(&m).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: unknown token", domain.ErrUnauthenticated)
		}
		return nil, err
	}
	return toToken(m), nil
}

func (r *tokenRepo) List(ctx context.Context) ([]domain.Token, error) {
	var rows []tokenModel
	if err := r.s.db.WithContext(ctx).Order("name asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.Token, 0, len(rows))
	for _, m := range rows {
		out = append(out, *toToken(m))
	}
	return out, nil
}

func (r *tokenRepo) Delete(ctx context.Context, name string) error {
	res := r.s.db.WithContext(ctx).Where("name = ?", name).Delete(&tokenModel{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: token %q", domain.ErrNotFound, name)
	}
	return nil
}

// isDuplicate reports a unique constraint violation on either supported driver.
func isDuplicate(err error) bool {
	var myErr *mysql.MySQLError
	if errors.As(err, &myErr) {
		return myErr.Number == 1062
	}
	msg := err.Error()
	return contains(msg, "UNIQUE constraint failed") || contains(msg, "Duplicate entry")
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
