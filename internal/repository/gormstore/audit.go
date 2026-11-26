package gormstore

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"ezstore/internal/domain"
)

type auditRepo struct{ s *store }

func (r *auditRepo) Last(ctx context.Context) (*domain.AuditEntry, error) {
	var m auditModel
	err := r.s.lockQuery(r.s.db.WithContext(ctx)).
		Order("seq desc").
		First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e := toAudit(m)
	return &e, nil
}

func (r *auditRepo) Append(ctx context.Context, e *domain.AuditEntry) error {
	ts := e.TS
	if ts.IsZero() {
		ts = timeNow()
	}
	ts = ts.UTC().Truncate(time.Millisecond)
	m := auditModel{
		TS:       ts.UnixMilli(),
		Actor:    e.Actor,
		Op:       e.Op,
		Name:     e.Name,
		OK:       e.OK,
		Detail:   e.Detail,
		PrevHash: e.PrevHash,
		Hash:     e.Hash,
	}
	if err := r.s.db.WithContext(ctx).Create(&m).Error; err != nil {
		return err
	}
	e.Seq = m.Seq
	e.TS = time.UnixMilli(m.TS).UTC()
	return nil
}

func (r *auditRepo) Tail(ctx context.Context, limit int) ([]domain.AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	var rows []auditModel
	if err := r.s.db.WithContext(ctx).Order("seq desc").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.AuditEntry, 0, len(rows))
	for i := len(rows) - 1; i >= 0; i-- {
		out = append(out, toAudit(rows[i]))
	}
	return out, nil
}

func (r *auditRepo) All(ctx context.Context) ([]domain.AuditEntry, error) {
	var rows []auditModel
	if err := r.s.db.WithContext(ctx).Order("seq asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]domain.AuditEntry, 0, len(rows))
	for _, m := range rows {
		out = append(out, toAudit(m))
	}
	return out, nil
}
