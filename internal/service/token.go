package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"ezstore/internal/domain"
	"ezstore/internal/repository"
)

// TokenPrefix identifies ezstore API tokens so they are recognisable in logs
// and secret scanners.
const TokenPrefix = "ezs_"

// TokenService issues and validates API tokens.
type TokenService struct {
	store repository.Store
	now   func() time.Time
}

// NewTokenService wires a TokenService.
func NewTokenService(store repository.Store) *TokenService {
	return &TokenService{store: store, now: func() time.Time { return time.Now().UTC() }}
}

// Create issues a token and returns its plaintext exactly once. Only the
// SHA-256 hash is persisted.
func (s *TokenService) Create(ctx context.Context, actor domain.Actor, name string, scopes, perms []string, ttl time.Duration) (string, *domain.Token, error) {
	if !actor.CanAdmin() {
		return "", nil, fmt.Errorf("%w: issuing tokens requires the admin permission", domain.ErrPermissionDenied)
	}
	if err := domain.ValidateTokenName(name); err != nil {
		return "", nil, err
	}
	normScopes, err := domain.ParseScopes(scopes)
	if err != nil {
		return "", nil, err
	}
	normPerms, err := domain.ParsePerms(perms)
	if err != nil {
		return "", nil, err
	}
	plaintext, hash, err := generateToken()
	if err != nil {
		return "", nil, err
	}
	tok := &domain.Token{
		ID:        domain.NewID(),
		Name:      name,
		Scopes:    normScopes,
		Perms:     normPerms,
		CreatedAt: s.now(),
		Enabled:   true,
	}
	if ttl > 0 {
		exp := s.now().Add(ttl)
		tok.ExpiresAt = &exp
	}
	if err := s.store.Tokens().Create(ctx, tok, hash); err != nil {
		return "", nil, err
	}
	return plaintext, tok, nil
}

// Authenticate resolves a plaintext token to an actor.
func (s *TokenService) Authenticate(ctx context.Context, plaintext string) (domain.Actor, error) {
	if len(plaintext) < len(TokenPrefix) || plaintext[:len(TokenPrefix)] != TokenPrefix {
		return domain.Actor{}, fmt.Errorf("%w: malformed token", domain.ErrUnauthenticated)
	}
	tok, err := s.store.Tokens().FindByHash(ctx, HashToken(plaintext))
	if err != nil {
		return domain.Actor{}, err
	}
	if !tok.Enabled {
		return domain.Actor{}, fmt.Errorf("%w: token %q is disabled", domain.ErrUnauthenticated, tok.Name)
	}
	if tok.Expired(s.now()) {
		return domain.Actor{}, fmt.Errorf("%w: token %q expired at %s", domain.ErrTokenExpired, tok.Name, tok.ExpiresAt.Format(time.RFC3339))
	}
	return domain.Actor{ID: tok.ID, Name: tok.Name, Scopes: tok.Scopes, Perms: tok.Perms}, nil
}

// List returns token metadata. Hashes are never returned.
func (s *TokenService) List(ctx context.Context, actor domain.Actor) ([]domain.Token, error) {
	if !actor.CanAdmin() {
		return nil, fmt.Errorf("%w: listing tokens requires the admin permission", domain.ErrPermissionDenied)
	}
	return s.store.Tokens().List(ctx)
}

// Revoke permanently deletes a token by name.
func (s *TokenService) Revoke(ctx context.Context, actor domain.Actor, name string) error {
	if !actor.CanAdmin() {
		return fmt.Errorf("%w: revoking tokens requires the admin permission", domain.ErrPermissionDenied)
	}
	return s.store.Tokens().Delete(ctx, name)
}

// HashToken returns the hex SHA-256 of a token, which is what gets stored.
func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

func generateToken() (plaintext, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	plaintext = TokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	return plaintext, HashToken(plaintext), nil
}
