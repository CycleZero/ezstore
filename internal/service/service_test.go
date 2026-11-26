package service_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"ezstore/internal/crypto"
	"ezstore/internal/domain"
	"ezstore/internal/repository/gormstore"
	"ezstore/internal/service"
)

type fixture struct {
	secrets *service.SecretService
	tokens  *service.TokenService
	audit   *service.AuditService
}

func newFixture(t *testing.T, retain int) *fixture {
	t.Helper()
	store, err := gormstore.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	cipher, err := crypto.New(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	audit := service.NewAuditService(store)
	return &fixture{
		secrets: service.NewSecretService(store, cipher, audit, retain),
		tokens:  service.NewTokenService(store),
		audit:   audit,
	}
}

func TestSecretLifecycle(t *testing.T) {
	f := newFixture(t, 0)
	ctx := context.Background()
	sys := domain.SystemActor()

	v1, err := f.secrets.Put(ctx, sys, "team/stripe", []byte("sk_one"), map[string]string{"env": "prod"})
	if err != nil {
		t.Fatalf("put v1: %v", err)
	}
	if v1 != 1 {
		t.Fatalf("first version = %d, want 1", v1)
	}

	got, err := f.secrets.Get(ctx, sys, "team/stripe", 0)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.Value) != "sk_one" || got.Version != 1 {
		t.Fatalf("get = %q v%d", got.Value, got.Version)
	}
	if got.Tags["env"] != "prod" {
		t.Fatalf("tags = %v", got.Tags)
	}

	if _, err := f.secrets.Put(ctx, sys, "team/stripe", []byte("sk_two"), nil); err != nil {
		t.Fatalf("put v2: %v", err)
	}
	old, err := f.secrets.Get(ctx, sys, "team/stripe", 1)
	if err != nil {
		t.Fatalf("get v1: %v", err)
	}
	if string(old.Value) != "sk_one" {
		t.Fatalf("historical value = %q, want sk_one", old.Value)
	}

	versions, err := f.secrets.History(ctx, sys, "team/stripe", 0)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(versions) != 2 || versions[0].Version != 2 {
		t.Fatalf("history = %+v", versions)
	}

	rolled, err := f.secrets.Rollback(ctx, sys, "team/stripe", 1)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rolled != 3 {
		t.Fatalf("rollback created v%d, want v3", rolled)
	}
	back, err := f.secrets.Get(ctx, sys, "team/stripe", 0)
	if err != nil {
		t.Fatalf("get after rollback: %v", err)
	}
	if string(back.Value) != "sk_one" {
		t.Fatalf("value after rollback = %q", back.Value)
	}

	if err := f.secrets.Delete(ctx, sys, "team/stripe", false); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, err := f.secrets.Get(ctx, sys, "team/stripe", 0); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("get after soft delete = %v, want ErrNotFound", err)
	}
	if _, err := f.secrets.History(ctx, sys, "team/stripe", 0); err != nil {
		t.Fatalf("history after soft delete must still work: %v", err)
	}

	if _, err := f.secrets.Put(ctx, sys, "team/stripe", []byte("sk_three"), nil); err != nil {
		t.Fatalf("put after delete: %v", err)
	}
	revived, err := f.secrets.Get(ctx, sys, "team/stripe", 0)
	if err != nil {
		t.Fatalf("get after revive: %v", err)
	}
	if revived.Version != 4 {
		t.Fatalf("revived version = %d, want 4", revived.Version)
	}

	if err := f.secrets.Delete(ctx, sys, "team/stripe", true); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, err := f.secrets.History(ctx, sys, "team/stripe", 0); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("history after purge = %v, want ErrNotFound", err)
	}
}

func TestScopeIsolation(t *testing.T) {
	f := newFixture(t, 0)
	ctx := context.Background()
	sys := domain.SystemActor()

	if _, err := f.secrets.Put(ctx, sys, "team/a/key", []byte("a"), nil); err != nil {
		t.Fatalf("seed a: %v", err)
	}
	if _, err := f.secrets.Put(ctx, sys, "team/b/key", []byte("b"), nil); err != nil {
		t.Fatalf("seed b: %v", err)
	}

	plaintext, _, err := f.tokens.Create(ctx, sys, "agent-a", []string{"team/a/**"}, []string{"read", "write"}, 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	actor, err := f.tokens.Authenticate(ctx, plaintext)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	if _, err := f.secrets.Get(ctx, actor, "team/a/key", 0); err != nil {
		t.Fatalf("scoped read failed: %v", err)
	}
	if _, err := f.secrets.Get(ctx, actor, "team/b/key", 0); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("cross-scope read = %v, want ErrPermissionDenied", err)
	}
	if _, err := f.secrets.Put(ctx, actor, "team/b/key", []byte("x"), nil); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("cross-scope write = %v, want ErrPermissionDenied", err)
	}
	if err := f.secrets.Delete(ctx, actor, "team/a/key", false); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("delete without permission = %v, want ErrPermissionDenied", err)
	}

	items, err := f.secrets.List(ctx, actor, "", "", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != 1 || items[0].Name != "team/a/key" {
		t.Fatalf("list leaked cross-scope names: %+v", items)
	}
}

func TestTokenExpiryAndRevocation(t *testing.T) {
	f := newFixture(t, 0)
	ctx := context.Background()
	sys := domain.SystemActor()

	plaintext, _, err := f.tokens.Create(ctx, sys, "short", []string{"**"}, []string{"read"}, time.Nanosecond)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := f.tokens.Authenticate(ctx, plaintext); !errors.Is(err, domain.ErrTokenExpired) {
		t.Fatalf("expired token = %v, want ErrTokenExpired", err)
	}

	fresh, _, err := f.tokens.Create(ctx, sys, "fresh", []string{"**"}, []string{"read"}, 0)
	if err != nil {
		t.Fatalf("create fresh: %v", err)
	}
	if _, err := f.tokens.Authenticate(ctx, fresh); err != nil {
		t.Fatalf("authenticate fresh: %v", err)
	}
	if err := f.tokens.Revoke(ctx, sys, "fresh"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := f.tokens.Authenticate(ctx, fresh); err == nil {
		t.Fatal("revoked token still authenticates")
	}

	if _, err := f.tokens.Authenticate(ctx, "not-a-token"); !errors.Is(err, domain.ErrUnauthenticated) {
		t.Fatalf("malformed token = %v, want ErrUnauthenticated", err)
	}
}

func TestHistoryRetention(t *testing.T) {
	f := newFixture(t, 2)
	ctx := context.Background()
	sys := domain.SystemActor()

	for i := 0; i < 5; i++ {
		if _, err := f.secrets.Put(ctx, sys, "team/key", []byte{byte('a' + i)}, nil); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	versions, err := f.secrets.History(ctx, sys, "team/key", 0)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("retained %d versions, want 2", len(versions))
	}
	if versions[0].Version != 5 || versions[1].Version != 4 {
		t.Fatalf("retained versions = %+v", versions)
	}
}

func TestAuditChainVerification(t *testing.T) {
	f := newFixture(t, 0)
	ctx := context.Background()
	sys := domain.SystemActor()

	if _, err := f.secrets.Put(ctx, sys, "team/key", []byte("v1"), nil); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := f.secrets.Get(ctx, sys, "team/key", 0); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := f.secrets.List(ctx, sys, "", "", 0); err != nil {
		t.Fatalf("list: %v", err)
	}

	count, err := f.audit.Verify(ctx, sys)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if count < 3 {
		t.Fatalf("verified %d entries, want at least 3", count)
	}

	entries, err := f.audit.Tail(ctx, sys, 1)
	if err != nil {
		t.Fatalf("tail: %v", err)
	}
	if len(entries) != 1 || entries[0].Op != domain.OpList {
		t.Fatalf("tail = %+v", entries)
	}
}

func TestNonAdminCannotReadAudit(t *testing.T) {
	f := newFixture(t, 0)
	ctx := context.Background()
	actor := domain.Actor{ID: "x", Scopes: []string{"**"}, Perms: []string{"read"}}
	if _, err := f.audit.Tail(ctx, actor, 10); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("tail as non-admin = %v, want ErrPermissionDenied", err)
	}
}
