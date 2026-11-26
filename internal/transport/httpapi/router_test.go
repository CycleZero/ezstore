package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"ezstore/internal/crypto"
	"ezstore/internal/domain"
	"ezstore/internal/repository/gormstore"
	"ezstore/internal/service"
	"ezstore/internal/transport/httpapi"
)

func newRouter(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	store, err := gormstore.Open("sqlite", filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	key, _ := crypto.GenerateKey()
	cipher, _ := crypto.New(key)
	audit := service.NewAuditService(store)
	secrets := service.NewSecretService(store, cipher, audit, 0)
	tokens := service.NewTokenService(store)

	plaintext, _, err := tokens.Create(context.Background(), domain.SystemActor(),
		"test-admin", []string{"**"}, []string{"read", "write", "delete", "admin"}, 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return httpapi.NewRouter(httpapi.Deps{Secrets: secrets, Tokens: tokens, Audit: audit}, false), plaintext
}

func do(t *testing.T, r http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestHTTPSecretLifecycle(t *testing.T) {
	router, token := newRouter(t)

	rec := do(t, router, http.MethodPost, "/v1/secrets", token, map[string]any{
		"name": "team/api-key", "value": "s3cret", "tags": map[string]string{"env": "dev"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("put status = %d body=%s", rec.Code, rec.Body)
	}

	rec = do(t, router, http.MethodGet, "/v1/secrets/get?name=team/api-key", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d body=%s", rec.Code, rec.Body)
	}
	var got struct {
		Value   string            `json:"value"`
		Version int64             `json:"version"`
		Tags    map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Value != "s3cret" || got.Version != 1 || got.Tags["env"] != "dev" {
		t.Fatalf("get payload = %+v", got)
	}

	rec = do(t, router, http.MethodGet, "/v1/secrets?prefix=team/", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body)
	}
	var listed struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listed)
	if listed.Count != 1 {
		t.Fatalf("list count = %d", listed.Count)
	}

	rec = do(t, router, http.MethodDelete, "/v1/secrets?name=team/api-key", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", rec.Code, rec.Body)
	}
	rec = do(t, router, http.MethodGet, "/v1/secrets/get?name=team/api-key", token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete status = %d", rec.Code)
	}

	rec = do(t, router, http.MethodGet, "/v1/audit/verify", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d body=%s", rec.Code, rec.Body)
	}
}

func TestHTTPAuthAndValidation(t *testing.T) {
	router, token := newRouter(t)

	rec := do(t, router, http.MethodGet, "/v1/secrets", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d", rec.Code)
	}

	rec = do(t, router, http.MethodGet, "/v1/secrets", "ezs_bogus", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token status = %d", rec.Code)
	}

	rec = do(t, router, http.MethodPost, "/v1/secrets", token, map[string]any{
		"name": "bad name", "value": "x",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid name status = %d body=%s", rec.Code, rec.Body)
	}

	rec = do(t, router, http.MethodGet, "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d", rec.Code)
	}
}
