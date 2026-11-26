package httpapi

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"ezstore/internal/domain"
)

// DTOs. Values are base64-free UTF-8 strings; ezstore is an agent-facing store
// for credentials, not a binary blob service.

type putSecretRequest struct {
	Name  string            `json:"name" binding:"required"`
	Value string            `json:"value" binding:"required"`
	Tags  map[string]string `json:"tags"`
}

type putSecretResponse struct {
	Name    string `json:"name"`
	Version int64  `json:"version"`
}

type getSecretResponse struct {
	Name      string            `json:"name"`
	Value     string            `json:"value"`
	Version   int64             `json:"version"`
	Tags      map[string]string `json:"tags"`
	CreatedAt string            `json:"created_at"`
}

type secretSummary struct {
	Name           string            `json:"name"`
	Tags           map[string]string `json:"tags"`
	CurrentVersion int64             `json:"current_version"`
	UpdatedAt      string            `json:"updated_at"`
}

type versionSummary struct {
	Version   int64  `json:"version"`
	Checksum  string `json:"checksum"`
	CreatedAt string `json:"created_at"`
	CreatedBy string `json:"created_by"`
}

type rollbackRequest struct {
	Name    string `json:"name" binding:"required"`
	Version int64  `json:"version" binding:"required"`
}

type createTokenRequest struct {
	Name   string   `json:"name" binding:"required"`
	Scopes []string `json:"scopes" binding:"required"`
	Perms  []string `json:"perms" binding:"required"`
	TTL    string   `json:"ttl"`
}

type createTokenResponse struct {
	Name      string   `json:"name"`
	Token     string   `json:"token"`
	Scopes    []string `json:"scopes"`
	Perms     []string `json:"perms"`
	ExpiresAt string   `json:"expires_at,omitempty"`
}

type tokenSummary struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	Perms     []string `json:"perms"`
	CreatedAt string   `json:"created_at"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	Enabled   bool     `json:"enabled"`
}

type auditSummary struct {
	Seq    uint64 `json:"seq"`
	TS     string `json:"ts"`
	Actor  string `json:"actor"`
	Op     string `json:"op"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Hash   string `json:"hash"`
}

// --- secrets ---

func (a *api) putSecret(c *gin.Context) {
	var req putSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, errInvalid(err.Error()))
		return
	}
	version, err := a.deps.Secrets.Put(c.Request.Context(), actorOf(c), req.Name, []byte(req.Value), req.Tags)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, putSecretResponse{Name: req.Name, Version: version})
}

func (a *api) getSecret(c *gin.Context) {
	name := c.Query("name")
	version, _ := strconv.ParseInt(c.DefaultQuery("version", "0"), 10, 64)
	v, err := a.deps.Secrets.Get(c.Request.Context(), actorOf(c), name, version)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, getSecretResponse{
		Name:      v.Name,
		Value:     string(v.Value),
		Version:   v.Version,
		Tags:      v.Tags,
		CreatedAt: formatTime(v.CreatedAt),
	})
}

func (a *api) listSecrets(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "0"))
	items, err := a.deps.Secrets.List(c.Request.Context(), actorOf(c),
		c.Query("prefix"), c.Query("tag"), limit)
	if err != nil {
		respondError(c, err)
		return
	}
	out := make([]secretSummary, 0, len(items))
	for _, item := range items {
		out = append(out, secretSummary{
			Name:           item.Name,
			Tags:           item.Tags,
			CurrentVersion: item.CurrentVersion,
			UpdatedAt:      formatTime(item.UpdatedAt),
		})
	}
	c.JSON(http.StatusOK, gin.H{"secrets": out, "count": len(out)})
}

func (a *api) deleteSecret(c *gin.Context) {
	purge := c.Query("purge") == "true"
	if err := a.deps.Secrets.Delete(c.Request.Context(), actorOf(c), c.Query("name"), purge); err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true, "purged": purge})
}

func (a *api) secretVersions(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "0"))
	items, err := a.deps.Secrets.History(c.Request.Context(), actorOf(c), c.Query("name"), limit)
	if err != nil {
		respondError(c, err)
		return
	}
	out := make([]versionSummary, 0, len(items))
	for _, item := range items {
		out = append(out, versionSummary{
			Version:   item.Version,
			Checksum:  item.Checksum,
			CreatedAt: formatTime(item.CreatedAt),
			CreatedBy: item.CreatedBy,
		})
	}
	c.JSON(http.StatusOK, gin.H{"versions": out, "count": len(out)})
}

func (a *api) rollbackSecret(c *gin.Context) {
	var req rollbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, errInvalid(err.Error()))
		return
	}
	version, err := a.deps.Secrets.Rollback(c.Request.Context(), actorOf(c), req.Name, req.Version)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, putSecretResponse{Name: req.Name, Version: version})
}

// --- tokens ---

func (a *api) createToken(c *gin.Context) {
	var req createTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, errInvalid(err.Error()))
		return
	}
	var ttl timeDuration
	if req.TTL != "" {
		parsed, err := parseDuration(req.TTL)
		if err != nil {
			respondError(c, errInvalid(err.Error()))
			return
		}
		ttl = timeDuration(parsed)
	}
	plaintext, tok, err := a.deps.Tokens.Create(c.Request.Context(), actorOf(c), req.Name, req.Scopes, req.Perms, ttl.Duration())
	if err != nil {
		respondError(c, err)
		return
	}
	resp := createTokenResponse{
		Name:   tok.Name,
		Token:  plaintext,
		Scopes: tok.Scopes,
		Perms:  tok.Perms,
	}
	if tok.ExpiresAt != nil {
		resp.ExpiresAt = formatTime(*tok.ExpiresAt)
	}
	c.JSON(http.StatusCreated, resp)
}

func (a *api) listTokens(c *gin.Context) {
	items, err := a.deps.Tokens.List(c.Request.Context(), actorOf(c))
	if err != nil {
		respondError(c, err)
		return
	}
	out := make([]tokenSummary, 0, len(items))
	for _, item := range items {
		summary := tokenSummary{
			Name:      item.Name,
			Scopes:    item.Scopes,
			Perms:     item.Perms,
			CreatedAt: formatTime(item.CreatedAt),
			Enabled:   item.Enabled,
		}
		if item.ExpiresAt != nil {
			summary.ExpiresAt = formatTime(*item.ExpiresAt)
		}
		out = append(out, summary)
	}
	c.JSON(http.StatusOK, gin.H{"tokens": out, "count": len(out)})
}

func (a *api) revokeToken(c *gin.Context) {
	if err := a.deps.Tokens.Revoke(c.Request.Context(), actorOf(c), c.Query("name")); err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"revoked": true})
}

// --- audit ---

func (a *api) tailAudit(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	items, err := a.deps.Audit.Tail(c.Request.Context(), actorOf(c), limit)
	if err != nil {
		respondError(c, err)
		return
	}
	out := make([]auditSummary, 0, len(items))
	for _, item := range items {
		out = append(out, auditSummary{
			Seq:    item.Seq,
			TS:     formatTime(item.TS),
			Actor:  item.Actor,
			Op:     item.Op,
			Name:   item.Name,
			OK:     item.OK,
			Detail: item.Detail,
			Hash:   item.Hash,
		})
	}
	c.JSON(http.StatusOK, gin.H{"entries": out, "count": len(out)})
}

func (a *api) verifyAudit(c *gin.Context) {
	n, err := a.deps.Audit.Verify(c.Request.Context(), actorOf(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"verified": true, "entries": n})
}

func errInvalid(msg string) error {
	return &invalidError{msg: msg}
}

type invalidError struct{ msg string }

func (e *invalidError) Error() string { return "invalid request: " + e.msg }
func (e *invalidError) Is(target error) bool {
	return target == domain.ErrInvalidArgument
}
