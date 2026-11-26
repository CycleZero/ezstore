// Package httpapi exposes ezstore over HTTP using Gin. Handlers are thin: they
// decode the request, call the service layer and map domain errors onto status
// codes. No business rule lives here.
package httpapi

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"ezstore/internal/domain"
	"ezstore/internal/service"
)

const actorKey = "ezstore.actor"

// Deps are the collaborators the router needs.
type Deps struct {
	Secrets *service.SecretService
	Tokens  *service.TokenService
	Audit   *service.AuditService
}

// NewRouter builds the Gin engine with every route and middleware wired.
func NewRouter(deps Deps, debug bool) *gin.Engine {
	if !debug {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.Recovery(), accessLog())
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	api := &api{deps: deps}
	v1 := r.Group("/v1", api.requireToken())
	{
		v1.GET("/secrets", api.listSecrets)
		v1.GET("/secrets/get", api.getSecret)
		v1.POST("/secrets", api.putSecret)
		v1.DELETE("/secrets", api.deleteSecret)
		v1.GET("/secrets/versions", api.secretVersions)
		v1.POST("/secrets/rollback", api.rollbackSecret)

		v1.GET("/tokens", api.listTokens)
		v1.POST("/tokens", api.createToken)
		v1.DELETE("/tokens", api.revokeToken)

		v1.GET("/audit", api.tailAudit)
		v1.GET("/audit/verify", api.verifyAudit)
	}
	return r
}

type api struct {
	deps Deps
}

// requireToken authenticates the bearer token and stores the actor on the
// request context.
func (a *api) requireToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			abortWithError(c, domain.ErrUnauthenticated)
			return
		}
		plaintext := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		actor, err := a.deps.Tokens.Authenticate(c.Request.Context(), plaintext)
		if err != nil {
			abortWithError(c, err)
			return
		}
		c.Set(actorKey, actor)
		c.Next()
	}
}

func actorOf(c *gin.Context) domain.Actor {
	v, ok := c.Get(actorKey)
	if !ok {
		return domain.Actor{}
	}
	actor, _ := v.(domain.Actor)
	return actor
}

// accessLog records method, path, status and duration. Request and response
// bodies are never logged, because they may contain secret values.
func accessLog() gin.HandlerFunc {
	logger := log.New(log.Writer(), "", log.LstdFlags)
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		logger.Printf("%s %s %d %s", c.Request.Method, c.Request.URL.Path,
			c.Writer.Status(), time.Since(start).Round(time.Millisecond))
	}
}

// errorBody is the single error shape returned by the API.
type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func abortWithError(c *gin.Context, err error) {
	status, code := statusFor(err)
	var body errorBody
	body.Error.Code = code
	body.Error.Message = err.Error()
	c.AbortWithStatusJSON(status, body)
}

// respondError writes err and, unlike abortWithError, lets the handler finish.
func respondError(c *gin.Context, err error) {
	status, code := statusFor(err)
	var body errorBody
	body.Error.Code = code
	body.Error.Message = err.Error()
	c.JSON(status, body)
}

func statusFor(err error) (int, string) {
	switch {
	case errors.Is(err, domain.ErrUnauthenticated):
		return http.StatusUnauthorized, "unauthenticated"
	case errors.Is(err, domain.ErrTokenExpired):
		return http.StatusUnauthorized, "token_expired"
	case errors.Is(err, domain.ErrPermissionDenied):
		return http.StatusForbidden, "permission_denied"
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, domain.ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, domain.ErrInvalidName),
		errors.Is(err, domain.ErrInvalidArgument),
		errors.Is(err, domain.ErrValueTooLarge):
		return http.StatusBadRequest, "invalid_request"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}
