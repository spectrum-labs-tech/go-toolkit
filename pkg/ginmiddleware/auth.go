package ginmiddleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/spectrum-labs-tech/go-toolkit/pkg/jwt"
)

// Context keys set by the auth middleware on successful validation.
const (
	// ContextKeyUserID holds the authenticated user's subject (string).
	ContextKeyUserID = "userID"

	// ContextKeyTenantID holds the authenticated tenant id — the token's
	// "tenant_id" claim (string) — and is set only when the token carries one.
	// It is absent when the token has no tenant claim, so handlers should treat
	// a missing value as "untenanted" rather than an error. Setting this claim
	// does not enforce tenant isolation: it is the caller's responsibility to
	// verify the authenticated user belongs to this tenant before granting
	// access (see jwt.TokenOptions.TenantID).
	ContextKeyTenantID = "tenantID"

	// ContextKeyAuthViaCookie is set to true when the token was resolved from
	// a cookie rather than an Authorization header. CSRFProtection checks this
	// to decide whether to enforce the Origin header.
	ContextKeyAuthViaCookie = "authViaCookie"

	// ContextKeyBearerPresent is set to true by OptionalAuthMiddleware when a
	// token was present in the request but failed validation. Handlers can use
	// this to distinguish "no token" from "bad token" and return 401 to trigger
	// a client-side refresh flow.
	ContextKeyBearerPresent = "bearerPresent"
)

// AuthConfig configures the auth middleware.
type AuthConfig struct {
	// Manager is the JWT manager used to verify tokens. Required.
	Manager *jwt.Manager

	// AccessTokenCookie is the cookie name checked when no Authorization header
	// is present. Leave empty to disable cookie auth.
	AccessTokenCookie string
}

// AuthMiddleware requires a valid access token on every request. It resolves
// the token from the Authorization: Bearer header first, then falls back to
// AccessTokenCookie if configured. On success it sets ContextKeyUserID, and
// ContextKeyTenantID when the token carries a "tenant_id" claim.
// Sets ContextKeyAuthViaCookie when the cookie path is used so that
// CSRFProtection can enforce Origin on subsequent middleware.
//
// Returns 401 Unauthorized when no token is present or the token is invalid.
func AuthMiddleware(cfg AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, fromCookie := resolveToken(c, cfg.AccessTokenCookie)
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization required"})
			c.Abort()
			return
		}

		claims, err := cfg.Manager.VerifyAccessToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		setIdentity(c, claims, fromCookie)
		c.Next()
	}
}

// OptionalAuthMiddleware parses the access token when present but does not
// reject unauthenticated requests. Sets ContextKeyUserID (and ContextKeyTenantID
// when the token carries a "tenant_id" claim) when the token is valid. Sets
// ContextKeyBearerPresent when a token is present but invalid, allowing handlers
// to return 401 and trigger a client refresh flow rather than silently treating
// the request as anonymous.
func OptionalAuthMiddleware(cfg AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, fromCookie := resolveToken(c, cfg.AccessTokenCookie)
		if tokenString == "" {
			c.Next()
			return
		}
		c.Set(ContextKeyBearerPresent, true)
		claims, err := cfg.Manager.VerifyAccessToken(tokenString)
		if err == nil {
			setIdentity(c, claims, fromCookie)
		}
		c.Next()
	}
}

// setIdentity records the verified identity from claims onto the context: the
// subject always, the tenant id only when the token carries one, and the
// cookie-auth marker when the token came from a cookie. Shared by AuthMiddleware
// and OptionalAuthMiddleware so both surface the same keys.
func setIdentity(c *gin.Context, claims jwt.Claims, fromCookie bool) {
	c.Set(ContextKeyUserID, claims.Subject)
	if claims.TenantID != "" {
		c.Set(ContextKeyTenantID, claims.TenantID)
	}
	if fromCookie {
		c.Set(ContextKeyAuthViaCookie, true)
	}
}

// resolveToken extracts the access token from the request, trying the
// Authorization: Bearer header first, then the named cookie.
func resolveToken(c *gin.Context, cookieName string) (token string, fromCookie bool) {
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer "), false
	}
	if cookieName != "" {
		if v, err := c.Cookie(cookieName); err == nil && v != "" {
			return v, true
		}
	}
	return "", false
}
