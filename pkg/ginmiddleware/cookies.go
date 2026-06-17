package ginmiddleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// CookieConfig controls the names, paths, and lifetimes of the auth cookies
// written by SetAuthCookies and ClearAuthCookies. Zero values are replaced
// with the defaults listed on each field.
type CookieConfig struct {
	// AccessTokenName is the cookie name for the access token.
	// Default: "access_token".
	AccessTokenName string

	// RefreshTokenName is the cookie name for the refresh token.
	// Default: "refresh_token".
	RefreshTokenName string

	// RefreshTokenPath scopes the refresh cookie to a specific path so the
	// browser only sends it to the refresh endpoint, limiting exposure.
	// Default: "/api/refresh".
	RefreshTokenPath string

	// AccessTokenMaxAge is the Max-Age in seconds for the access token cookie.
	// Default: 900 (15 minutes).
	AccessTokenMaxAge int

	// RefreshTokenMaxAge is the Max-Age in seconds for the refresh token cookie.
	// Default: 604800 (7 days).
	RefreshTokenMaxAge int
}

func (c *CookieConfig) withDefaults() CookieConfig {
	out := *c
	if out.AccessTokenName == "" {
		out.AccessTokenName = "access_token"
	}
	if out.RefreshTokenName == "" {
		out.RefreshTokenName = "refresh_token"
	}
	if out.RefreshTokenPath == "" {
		out.RefreshTokenPath = "/api/refresh"
	}
	if out.AccessTokenMaxAge == 0 {
		out.AccessTokenMaxAge = 900
	}
	if out.RefreshTokenMaxAge == 0 {
		out.RefreshTokenMaxAge = 604800
	}
	return out
}

// SetAuthCookies writes HttpOnly access and refresh token cookies to the
// response. Cookie attributes:
//
//   - Access token: Path=/, SameSite=Lax.
//   - Refresh token: Path=cfg.RefreshTokenPath, SameSite=Strict (path-scoped
//     so the browser only sends it to the token refresh endpoint).
//   - Secure is set when the connection is TLS or X-Forwarded-Proto is "https".
//   - Cache-Control: no-store is set on the response — auth cookie responses
//     must never be cached by an intermediary.
//
// Pass an empty refreshToken to skip writing the refresh cookie, for example
// when issuing a new access token without rotating the refresh token.
func SetAuthCookies(c *gin.Context, accessToken, refreshToken string, cfg CookieConfig) {
	cfg = cfg.withDefaults()
	secure := isSecure(c)
	c.Header("Cache-Control", "no-store")
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     cfg.AccessTokenName,
		Value:    accessToken,
		Path:     "/",
		MaxAge:   cfg.AccessTokenMaxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	if refreshToken != "" {
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     cfg.RefreshTokenName,
			Value:    refreshToken,
			Path:     cfg.RefreshTokenPath,
			MaxAge:   cfg.RefreshTokenMaxAge,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		})
	}
}

// ClearAuthCookies immediately expires both auth cookies by setting Max-Age=-1.
// Call this on logout or after session revocation to ensure the browser
// discards them on the next response.
func ClearAuthCookies(c *gin.Context, cfg CookieConfig) {
	cfg = cfg.withDefaults()
	secure := isSecure(c)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     cfg.AccessTokenName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     cfg.RefreshTokenName,
		Value:    "",
		Path:     cfg.RefreshTokenPath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// isSecure returns true when the connection is TLS or the request arrived via
// an HTTPS proxy (X-Forwarded-Proto: https).
func isSecure(c *gin.Context) bool {
	return c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
}
