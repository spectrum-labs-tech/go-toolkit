// Package ginmiddleware provides Gin middleware and helpers for common
// web-service concerns: authentication, CSRF protection, auth cookie
// management, HTTP security headers, cache headers, and per-IP rate limiting.
//
// # Auth
//
// AuthMiddleware and OptionalAuthMiddleware verify JWT access tokens issued by
// a [jwt.Manager]. They check the Authorization: Bearer header first, then fall
// back to a named cookie. On success they set the "userID" context key so
// downstream handlers can call c.GetString("userID").
//
// # CSRF
//
// CSRFProtection must be mounted after an auth middleware so it can inspect
// whether the request was authenticated via cookie. Cookie-authed state-changing
// requests (POST, PUT, PATCH, DELETE) are rejected unless the Origin header
// matches the request host or appears in the trusted-origins list.
//
// # Cookie helpers
//
// SetAuthCookies and ClearAuthCookies manage HttpOnly auth cookies with
// configurable names, paths, and lifetimes via CookieConfig. The Secure
// attribute is set automatically when the connection is TLS or X-Forwarded-Proto
// is "https".
//
// # Security headers
//
// SecureHeaders sets defensive response headers (X-Frame-Options,
// X-Content-Type-Options, Referrer-Policy, Strict-Transport-Security) with
// safe defaults. HSTS is only emitted on HTTPS connections. Use WithCSP,
// WithHSTS, WithoutHSTS, WithFrameOptions, WithReferrerPolicy, and
// WithPermissionsPolicy to customise the defaults.
//
// # Cache headers
//
// SetCache, DefaultPublicCache, NoStore, and SetCacheMaxAge set Cache-Control
// before the handler runs, making them safe to use at the router-group level.
//
// # Rate limiting
//
// IPRateLimit enforces per-IP token-bucket rate limits. Create a shared
// RateLimiter with NewRateLimiter and pass it to IPRateLimit.
//
// # Typical setup
//
//	mgr, _ := jwt.New(jwt.Config{...})
//
//	r := gin.New()
//	r.Use(ginmiddleware.SecureHeaders())
//	r.Use(ginmiddleware.AuthMiddleware(ginmiddleware.AuthConfig{
//	    Manager:           mgr,
//	    AccessTokenCookie: "access_token",
//	}))
//	r.Use(ginmiddleware.CSRFProtection([]string{"https://app.example.com"}))
package ginmiddleware
