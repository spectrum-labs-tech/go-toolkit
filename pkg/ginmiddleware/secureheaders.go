package ginmiddleware

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
)

// secureHeadersConfig holds the resolved configuration for SecureHeaders.
type secureHeadersConfig struct {
	frameOptions   string
	noSniff        bool
	referrerPolicy string
	hstsMaxAge     int
	hstsSubDomains bool
	csp            string
	permPolicy     string
}

func defaultSecureHeadersConfig() secureHeadersConfig {
	return secureHeadersConfig{
		frameOptions:   "DENY",
		noSniff:        true,
		referrerPolicy: "strict-origin-when-cross-origin",
		hstsMaxAge:     31536000,
		hstsSubDomains: true,
	}
}

// SecureHeadersOption configures SecureHeaders middleware.
type SecureHeadersOption func(*secureHeadersConfig)

// WithFrameOptions overrides the X-Frame-Options header value.
// Pass an empty string to omit the header entirely.
// The default is "DENY".
func WithFrameOptions(value string) SecureHeadersOption {
	return func(c *secureHeadersConfig) { c.frameOptions = value }
}

// WithReferrerPolicy overrides the Referrer-Policy header value.
// Pass an empty string to omit the header entirely.
// The default is "strict-origin-when-cross-origin".
func WithReferrerPolicy(policy string) SecureHeadersOption {
	return func(c *secureHeadersConfig) { c.referrerPolicy = policy }
}

// WithHSTS overrides the Strict-Transport-Security configuration.
// maxAge is in seconds; set to 0 to omit HSTS entirely.
// The HSTS header is only written for HTTPS requests regardless of this setting.
func WithHSTS(maxAge int, includeSubDomains bool) SecureHeadersOption {
	return func(c *secureHeadersConfig) {
		c.hstsMaxAge = maxAge
		c.hstsSubDomains = includeSubDomains
	}
}

// WithoutHSTS disables the Strict-Transport-Security header.
// Use this when TLS termination happens upstream and the application itself
// is never reached directly over HTTPS.
func WithoutHSTS() SecureHeadersOption {
	return func(c *secureHeadersConfig) { c.hstsMaxAge = 0 }
}

// WithCSP sets the Content-Security-Policy header to policy.
// CSP is omitted by default because the correct policy is application-specific.
func WithCSP(policy string) SecureHeadersOption {
	return func(c *secureHeadersConfig) { c.csp = policy }
}

// WithPermissionsPolicy sets the Permissions-Policy header to policy.
// The header is omitted by default.
func WithPermissionsPolicy(policy string) SecureHeadersOption {
	return func(c *secureHeadersConfig) { c.permPolicy = policy }
}

// SecureHeaders returns a middleware that sets defensive HTTP security headers
// on every response. The default configuration sets:
//
//   - X-Frame-Options: DENY (clickjacking protection)
//   - X-Content-Type-Options: nosniff (MIME sniffing protection)
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains (HTTPS only)
//
// Content-Security-Policy and Permissions-Policy are omitted by default because
// suitable values are highly application-specific. Add them with WithCSP and
// WithPermissionsPolicy.
//
// HSTS is only written when the request is HTTPS (TLS termination at the app, or
// X-Forwarded-Proto: https set by a trusted proxy). This prevents HSTS from
// breaking local HTTP development.
//
//	r := gin.New()
//	r.Use(ginmiddleware.SecureHeaders())
//
//	// With a custom CSP and no HSTS (TLS terminates upstream):
//	r.Use(ginmiddleware.SecureHeaders(
//	    ginmiddleware.WithCSP("default-src 'self'"),
//	    ginmiddleware.WithoutHSTS(),
//	))
func SecureHeaders(opts ...SecureHeadersOption) gin.HandlerFunc {
	cfg := defaultSecureHeadersConfig()
	for _, o := range opts {
		o(&cfg)
	}

	return func(c *gin.Context) {
		if cfg.frameOptions != "" {
			c.Header("X-Frame-Options", cfg.frameOptions)
		}
		if cfg.noSniff {
			c.Header("X-Content-Type-Options", "nosniff")
		}
		if cfg.referrerPolicy != "" {
			c.Header("Referrer-Policy", cfg.referrerPolicy)
		}
		if cfg.hstsMaxAge > 0 && isHTTPS(c) {
			hsts := fmt.Sprintf("max-age=%d", cfg.hstsMaxAge)
			if cfg.hstsSubDomains {
				hsts += "; includeSubDomains"
			}
			c.Header("Strict-Transport-Security", hsts)
		}
		if cfg.csp != "" {
			c.Header("Content-Security-Policy", cfg.csp)
		}
		if cfg.permPolicy != "" {
			c.Header("Permissions-Policy", cfg.permPolicy)
		}
		c.Next()
	}
}

// isHTTPS reports whether the request arrived over TLS, either directly or via
// a reverse proxy that sets X-Forwarded-Proto.
func isHTTPS(c *gin.Context) bool {
	return c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
}
