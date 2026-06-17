package ginmiddleware

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// CSRFProtection guards against cross-site request forgery for cookie-authed
// requests. It must be mounted after an auth middleware that sets
// ContextKeyAuthViaCookie so it can distinguish bearer-authed requests (which
// are not CSRF-vulnerable) from cookie-authed ones.
//
// Logic:
//   - Safe methods (GET, HEAD, OPTIONS) always pass through.
//   - Requests without ContextKeyAuthViaCookie pass through (bearer auth is not
//     forgeable cross-site without JavaScript cooperation).
//   - For cookie-authed non-safe requests, the Origin header is extracted (with
//     Referer as fallback). A missing Origin is allowed — SameSite cookie
//     scoping covers that path. A present Origin that does not match the request
//     host is blocked unless it appears in trustedOrigins.
//
// trustedOrigins should be exact origin strings ("https://app.example.com").
// Use it for known first-party origins that legitimately cross host boundaries,
// such as a frontend on a different subdomain.
func CSRFProtection(trustedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()
			return
		}

		if _, viaCookie := c.Get(ContextKeyAuthViaCookie); !viaCookie {
			c.Next()
			return
		}

		origin := c.GetHeader("Origin")
		if origin == "" {
			if ref := c.GetHeader("Referer"); ref != "" {
				if u, err := url.Parse(ref); err == nil {
					origin = u.Scheme + "://" + u.Host
				}
			}
		}

		if origin == "" {
			c.Next()
			return
		}

		u, err := url.Parse(origin)
		if err != nil || !hostMatches(u.Host, c.Request.Host) {
			if !isTrustedOrigin(origin, trustedOrigins) {
				c.JSON(http.StatusForbidden, gin.H{"error": "CSRF check failed"})
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

func isTrustedOrigin(origin string, trusted []string) bool {
	for _, t := range trusted {
		if t == origin {
			return true
		}
	}
	return false
}

func hostMatches(originHost, requestHost string) bool {
	return strings.EqualFold(stripPort(originHost), stripPort(requestHost))
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
