package ginmiddleware

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// DefaultPublicCache sets Cache-Control: public, max-age=3600 (1 hour).
// Suitable for static assets or API responses that are safe to cache publicly.
func DefaultPublicCache() gin.HandlerFunc {
	return SetCache("public, max-age=3600")
}

// NoStore sets Cache-Control: no-store. Use this on any response that contains
// user-specific or sensitive data that must not be stored by browsers or
// intermediary caches.
func NoStore() gin.HandlerFunc {
	return SetCache("no-store")
}

// SetCache returns a middleware that sets the Cache-Control header to directive
// before the handler runs. This ensures the header is present even when the
// handler writes the response directly.
func SetCache(directive string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", directive)
		c.Next()
	}
}

// SetCacheMaxAge sets Cache-Control: public, max-age=<seconds>.
func SetCacheMaxAge(seconds int) gin.HandlerFunc {
	return SetCache(fmt.Sprintf("public, max-age=%d", seconds))
}
