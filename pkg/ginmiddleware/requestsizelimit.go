package ginmiddleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequestSizeLimit returns a middleware that caps the total request body size
// at maxBytes. It provides two layers of protection:
//
//  1. Content-Length early rejection — if the client declares a Content-Length
//     larger than maxBytes the request is aborted with 413 before the body is
//     read at all. Note that Content-Length is client-supplied and may be
//     absent or wrong; layer 2 handles those cases.
//  2. http.MaxBytesReader — wraps the request body so that any read beyond
//     maxBytes returns an error, preventing the server from buffering an
//     unbounded stream to disk or memory even when Content-Length is missing
//     or forged.
//
// Mount this middleware before any handler or binding that reads the body
// (including Gin's multipart form parsing). When it is in place, MaxBytes in
// the upload package is a post-parse sanity check, not exhaustion protection —
// exhaustion protection comes from this middleware.
//
//	r := gin.New()
//	r.Use(ginmiddleware.RequestSizeLimit(50 << 20)) // 50 MB cap
//	r.Use(ginmiddleware.SecureHeaders())
func RequestSizeLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if maxBytes > 0 {
			if c.Request.ContentLength > maxBytes {
				c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
				return
			}
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}
