package ginmiddleware

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimiter maintains a per-key map of token-bucket limiters. Create one
// with NewRateLimiter and share it across the process lifetime; it is safe for
// concurrent use.
//
// Note: the internal client map grows without bound. In deployments exposed to
// a large number of unique IPs (e.g. internet-facing services under attack),
// consider fronting the application with a reverse proxy that performs rate
// limiting at the edge (nginx, Cloudflare, etc.) rather than relying solely on
// this middleware.
type RateLimiter struct {
	r       rate.Limit
	burst   int
	mu      sync.Mutex
	clients map[string]*rate.Limiter
}

// NewRateLimiter returns a RateLimiter that allows r events per second with a
// maximum burst of burst events. A burst of 1 allows exactly one event before
// the rate limit kicks in.
func NewRateLimiter(r rate.Limit, burst int) *RateLimiter {
	return &RateLimiter{
		r:       r,
		burst:   burst,
		clients: make(map[string]*rate.Limiter),
	}
}

func (rl *RateLimiter) get(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	l, ok := rl.clients[key]
	if !ok {
		l = rate.NewLimiter(rl.r, rl.burst)
		rl.clients[key] = l
	}
	return l
}

// IPRateLimit returns a middleware that enforces rl's rate limit per client IP
// as reported by gin's ClientIP (respects X-Forwarded-For / X-Real-IP when
// trusted proxies are configured). Requests that exceed the limit receive 429
// Too Many Requests and the handler chain is aborted.
func IPRateLimit(rl *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !rl.get(ip).Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			c.Abort()
			return
		}
		c.Next()
	}
}
