package ginmiddleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spectrum-labs-tech/go-toolkit/pkg/ginmiddleware"
	"golang.org/x/time/rate"
)

func TestIPRateLimit_Allows(t *testing.T) {
	t.Parallel()
	rl := ginmiddleware.NewRateLimiter(rate.Limit(10), 10)

	router := gin.New()
	router.Use(ginmiddleware.IPRateLimit(rl))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestIPRateLimit_Blocks(t *testing.T) {
	t.Parallel()
	// 0 events/sec, burst=0 — every request exceeds the limit.
	rl := ginmiddleware.NewRateLimiter(rate.Limit(0), 0)

	router := gin.New()
	router.Use(ginmiddleware.IPRateLimit(rl))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
}

func TestIPRateLimit_PerIP(t *testing.T) {
	t.Parallel()
	// burst=1 — only one request allowed per IP before refill.
	rl := ginmiddleware.NewRateLimiter(rate.Limit(0), 1)

	router := gin.New()
	router.Use(ginmiddleware.IPRateLimit(rl))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	// First request from 192.0.2.1 — allowed.
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-Forwarded-For", "192.0.2.1")
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("first request: expected 200, got %d", w1.Code)
	}

	// Second request from same IP — blocked (burst exhausted).
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("X-Forwarded-For", "192.0.2.1")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: expected 429, got %d", w2.Code)
	}

	// Request from a different IP — allowed (separate bucket).
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.Header.Set("X-Forwarded-For", "192.0.2.2")
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("different IP: expected 200, got %d", w3.Code)
	}
}
