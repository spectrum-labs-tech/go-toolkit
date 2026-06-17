package ginmiddleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spectrum-labs-tech/go-toolkit/pkg/ginmiddleware"
)

func runCacheMiddleware(t *testing.T, mw gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.Use(mw)
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	router.ServeHTTP(w, req)
	return w
}

func TestDefaultPublicCache(t *testing.T) {
	t.Parallel()
	w := runCacheMiddleware(t, ginmiddleware.DefaultPublicCache())
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("Cache-Control = %q, want public, max-age=3600", got)
	}
}

func TestNoStore(t *testing.T) {
	t.Parallel()
	w := runCacheMiddleware(t, ginmiddleware.NoStore())
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestSetCache_CustomDirective(t *testing.T) {
	t.Parallel()
	w := runCacheMiddleware(t, ginmiddleware.SetCache("private, max-age=60"))
	if got := w.Header().Get("Cache-Control"); got != "private, max-age=60" {
		t.Errorf("Cache-Control = %q, want private, max-age=60", got)
	}
}

func TestSetCacheMaxAge(t *testing.T) {
	t.Parallel()
	w := runCacheMiddleware(t, ginmiddleware.SetCacheMaxAge(7200))
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=7200" {
		t.Errorf("Cache-Control = %q, want public, max-age=7200", got)
	}
}
