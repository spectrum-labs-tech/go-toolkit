package ginmiddleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spectrum-labs-tech/go-toolkit/pkg/ginmiddleware"
	"github.com/spectrum-labs-tech/go-toolkit/pkg/jwt"
)

// csrfRouter builds a test router with CSRF protection mounted after auth.
// The route handler marks success by returning 200.
func csrfRouter(mgr *jwt.Manager, cookieName string) *gin.Engine {
	router := gin.New()
	router.Use(ginmiddleware.AuthMiddleware(ginmiddleware.AuthConfig{
		Manager:           mgr,
		AccessTokenCookie: cookieName,
	}))
	router.Use(ginmiddleware.CSRFProtection([]string{"https://trusted.example.com"}))
	router.POST("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	router.HEAD("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	router.OPTIONS("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	return router
}

func TestCSRF_SafeMethodsPassThrough(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("u")

	router := csrfRouter(mgr, "access_token")

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", method, w.Code)
		}
	}
}

func TestCSRF_BearerAuthExempt(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("u")

	router := csrfRouter(mgr, "access_token")

	// POST with Bearer header — no cookie, so CSRF doesn't apply.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Origin", "https://evil.example.com")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Bearer POST with mismatched origin should pass: got %d", w.Code)
	}
}

func TestCSRF_CookieAuth_SameOriginAllowed(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("u")

	router := csrfRouter(mgr, "access_token")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Host = "example.com"
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("Origin", "http://example.com")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("same-origin POST should pass: got %d", w.Code)
	}
}

func TestCSRF_CookieAuth_CrossOriginBlocked(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("u")

	router := csrfRouter(mgr, "access_token")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Host = "example.com"
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("Origin", "https://evil.example.com")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin POST should be blocked: got %d", w.Code)
	}
}

func TestCSRF_TrustedOriginAllowed(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("u")

	router := csrfRouter(mgr, "access_token")

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Host = "example.com"
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("Origin", "https://trusted.example.com")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("trusted origin POST should pass: got %d", w.Code)
	}
}

func TestCSRF_MissingOriginAllowed(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("u")

	router := csrfRouter(mgr, "access_token")

	// No Origin header — allowed (same-site form submit scenario).
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("missing origin should pass: got %d", w.Code)
	}
}
