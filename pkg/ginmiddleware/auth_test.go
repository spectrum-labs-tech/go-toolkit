package ginmiddleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spectrum-labs-tech/go-toolkit/pkg/ginmiddleware"
	"github.com/spectrum-labs-tech/go-toolkit/pkg/jwt"
)

func newTestJWTManager(t *testing.T) *jwt.Manager {
	t.Helper()
	mgr, err := jwt.New(jwt.Config{
		Secret:   []byte("test-secret-32-bytes-long-enough!"),
		Issuer:   "test.example.com",
		Audience: "test.example.com/api",
	})
	if err != nil {
		t.Fatalf("jwt.New: %v", err)
	}
	return mgr
}

func TestAuthMiddleware_BearerAllowed(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("user-1")

	router := gin.New()
	router.Use(ginmiddleware.AuthMiddleware(ginmiddleware.AuthConfig{Manager: mgr}))
	router.GET("/", func(c *gin.Context) {
		uid, _ := c.Get(ginmiddleware.ContextKeyUserID)
		c.String(http.StatusOK, uid.(string))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "user-1" {
		t.Errorf("userID = %q, want user-1", w.Body.String())
	}
}

func TestAuthMiddleware_CookieAllowed(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("user-cookie")

	router := gin.New()
	router.Use(ginmiddleware.AuthMiddleware(ginmiddleware.AuthConfig{
		Manager:           mgr,
		AccessTokenCookie: "access_token",
	}))
	router.GET("/", func(c *gin.Context) {
		viaCookie, _ := c.Get(ginmiddleware.ContextKeyAuthViaCookie)
		if viaCookie != true {
			c.String(http.StatusInternalServerError, "not via cookie")
			return
		}
		uid, _ := c.Get(ginmiddleware.ContextKeyUserID)
		c.String(http.StatusOK, uid.(string))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.String() != "user-cookie" {
		t.Errorf("userID = %q, want user-cookie", w.Body.String())
	}
}

func TestAuthMiddleware_SetsTenantID(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("user-1", jwt.TokenOptions{TenantID: "tenant-x"})

	router := gin.New()
	router.Use(ginmiddleware.AuthMiddleware(ginmiddleware.AuthConfig{Manager: mgr}))
	router.GET("/", func(c *gin.Context) {
		tid, _ := c.Get(ginmiddleware.ContextKeyTenantID)
		c.String(http.StatusOK, tid.(string))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "tenant-x" {
		t.Errorf("tenantID = %q, want tenant-x", w.Body.String())
	}
}

func TestAuthMiddleware_NoTenantClaimLeavesTenantUnset(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("user-1") // no tenant claim

	router := gin.New()
	router.Use(ginmiddleware.AuthMiddleware(ginmiddleware.AuthConfig{Manager: mgr}))
	router.GET("/", func(c *gin.Context) {
		if _, ok := c.Get(ginmiddleware.ContextKeyTenantID); ok {
			c.String(http.StatusInternalServerError, "tenantID should be unset")
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOptionalAuthMiddleware_SetsTenantID(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("opt-user", jwt.TokenOptions{TenantID: "tenant-y"})

	router := gin.New()
	router.Use(ginmiddleware.OptionalAuthMiddleware(ginmiddleware.AuthConfig{Manager: mgr}))
	router.GET("/", func(c *gin.Context) {
		tid, _ := c.Get(ginmiddleware.ContextKeyTenantID)
		c.String(http.StatusOK, tid.(string))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "tenant-y" {
		t.Errorf("tenantID = %q, want tenant-y", w.Body.String())
	}
}

func TestAuthMiddleware_NoToken(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)

	router := gin.New()
	router.Use(ginmiddleware.AuthMiddleware(ginmiddleware.AuthConfig{Manager: mgr}))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)

	router := gin.New()
	router.Use(ginmiddleware.AuthMiddleware(ginmiddleware.AuthConfig{Manager: mgr}))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not.a.real.token")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestOptionalAuthMiddleware_ValidToken(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)
	token, _ := mgr.GenerateAccessToken("opt-user")

	router := gin.New()
	router.Use(ginmiddleware.OptionalAuthMiddleware(ginmiddleware.AuthConfig{Manager: mgr}))
	router.GET("/", func(c *gin.Context) {
		uid, _ := c.Get(ginmiddleware.ContextKeyUserID)
		c.String(http.StatusOK, uid.(string))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != "opt-user" {
		t.Errorf("userID = %q, want opt-user", w.Body.String())
	}
}

func TestOptionalAuthMiddleware_NoToken(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)

	router := gin.New()
	router.Use(ginmiddleware.OptionalAuthMiddleware(ginmiddleware.AuthConfig{Manager: mgr}))
	router.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 (unauthenticated allowed), got %d", w.Code)
	}
}

func TestOptionalAuthMiddleware_InvalidTokenSetsBearer(t *testing.T) {
	t.Parallel()
	mgr := newTestJWTManager(t)

	router := gin.New()
	router.Use(ginmiddleware.OptionalAuthMiddleware(ginmiddleware.AuthConfig{Manager: mgr}))
	router.GET("/", func(c *gin.Context) {
		_, hasUID := c.Get(ginmiddleware.ContextKeyUserID)
		bp, _ := c.Get(ginmiddleware.ContextKeyBearerPresent)
		if hasUID {
			c.String(http.StatusInternalServerError, "should not have userID")
			return
		}
		if bp != true {
			c.String(http.StatusInternalServerError, "bearerPresent not set")
			return
		}
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad.token.here")
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
