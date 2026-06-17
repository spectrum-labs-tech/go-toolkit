package ginmiddleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spectrum-labs-tech/go-toolkit/pkg/ginmiddleware"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func cookieMap(resp *http.Response) map[string]*http.Cookie {
	m := make(map[string]*http.Cookie)
	for _, c := range resp.Cookies() {
		m[c.Name] = c
	}
	return m
}

func TestSetAuthCookies_DefaultNames(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	ginmiddleware.SetAuthCookies(c, "access-tok", "refresh-tok", ginmiddleware.CookieConfig{})

	resp := w.Result()
	cookies := cookieMap(resp)

	if _, ok := cookies["access_token"]; !ok {
		t.Error("expected access_token cookie")
	}
	if _, ok := cookies["refresh_token"]; !ok {
		t.Error("expected refresh_token cookie")
	}
	if cookies["access_token"].Value != "access-tok" {
		t.Errorf("access_token value = %q", cookies["access_token"].Value)
	}
	if cookies["refresh_token"].Value != "refresh-tok" {
		t.Errorf("refresh_token value = %q", cookies["refresh_token"].Value)
	}
}

func TestSetAuthCookies_CustomNames(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	cfg := ginmiddleware.CookieConfig{
		AccessTokenName:  "my_at",
		RefreshTokenName: "my_rt",
	}
	ginmiddleware.SetAuthCookies(c, "a", "r", cfg)

	cookies := cookieMap(w.Result())
	if _, ok := cookies["my_at"]; !ok {
		t.Error("expected my_at cookie")
	}
	if _, ok := cookies["my_rt"]; !ok {
		t.Error("expected my_rt cookie")
	}
}

func TestSetAuthCookies_NoRefreshToken(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	ginmiddleware.SetAuthCookies(c, "access-tok", "", ginmiddleware.CookieConfig{})

	cookies := cookieMap(w.Result())
	if _, ok := cookies["access_token"]; !ok {
		t.Error("expected access_token cookie")
	}
	if _, ok := cookies["refresh_token"]; ok {
		t.Error("refresh_token should not be set when empty")
	}
}

func TestSetAuthCookies_HttpOnly(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	ginmiddleware.SetAuthCookies(c, "at", "rt", ginmiddleware.CookieConfig{})

	for _, cookie := range w.Result().Cookies() {
		if !cookie.HttpOnly {
			t.Errorf("cookie %q must be HttpOnly", cookie.Name)
		}
	}
}

func TestSetAuthCookies_CacheControlNoStore(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	ginmiddleware.SetAuthCookies(c, "at", "rt", ginmiddleware.CookieConfig{})

	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestSetAuthCookies_SecureDefault(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	ginmiddleware.SetAuthCookies(c, "at", "rt", ginmiddleware.CookieConfig{})

	for _, cookie := range w.Result().Cookies() {
		if !cookie.Secure {
			t.Errorf("cookie %q: Secure should default to true", cookie.Name)
		}
	}
}

func TestSetAuthCookies_WithSecureFalse(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)

	cfg := ginmiddleware.CookieConfig{}.WithSecure(false)
	ginmiddleware.SetAuthCookies(c, "at", "rt", cfg)

	for _, cookie := range w.Result().Cookies() {
		if cookie.Secure {
			t.Errorf("cookie %q: Secure should be false when explicitly opted out", cookie.Name)
		}
	}
}

func TestClearAuthCookies(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/logout", nil)

	ginmiddleware.ClearAuthCookies(c, ginmiddleware.CookieConfig{})

	cookies := cookieMap(w.Result())
	at, ok := cookies["access_token"]
	if !ok {
		t.Fatal("expected access_token expiry cookie")
	}
	if at.MaxAge != -1 {
		t.Errorf("access_token MaxAge = %d, want -1", at.MaxAge)
	}
	rt, ok := cookies["refresh_token"]
	if !ok {
		t.Fatal("expected refresh_token expiry cookie")
	}
	if rt.MaxAge != -1 {
		t.Errorf("refresh_token MaxAge = %d, want -1", rt.MaxAge)
	}
}
