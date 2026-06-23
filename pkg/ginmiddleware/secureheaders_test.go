package ginmiddleware_test

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spectrum-labs-tech/go-toolkit/pkg/ginmiddleware"
)

func secureRouter(opts ...ginmiddleware.SecureHeadersOption) *gin.Engine {
	r := gin.New()
	r.Use(ginmiddleware.SecureHeaders(opts...))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

func TestSecureHeaders_Defaults(t *testing.T) {
	t.Parallel()
	r := secureRouter()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	cases := []struct{ header, want string }{
		{"X-Frame-Options", "DENY"},
		{"X-Content-Type-Options", "nosniff"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
	}
	for _, tc := range cases {
		if got := w.Header().Get(tc.header); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.header, got, tc.want)
		}
	}
}

func TestSecureHeaders_HSTSOnlyOverHTTPS(t *testing.T) {
	t.Parallel()
	r := secureRouter()

	// Plain HTTP — no HSTS.
	wHTTP := httptest.NewRecorder()
	r.ServeHTTP(wHTTP, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := wHTTP.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HTTP: HSTS should be absent, got %q", got)
	}

	// X-Forwarded-Proto: https — HSTS present.
	wHTTPS := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	r.ServeHTTP(wHTTPS, req)
	if got := wHTTPS.Header().Get("Strict-Transport-Security"); got == "" {
		t.Error("HTTPS: HSTS should be present")
	}
}

func TestSecureHeaders_HSTSIncludesSubDomains(t *testing.T) {
	t.Parallel()
	r := secureRouter()

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	r.ServeHTTP(w, req)

	hsts := w.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Fatal("HSTS header missing")
	}
	if !strings.Contains(hsts, "includeSubDomains") {
		t.Errorf("HSTS %q should contain includeSubDomains", hsts)
	}
}

func TestSecureHeaders_WithoutHSTS(t *testing.T) {
	t.Parallel()
	r := secureRouter(ginmiddleware.WithoutHSTS())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("WithoutHSTS: header should be absent, got %q", got)
	}
}

func TestSecureHeaders_WithCustomHSTS(t *testing.T) {
	t.Parallel()
	r := secureRouter(ginmiddleware.WithHSTS(63072000, false))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	r.ServeHTTP(w, req)

	hsts := w.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=63072000") {
		t.Errorf("HSTS %q should contain max-age=63072000", hsts)
	}
	if strings.Contains(hsts, "includeSubDomains") {
		t.Errorf("HSTS %q should not contain includeSubDomains", hsts)
	}
}

func TestSecureHeaders_WithCSP(t *testing.T) {
	t.Parallel()
	r := secureRouter(ginmiddleware.WithCSP("default-src 'self'"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := w.Header().Get("Content-Security-Policy"); got != "default-src 'self'" {
		t.Errorf("CSP = %q, want %q", got, "default-src 'self'")
	}
}

func TestSecureHeaders_NoCSPByDefault(t *testing.T) {
	t.Parallel()
	r := secureRouter()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := w.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("CSP should be absent by default, got %q", got)
	}
}

func TestSecureHeaders_WithFrameOptionsEmpty(t *testing.T) {
	t.Parallel()
	r := secureRouter(ginmiddleware.WithFrameOptions(""))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := w.Header().Get("X-Frame-Options"); got != "" {
		t.Errorf("X-Frame-Options should be absent, got %q", got)
	}
}

func TestSecureHeaders_HSTSOnDirectTLS(t *testing.T) {
	t.Parallel()
	r := secureRouter()

	// req.TLS != nil simulates a connection that terminated TLS at the app
	// (no reverse proxy involved).
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Strict-Transport-Security"); got == "" {
		t.Error("HSTS should be present when req.TLS is non-nil")
	}
}

func TestSecureHeaders_WithFrameOptionsOverride(t *testing.T) {
	t.Parallel()
	r := secureRouter(ginmiddleware.WithFrameOptions("SAMEORIGIN"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := w.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options = %q, want SAMEORIGIN", got)
	}
}

func TestSecureHeaders_WithReferrerPolicyOverride(t *testing.T) {
	t.Parallel()
	r := secureRouter(ginmiddleware.WithReferrerPolicy("no-referrer"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}

func TestSecureHeaders_WithPermissionsPolicy(t *testing.T) {
	t.Parallel()
	r := secureRouter(ginmiddleware.WithPermissionsPolicy("camera=(), microphone=()"))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := w.Header().Get("Permissions-Policy"); got != "camera=(), microphone=()" {
		t.Errorf("Permissions-Policy = %q, want %q", got, "camera=(), microphone=()")
	}
}

