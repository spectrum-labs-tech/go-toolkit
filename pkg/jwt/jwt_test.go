package jwt_test

import (
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/spectrum-labs-tech/go-toolkit/pkg/jwt"
)

func newTestManager(t *testing.T) *jwt.Manager {
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

func TestNew_Validation(t *testing.T) {
	t.Parallel()
	longEnough := []byte("this-secret-is-exactly-32-bytes!")
	cases := []struct {
		name string
		cfg  jwt.Config
	}{
		{"missing secret", jwt.Config{Issuer: "x", Audience: "y"}},
		{"secret too short", jwt.Config{Secret: []byte("short"), Issuer: "x", Audience: "y"}},
		{"missing issuer", jwt.Config{Secret: longEnough, Audience: "y"}},
		{"missing audience", jwt.Config{Secret: longEnough, Issuer: "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := jwt.New(tc.cfg); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestAccessToken_RoundTrip(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	token, err := mgr.GenerateAccessToken("user-123")
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	claims, err := mgr.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-123")
	}
	if claims.JTI == "" {
		t.Error("JTI should be non-empty")
	}
}

func TestAccessToken_EmptySubject(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	if _, err := mgr.GenerateAccessToken(""); err == nil {
		t.Error("expected error for empty subject")
	}
}

func TestAccessToken_WrongSecret(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	other, _ := jwt.New(jwt.Config{
		Secret:   []byte("completely-different-secret-here!"),
		Issuer:   "test.example.com",
		Audience: "test.example.com/api",
	})

	token, _ := mgr.GenerateAccessToken("user-1")
	if _, err := other.VerifyAccessToken(token); err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestAccessToken_WrongIssuer(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	other, _ := jwt.New(jwt.Config{
		Secret:   []byte("test-secret-32-bytes-long-enough!"),
		Issuer:   "different.example.com",
		Audience: "test.example.com/api",
	})

	token, _ := mgr.GenerateAccessToken("user-1")
	if _, err := other.VerifyAccessToken(token); err == nil {
		t.Error("expected error for wrong issuer")
	}
}

func TestAccessToken_EnforcesIssAud(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	// Craft a token without iss/aud — must be rejected.
	raw := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := raw.SignedString([]byte("test-secret-32-bytes-long-enough!"))

	if _, err := mgr.VerifyAccessToken(tokenString); err == nil {
		t.Error("expected error for token missing iss/aud")
	}
}

func TestAccessToken_Expired(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	raw := gojwt.NewWithClaims(gojwt.SigningMethodHS256, gojwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(-time.Minute).Unix(),
		"iss": "test.example.com",
		"aud": []string{"test.example.com/api"},
	})
	tokenString, _ := raw.SignedString([]byte("test-secret-32-bytes-long-enough!"))

	if _, err := mgr.VerifyAccessToken(tokenString); err == nil {
		t.Error("expected error for expired token")
	}
}

func TestRefreshToken_RoundTrip(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	token, err := mgr.GenerateRefreshToken("user-456")
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}

	claims, err := mgr.VerifyRefreshToken(token)
	if err != nil {
		t.Fatalf("VerifyRefreshToken: %v", err)
	}
	if claims.Subject != "user-456" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-456")
	}
	if claims.JTI == "" {
		t.Error("JTI should be non-empty")
	}
}

func TestRefreshToken_RejectsAccessToken(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	accessToken, _ := mgr.GenerateAccessToken("user-1")
	if _, err := mgr.VerifyRefreshToken(accessToken); err == nil {
		t.Error("expected error: access token used as refresh token")
	}
}

func TestOAuthCode_RoundTrip(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	code, err := mgr.GenerateOAuthCode("user-789")
	if err != nil {
		t.Fatalf("GenerateOAuthCode: %v", err)
	}

	subject, jti, err := mgr.VerifyOAuthCode(code)
	if err != nil {
		t.Fatalf("VerifyOAuthCode: %v", err)
	}
	if subject != "user-789" {
		t.Errorf("subject = %q, want %q", subject, "user-789")
	}
	if jti == "" {
		t.Error("jti should be non-empty for replay prevention")
	}
}

func TestOAuthCode_UniqueJTI(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	_, jti1, _ := mgr.VerifyOAuthCode(func() string { c, _ := mgr.GenerateOAuthCode("u"); return c }())
	_, jti2, _ := mgr.VerifyOAuthCode(func() string { c, _ := mgr.GenerateOAuthCode("u"); return c }())
	if jti1 == jti2 {
		t.Error("each code must have a unique jti")
	}
}

func TestOAuthCode_RejectsAccessToken(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	accessToken, _ := mgr.GenerateAccessToken("user-1")
	if _, _, err := mgr.VerifyOAuthCode(accessToken); err == nil {
		t.Error("expected error: access token used as oauth code")
	}
}

func TestOAuthCode_RejectsRefreshToken(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)

	refreshToken, _ := mgr.GenerateRefreshToken("user-1")
	if _, _, err := mgr.VerifyOAuthCode(refreshToken); err == nil {
		t.Error("expected error: refresh token used as oauth code")
	}
}

func TestDefaultTTLs(t *testing.T) {
	t.Parallel()
	mgr, _ := jwt.New(jwt.Config{
		Secret:   []byte("test-secret-32-bytes-long-enough!"),
		Issuer:   "x",
		Audience: "y",
		// TTLs omitted — should use defaults
	})
	if mgr.AccessTokenTTL() != 15*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want 15m", mgr.AccessTokenTTL())
	}
	if mgr.RefreshTokenTTL() != 7*24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want 168h", mgr.RefreshTokenTTL())
	}
}
