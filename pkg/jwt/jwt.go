// Package jwt provides a Manager for issuing and validating signed JSON Web
// Tokens. Three token types are supported:
//
//   - Access tokens: short-lived bearer credentials (default 15 minutes).
//   - Refresh tokens: long-lived credentials used to obtain new access tokens
//     (default 7 days). Distinguished from access tokens by a "purpose":"refresh"
//     claim so the two types cannot be substituted for each other.
//   - OAuth exchange codes: single-use, very short-lived codes (default 60 s)
//     for the authorization-code grant. Each code carries a unique JTI; callers
//     must record the JTI on first use and reject any reuse to prevent replay.
//
// All tokens are signed with HMAC-SHA256. The Manager enforces iss, aud, and
// exp on every Verify call; tokens that lack any of these claims are rejected.
// Identity is carried exclusively in the "sub" claim — no legacy user_id claim
// is written or read.
//
// Typical setup:
//
//	mgr, err := jwt.New(jwt.Config{
//	    Secret:   []byte(os.Getenv("JWT_SECRET")),
//	    Issuer:   "myapp.example.com",
//	    Audience: "myapp.example.com/api",
//	})
package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Sentinel errors returned by Verify methods.
var (
	// ErrInvalidToken is returned when a token cannot be parsed, has an invalid
	// signature, is expired, or fails iss/aud validation.
	ErrInvalidToken = errors.New("jwt: invalid token")

	// ErrInvalidClaims is returned when a token is structurally valid but its
	// claims cannot be extracted into the expected shape.
	ErrInvalidClaims = errors.New("jwt: invalid claims")

	// ErrMissingSubject is returned when generating a token with an empty
	// subject or when a verified token carries no "sub" claim.
	ErrMissingSubject = errors.New("jwt: missing subject")
)

// Config holds the parameters for a Manager. Secret, Issuer, and Audience are
// required; TTL fields default to sensible values when zero.
type Config struct {
	// Secret is the HMAC-SHA256 signing key. Must be non-empty.
	Secret []byte

	// Issuer is written as the "iss" claim on generation and enforced on
	// validation. Use a stable URI that identifies your service.
	Issuer string

	// Audience is written as the "aud" claim on generation and enforced on
	// validation. Use a URI that identifies the intended recipient API.
	Audience string

	// AccessTokenTTL controls how long access tokens remain valid.
	// Default: 15 minutes.
	AccessTokenTTL time.Duration

	// RefreshTokenTTL controls how long refresh tokens remain valid.
	// Default: 7 days.
	RefreshTokenTTL time.Duration

	// OAuthCodeTTL controls how long OAuth exchange codes remain valid.
	// Default: 60 seconds.
	OAuthCodeTTL time.Duration
}

// Claims holds the identity fields extracted from a verified token.
type Claims struct {
	// Subject is the "sub" claim — the identity of the token's owner.
	Subject string

	// JTI is the unique token identifier. Always non-empty; use it to detect
	// replay of OAuth exchange codes.
	JTI string

	// TenantID is the value of the "tenant_id" claim. Empty when the token was
	// issued without one — callers that do not use multi-tenancy can ignore it.
	TenantID string
}

// TokenOptions carries optional per-token parameters. Pass a single TokenOptions
// value to any Generate method; fields at their zero value are omitted from the
// token. When multiple values are supplied only the first is used.
type TokenOptions struct {
	// TenantID is written as the "tenant_id" claim when non-empty. Tokens
	// verified without a "tenant_id" claim return Claims.TenantID == "".
	TenantID string
}

// Manager handles JWT generation and validation. Construct one with New and
// inject it wherever tokens are issued or verified.
type Manager struct {
	cfg Config
}

// minSecretLen is the minimum acceptable HMAC-SHA256 key length. RFC 2104
// recommends a key at least as long as the hash output (32 bytes for SHA-256).
const minSecretLen = 32

// New constructs a Manager from cfg. Returns an error if Secret, Issuer, or
// Audience are empty or if Secret is shorter than 32 bytes. Zero TTL values
// are replaced with their defaults.
func New(cfg Config) (*Manager, error) {
	if len(cfg.Secret) == 0 {
		return nil, errors.New("jwt: secret is required")
	}
	if len(cfg.Secret) < minSecretLen {
		return nil, fmt.Errorf("jwt: secret must be at least %d bytes (got %d)", minSecretLen, len(cfg.Secret))
	}
	if cfg.Issuer == "" {
		return nil, errors.New("jwt: issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("jwt: audience is required")
	}
	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = 15 * time.Minute
	}
	if cfg.RefreshTokenTTL <= 0 {
		cfg.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	if cfg.OAuthCodeTTL <= 0 {
		cfg.OAuthCodeTTL = 60 * time.Second
	}
	return &Manager{cfg: cfg}, nil
}

// AccessTokenTTL returns the configured access token lifetime.
func (m *Manager) AccessTokenTTL() time.Duration { return m.cfg.AccessTokenTTL }

// RefreshTokenTTL returns the configured refresh token lifetime.
func (m *Manager) RefreshTokenTTL() time.Duration { return m.cfg.RefreshTokenTTL }

// GenerateAccessToken issues a signed access token for subject. Pass an optional
// TokenOptions to include extra claims such as TenantID. Returns ErrMissingSubject
// if subject is empty.
func (m *Manager) GenerateAccessToken(subject string, opts ...TokenOptions) (string, error) {
	if subject == "" {
		return "", ErrMissingSubject
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": subject,
		"iat": now.Unix(),
		"exp": now.Add(m.cfg.AccessTokenTTL).Unix(),
		"jti": uuid.NewString(),
		"iss": m.cfg.Issuer,
		"aud": []string{m.cfg.Audience},
	}
	if len(opts) > 0 && opts[0].TenantID != "" {
		claims["tenant_id"] = opts[0].TenantID
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.cfg.Secret)
}

// VerifyAccessToken validates tokenString as an access token and returns its
// claims. Enforces signature, exp, iss, and aud. Returns ErrInvalidToken if
// any check fails.
func (m *Manager) VerifyAccessToken(tokenString string) (Claims, error) {
	return m.parse(tokenString, "")
}

// GenerateRefreshToken issues a signed refresh token for subject. The token
// carries a "purpose":"refresh" claim so it cannot be accepted by
// VerifyAccessToken. Pass an optional TokenOptions to include extra claims such
// as TenantID. Returns ErrMissingSubject if subject is empty.
func (m *Manager) GenerateRefreshToken(subject string, opts ...TokenOptions) (string, error) {
	if subject == "" {
		return "", ErrMissingSubject
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":     subject,
		"iat":     now.Unix(),
		"exp":     now.Add(m.cfg.RefreshTokenTTL).Unix(),
		"jti":     uuid.NewString(),
		"iss":     m.cfg.Issuer,
		"aud":     []string{m.cfg.Audience},
		"purpose": "refresh",
	}
	if len(opts) > 0 && opts[0].TenantID != "" {
		claims["tenant_id"] = opts[0].TenantID
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.cfg.Secret)
}

// VerifyRefreshToken validates tokenString as a refresh token and returns its
// claims. Enforces signature, exp, iss, aud, and purpose. Returns
// ErrInvalidToken if any check fails, including if an access token is supplied.
func (m *Manager) VerifyRefreshToken(tokenString string) (Claims, error) {
	return m.parse(tokenString, "refresh")
}

// GenerateOAuthCode issues a short-lived OAuth authorization-code token for
// subject. The code carries a unique JTI for replay detection; callers must
// store and mark the JTI consumed on first use. Pass an optional TokenOptions
// to include extra claims such as TenantID. Returns ErrMissingSubject if
// subject is empty.
func (m *Manager) GenerateOAuthCode(subject string, opts ...TokenOptions) (string, error) {
	if subject == "" {
		return "", ErrMissingSubject
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":     subject,
		"iat":     now.Unix(),
		"exp":     now.Add(m.cfg.OAuthCodeTTL).Unix(),
		"jti":     uuid.NewString(),
		"iss":     m.cfg.Issuer,
		"aud":     []string{m.cfg.Audience},
		"purpose": "oauth_exchange",
	}
	if len(opts) > 0 && opts[0].TenantID != "" {
		claims["tenant_id"] = opts[0].TenantID
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.cfg.Secret)
}

// VerifyOAuthCode validates tokenString as an OAuth exchange code and returns
// the subject and JTI. The caller must check the JTI against a consumed-codes
// store and reject it if already seen. Returns ErrInvalidToken if the token is
// invalid, expired, or is not an OAuth exchange code.
func (m *Manager) VerifyOAuthCode(tokenString string) (subject, jti string, err error) {
	claims, err := m.parse(tokenString, "oauth_exchange")
	if err != nil {
		return "", "", err
	}
	return claims.Subject, claims.JTI, nil
}

// parse is the shared validation path. If purpose is non-empty the "purpose"
// claim must match exactly, preventing cross-type token substitution.
func (m *Manager) parse(tokenString, purpose string) (Claims, error) {
	token, err := jwt.Parse(tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("jwt: unexpected signing method: %v", token.Header["alg"])
			}
			return m.cfg.Secret, nil
		},
		jwt.WithIssuer(m.cfg.Issuer),
		jwt.WithAudience(m.cfg.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return Claims{}, ErrInvalidToken
	}
	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return Claims{}, ErrInvalidClaims
	}
	if purpose != "" {
		if got, _ := mapClaims["purpose"].(string); got != purpose {
			return Claims{}, fmt.Errorf("%w: unexpected purpose %q", ErrInvalidToken, got)
		}
	}
	sub, _ := mapClaims["sub"].(string)
	if sub == "" {
		return Claims{}, ErrMissingSubject
	}
	jti, _ := mapClaims["jti"].(string)
	tenantID, _ := mapClaims["tenant_id"].(string)
	return Claims{Subject: sub, JTI: jti, TenantID: tenantID}, nil
}
