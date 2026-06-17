// Package env provides typed helpers for reading environment variables with
// fallback values. Each function reads the named variable at call time, so
// changes made with os.Setenv between calls are reflected immediately.
//
// All helpers treat an empty string the same as an unset variable and return
// the fallback in both cases.
package env

import (
	"os"
	"strconv"
	"strings"
)

// Str returns the value of key, or fallback if the variable is unset or empty.
func Str(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Int64 returns the value of key parsed as a base-10 int64, or fallback if
// the variable is unset, empty, or not a valid integer.
func Int64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

// Bool returns the value of key parsed as a boolean, or fallback if the
// variable is unset, empty, or not a recognised value.
//
// Accepted true values: "1", "true", "yes", "on" (case-insensitive).
// Accepted false values: "0", "false", "no", "off" (case-insensitive).
// Any other non-empty value returns fallback.
func Bool(key string, fallback bool) bool {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return fallback
}

// CSV returns the value of key split on commas with surrounding whitespace
// trimmed from each element. If the variable is unset or empty, fallback is
// split the same way. Returns nil when the resulting list would be empty.
//
// Example: CSV("ALLOWED_ORIGINS", "") with ALLOWED_ORIGINS="http://a.com, http://b.com"
// returns []string{"http://a.com", "http://b.com"}.
func CSV(key, fallback string) []string {
	raw := strings.TrimSpace(Str(key, fallback))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
