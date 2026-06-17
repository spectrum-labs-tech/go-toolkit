package env_test

import (
	"testing"

	"github.com/spectrum-labs-tech/go-toolkit/pkg/env"
)

// Note: t.Setenv cannot be combined with t.Parallel per Go testing rules.

func TestStr(t *testing.T) {
	t.Setenv("TOOLKIT_TEST_STR", "hello")
	if got := env.Str("TOOLKIT_TEST_STR", "default"); got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
	if got := env.Str("TOOLKIT_TEST_STR_MISSING", "default"); got != "default" {
		t.Errorf("got %q, want %q", got, "default")
	}
}

func TestInt64(t *testing.T) {
	t.Setenv("TOOLKIT_TEST_INT", "42")
	if got := env.Int64("TOOLKIT_TEST_INT", 0); got != 42 {
		t.Errorf("got %d, want 42", got)
	}
	if got := env.Int64("TOOLKIT_TEST_INT_MISSING", 99); got != 99 {
		t.Errorf("got %d, want 99", got)
	}
	t.Setenv("TOOLKIT_TEST_INT_BAD", "notanumber")
	if got := env.Int64("TOOLKIT_TEST_INT_BAD", 7); got != 7 {
		t.Errorf("bad value should return fallback, got %d", got)
	}
}

func TestBool(t *testing.T) {
	trueVals := []string{"1", "true", "TRUE", "yes", "YES", "on", "ON"}
	falseVals := []string{"0", "false", "FALSE", "no", "NO", "off", "OFF"}

	for _, v := range trueVals {
		t.Setenv("TOOLKIT_TEST_BOOL", v)
		if !env.Bool("TOOLKIT_TEST_BOOL", false) {
			t.Errorf("%q should parse as true", v)
		}
	}
	for _, v := range falseVals {
		t.Setenv("TOOLKIT_TEST_BOOL", v)
		if env.Bool("TOOLKIT_TEST_BOOL", true) {
			t.Errorf("%q should parse as false", v)
		}
	}
	if env.Bool("TOOLKIT_TEST_BOOL_MISSING", true) != true {
		t.Error("missing key should return fallback true")
	}
}

func TestCSV(t *testing.T) {
	t.Setenv("TOOLKIT_TEST_CSV", "a, b , c")
	got := env.CSV("TOOLKIT_TEST_CSV", "")
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("got %v, want [a b c]", got)
	}
	if got := env.CSV("TOOLKIT_TEST_CSV_MISSING", "x,y"); len(got) != 2 {
		t.Errorf("fallback split failed: %v", got)
	}
	if got := env.CSV("TOOLKIT_TEST_CSV_MISSING", ""); got != nil {
		t.Errorf("empty fallback should return nil, got %v", got)
	}
}
