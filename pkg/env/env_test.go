package env_test

import (
	"strings"
	"testing"
	"time"

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

func TestDuration(t *testing.T) {
	t.Setenv("TOOLKIT_TEST_DUR", "30m")
	if got := env.Duration("TOOLKIT_TEST_DUR", time.Second); got != 30*time.Minute {
		t.Errorf("got %v, want 30m", got)
	}
	if got := env.Duration("TOOLKIT_TEST_DUR_MISSING", 5*time.Second); got != 5*time.Second {
		t.Errorf("missing key should return fallback, got %v", got)
	}
	t.Setenv("TOOLKIT_TEST_DUR_BAD", "notaduration")
	if got := env.Duration("TOOLKIT_TEST_DUR_BAD", 7*time.Second); got != 7*time.Second {
		t.Errorf("bad value should return fallback, got %v", got)
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

func TestCheck_AllSet(t *testing.T) {
	t.Setenv("TOOLKIT_CHECK_A", "value-a")
	t.Setenv("TOOLKIT_CHECK_B", "value-b")
	if err := env.Check("TOOLKIT_CHECK_A", "TOOLKIT_CHECK_B"); err != nil {
		t.Errorf("all set: unexpected error: %v", err)
	}
}

func TestCheck_MissingReturnsError(t *testing.T) {
	err := env.Check("TOOLKIT_CHECK_NOT_SET_XYZ")
	if err == nil {
		t.Error("expected error for missing key, got nil")
	}
}

func TestCheck_ReportsAllMissing(t *testing.T) {
	err := env.Check("TOOLKIT_CHECK_MISS_1", "TOOLKIT_CHECK_MISS_2")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "TOOLKIT_CHECK_MISS_1") || !strings.Contains(err.Error(), "TOOLKIT_CHECK_MISS_2") {
		t.Errorf("error %q should name all missing keys", err.Error())
	}
}

func TestRequire_AllSet(t *testing.T) {
	t.Setenv("TOOLKIT_REQ_A", "value-a")
	t.Setenv("TOOLKIT_REQ_B", "value-b")
	// Should not panic.
	env.Require("TOOLKIT_REQ_A", "TOOLKIT_REQ_B")
}

func TestRequire_MissingPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expected panic, got none")
		}
	}()
	env.Require("TOOLKIT_REQ_DEFINITELY_NOT_SET_XYZ")
}

func TestRequire_ReportsAllMissing(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panic value is %T, want string", r)
		}
		if !strings.Contains(msg, "TOOLKIT_REQ_MISS_1") || !strings.Contains(msg, "TOOLKIT_REQ_MISS_2") {
			t.Errorf("panic message %q should name all missing keys", msg)
		}
	}()
	env.Require("TOOLKIT_REQ_MISS_1", "TOOLKIT_REQ_MISS_2")
}

func TestMustStr_Set(t *testing.T) {
	t.Setenv("TOOLKIT_MUST_STR", "hello")
	if got := env.MustStr("TOOLKIT_MUST_STR"); got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestMustStr_MissingPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic, got none")
		}
	}()
	env.MustStr("TOOLKIT_MUST_STR_NOT_SET_XYZ")
}
