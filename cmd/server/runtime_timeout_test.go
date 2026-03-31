package main

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestDurationEnv_UsesFallbackWhenUnset(t *testing.T) {
	const key = "TEST_DURATION_ENV_UNSET"
	fallback := 30 * time.Second

	t.Setenv(key, "")
	if got := durationEnv(key, fallback, zap.NewNop()); got != fallback {
		t.Fatalf("durationEnv() = %s, want %s", got, fallback)
	}
}

func TestDurationEnv_ParsesValidDuration(t *testing.T) {
	const key = "TEST_DURATION_ENV_VALID"
	fallback := 30 * time.Second

	t.Setenv(key, "2m15s")
	if got := durationEnv(key, fallback, zap.NewNop()); got != 2*time.Minute+15*time.Second {
		t.Fatalf("durationEnv() = %s, want %s", got, 2*time.Minute+15*time.Second)
	}
}

func TestDurationEnv_UsesFallbackWhenInvalid(t *testing.T) {
	const key = "TEST_DURATION_ENV_INVALID"
	fallback := 45 * time.Second

	t.Setenv(key, "not-a-duration")
	if got := durationEnv(key, fallback, zap.NewNop()); got != fallback {
		t.Fatalf("durationEnv() = %s, want %s", got, fallback)
	}
}
