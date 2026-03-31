package main

import (
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

func durationEnv(key string, fallback time.Duration, logger *zap.Logger) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		if logger != nil {
			logger.Warn("Invalid duration env, using fallback",
				zap.String("env", key),
				zap.String("value", raw),
				zap.Duration("fallback", fallback),
				zap.Error(err),
			)
		}
		return fallback
	}

	return value
}
