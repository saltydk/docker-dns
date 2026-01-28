package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New returns a configured slog.Logger writing to stdout.
func New(level string) *slog.Logger {
	lvl := parseLevel(level)
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	})
	return slog.New(h)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
