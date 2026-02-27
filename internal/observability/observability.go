package observability

import (
	"context"
	"log/slog"
	"os"
)

func NewLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

func InitTracing(_ context.Context) func() {
	return func() {}
}

func InitMetrics(_ context.Context) func() {
	return func() {}
}
