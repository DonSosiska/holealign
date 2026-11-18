package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/DonSosiska/holealign/internal/server/config"
)

func nopLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mustLoad(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
