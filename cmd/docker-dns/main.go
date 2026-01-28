package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"docker-dns/internal/cloudflare"
	"docker-dns/internal/config"
	"docker-dns/internal/engine"
	"docker-dns/internal/logging"
	"docker-dns/internal/traefik"
	"docker-dns/internal/wanip"
)

var (
	version = "0.0.0-dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if shouldPrintVersion(os.Args) {
		fmt.Printf("version=%s\ncommit=%s\ndate=%s\n", version, commit, date)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger := logging.New(cfg.LogLevel)

	httpClient := &http.Client{
		Timeout: 20 * time.Second,
	}

	cfClient, err := cloudflare.New(cloudflare.Auth{
		APIToken: cfg.CloudflareAPIToken,
		APIKey:   cfg.CloudflareAPIKey,
		Email:    cfg.CloudflareEmail,
	}, httpClient, logger)
	if err != nil {
		logger.Error("Failed to initialize Cloudflare client", "error", err)
		os.Exit(1)
	}

	traefikClient := &traefik.Client{
		BaseURL: cfg.TraefikAPIURL,
		Client:  httpClient,
		Logger:  logger,
	}

	wanProvider := &wanip.Provider{
		Client:      httpClient,
		Logger:      logger,
		MaxRetries:  cfg.WANIPRetries,
		RetryDelay:  cfg.WANIPRetryDelay,
		HTTPTimeout: cfg.WANIPTimeout,
	}

	eng := engine.New(cfg, logger, cfClient, traefikClient, wanProvider)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := eng.Run(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			logger.Info("Engine stopped", "reason", "context canceled")
			return
		}
		logger.Error("Engine stopped", "error", err)
		os.Exit(1)
	}
}

func shouldPrintVersion(args []string) bool {
	for _, arg := range args[1:] {
		switch arg {
		case "--version", "-version", "version":
			return true
		}
	}
	return false
}
