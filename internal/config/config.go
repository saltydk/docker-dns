package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultIPVersion       = "both"
	defaultDelaySeconds    = 60
	defaultStartupDelaySec = 10
	defaultWANIPTimeoutSec = 5
	defaultWANIPRetries    = 3
	defaultWANIPRetryDelay = 5

	defaultCFRetries  = 3
	defaultCFMinDelay = 4
	defaultCFMaxDelay = 10
)

// Config holds runtime configuration loaded from environment variables.
type Config struct {
	CloudflareAPIKey       string
	CloudflareEmail        string
	CloudflareAPIToken     string
	CloudflareProxyDefault bool

	TraefikAPIURL      string
	TraefikEntrypoints []string
	CustomURLs         []string

	IPVersion    string
	Delay        time.Duration
	StartupDelay time.Duration

	WANIPTimeout    time.Duration
	WANIPRetries    int
	WANIPRetryDelay time.Duration
	CFRetryAttempts int
	CFRetryMinDelay time.Duration
	CFRetryMaxDelay time.Duration

	LogLevel string
}

// Load parses environment variables and validates configuration.
func Load() (Config, error) {
	cfg := Config{
		IPVersion:       defaultIPVersion,
		Delay:           time.Duration(defaultDelaySeconds) * time.Second,
		StartupDelay:    time.Duration(defaultStartupDelaySec) * time.Second,
		WANIPTimeout:    time.Duration(defaultWANIPTimeoutSec) * time.Second,
		WANIPRetries:    defaultWANIPRetries,
		WANIPRetryDelay: time.Duration(defaultWANIPRetryDelay) * time.Second,
		CFRetryAttempts: defaultCFRetries,
		CFRetryMinDelay: time.Duration(defaultCFMinDelay) * time.Second,
		CFRetryMaxDelay: time.Duration(defaultCFMaxDelay) * time.Second,
		LogLevel:        "info",
	}

	cfg.CloudflareAPIKey = strings.TrimSpace(os.Getenv("CLOUDFLARE_API_KEY"))
	cfg.CloudflareEmail = strings.TrimSpace(os.Getenv("CLOUDFLARE_EMAIL"))
	cfg.CloudflareAPIToken = strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN"))

	if v, ok := os.LookupEnv("CLOUDFLARE_PROXY_DEFAULT"); ok {
		b, err := parseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid CLOUDFLARE_PROXY_DEFAULT: %w", err)
		}
		cfg.CloudflareProxyDefault = b
	}

	cfg.TraefikAPIURL = strings.TrimRight(strings.TrimSpace(os.Getenv("TRAEFIK_API_URL")), "/")
	cfg.TraefikEntrypoints = splitCSV(os.Getenv("TRAEFIK_ENTRYPOINTS"))
	cfg.CustomURLs = splitCSV(os.Getenv("CUSTOM_URLS"))

	if v := strings.TrimSpace(os.Getenv("IP_VERSION")); v != "" {
		cfg.IPVersion = v
	}
	cfg.IPVersion = strings.ToLower(cfg.IPVersion)

	if v := strings.TrimSpace(os.Getenv("DELAY")); v != "" {
		sec, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid DELAY: %w", err)
		}
		cfg.Delay = time.Duration(sec) * time.Second
	}

	if v := strings.TrimSpace(os.Getenv("LOG_LEVEL")); v != "" {
		cfg.LogLevel = strings.ToLower(v)
	}

	if err := validate(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func validate(cfg Config) error {
	if cfg.TraefikAPIURL == "" {
		return errors.New("TRAEFIK_API_URL is required")
	}
	if len(cfg.TraefikEntrypoints) == 0 {
		return errors.New("TRAEFIK_ENTRYPOINTS is required")
	}
	if cfg.CloudflareAPIToken == "" && (cfg.CloudflareAPIKey == "" || cfg.CloudflareEmail == "") {
		return errors.New("CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_KEY + CLOUDFLARE_EMAIL is required")
	}
	if cfg.IPVersion != "4" && cfg.IPVersion != "6" && cfg.IPVersion != "both" {
		return errors.New("IP_VERSION must be one of: 4, 6, both")
	}
	return nil
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func parseBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "t", "yes", "y":
		return true, nil
	case "false", "0", "f", "no", "n":
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean value")
	}
}
