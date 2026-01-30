package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadParsesOverrides(t *testing.T) {
	t.Setenv("TRAEFIK_API_URL", "http://traefik")
	t.Setenv("TRAEFIK_ENTRYPOINTS", "web")
	t.Setenv("CLOUDFLARE_API_TOKEN", "token")
	t.Setenv("DELAY", "30")
	t.Setenv("WANIP_TIMEOUT", "7")
	t.Setenv("WANIP_RETRIES", "4")
	t.Setenv("WANIP_RETRY_DELAY", "6")
	t.Setenv("CF_RETRY_ATTEMPTS", "5")
	t.Setenv("CF_RETRY_MIN_DELAY", "2")
	t.Setenv("CF_RETRY_MAX_DELAY", "9")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Delay != 30*time.Second {
		t.Fatalf("expected delay 30s, got %v", cfg.Delay)
	}
	if cfg.WANIPTimeout != 7*time.Second {
		t.Fatalf("expected WANIP timeout 7s, got %v", cfg.WANIPTimeout)
	}
	if cfg.WANIPRetries != 4 {
		t.Fatalf("expected WANIP retries 4, got %d", cfg.WANIPRetries)
	}
	if cfg.WANIPRetryDelay != 6*time.Second {
		t.Fatalf("expected WANIP retry delay 6s, got %v", cfg.WANIPRetryDelay)
	}
	if cfg.CFRetryAttempts != 5 {
		t.Fatalf("expected CF retry attempts 5, got %d", cfg.CFRetryAttempts)
	}
	if cfg.CFRetryMinDelay != 2*time.Second {
		t.Fatalf("expected CF retry min delay 2s, got %v", cfg.CFRetryMinDelay)
	}
	if cfg.CFRetryMaxDelay != 9*time.Second {
		t.Fatalf("expected CF retry max delay 9s, got %v", cfg.CFRetryMaxDelay)
	}
}

func TestLoadValidatesDelay(t *testing.T) {
	resetEnv()
	t.Setenv("TRAEFIK_API_URL", "http://traefik")
	t.Setenv("TRAEFIK_ENTRYPOINTS", "web")
	t.Setenv("CLOUDFLARE_API_TOKEN", "token")
	t.Setenv("DELAY", "0")

	_, err := Load()
	if err == nil {
		t.Fatalf("expected error for DELAY=0")
	}
}

func TestLoadValidatesWANIPTimeout(t *testing.T) {
	resetEnv()
	t.Setenv("TRAEFIK_API_URL", "http://traefik")
	t.Setenv("TRAEFIK_ENTRYPOINTS", "web")
	t.Setenv("CLOUDFLARE_API_TOKEN", "token")
	t.Setenv("WANIP_TIMEOUT", "0")

	_, err := Load()
	if err == nil {
		t.Fatalf("expected error for WANIP_TIMEOUT=0")
	}
}

func resetEnv() {
	for _, key := range []string{
		"TRAEFIK_API_URL",
		"TRAEFIK_ENTRYPOINTS",
		"CLOUDFLARE_API_TOKEN",
		"CLOUDFLARE_API_KEY",
		"CLOUDFLARE_EMAIL",
		"DELAY",
		"WANIP_TIMEOUT",
		"WANIP_RETRIES",
		"WANIP_RETRY_DELAY",
		"CF_RETRY_ATTEMPTS",
		"CF_RETRY_MIN_DELAY",
		"CF_RETRY_MAX_DELAY",
	} {
		_ = os.Unsetenv(key)
	}
}
