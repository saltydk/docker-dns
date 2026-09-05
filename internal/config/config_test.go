package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadUsesProvidedEnvironmentInsteadOfProcess(t *testing.T) {
	t.Setenv("IP_VERSION", "bogus")

	cfg, err := load(mapEnvironment(map[string]string{
		"TRAEFIK_API_URL":      "http://traefik",
		"TRAEFIK_ENTRYPOINTS":  "web",
		"CLOUDFLARE_API_TOKEN": "token",
		"IP_VERSION":           "4",
		"CF_RETRY_MIN_DELAY":   "2",
		"CF_RETRY_MAX_DELAY":   "9",
	}))
	if err != nil {
		t.Fatalf("load() error = %v", err)
	}
	if cfg.IPVersion != "4" {
		t.Fatalf("IPVersion = %q, want 4", cfg.IPVersion)
	}
}

func TestLoadRejectsReversedCloudflareRetryDelays(t *testing.T) {
	_, err := load(mapEnvironment(map[string]string{
		"TRAEFIK_API_URL":      "http://traefik",
		"TRAEFIK_ENTRYPOINTS":  "web",
		"CLOUDFLARE_API_TOKEN": "token",
		"CF_RETRY_MIN_DELAY":   "10",
		"CF_RETRY_MAX_DELAY":   "1",
	}))
	if err == nil || !strings.Contains(err.Error(), "CF_RETRY_MIN_DELAY must not exceed CF_RETRY_MAX_DELAY") {
		t.Fatalf("load() error = %v, want retry delay range error", err)
	}
}

func mapEnvironment(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func TestLoadParsesOverrides(t *testing.T) {
	values := validEnvironment()
	values["CLOUDFLARE_ALLOW_NESTED_PROXY"] = "true"
	values["DELAY"] = "30"
	values["WANIP_TIMEOUT"] = "7"
	values["WANIP_RETRIES"] = "4"
	values["WANIP_RETRY_DELAY"] = "6"
	values["CF_RETRY_ATTEMPTS"] = "5"
	values["CF_RETRY_MIN_DELAY"] = "2"
	values["CF_RETRY_MAX_DELAY"] = "9"

	cfg, err := load(mapEnvironment(values))
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
	if !cfg.CloudflareAllowNestedProxy {
		t.Fatal("expected nested proxy override to be enabled")
	}
}

func TestLoadValidatesDelay(t *testing.T) {
	values := validEnvironment()
	values["DELAY"] = "0"

	_, err := load(mapEnvironment(values))
	if err == nil {
		t.Fatalf("expected error for DELAY=0")
	}
}

func TestLoadValidatesWANIPTimeout(t *testing.T) {
	values := validEnvironment()
	values["WANIP_TIMEOUT"] = "0"

	_, err := load(mapEnvironment(values))
	if err == nil {
		t.Fatalf("expected error for WANIP_TIMEOUT=0")
	}
}

func TestLoadValidatesNestedProxyOverride(t *testing.T) {
	values := validEnvironment()
	values["CLOUDFLARE_ALLOW_NESTED_PROXY"] = "sometimes"

	_, err := load(mapEnvironment(values))
	if err == nil {
		t.Fatal("expected error for invalid nested proxy override")
	}
}

func validEnvironment() map[string]string {
	return map[string]string{
		"TRAEFIK_API_URL":      "http://traefik",
		"TRAEFIK_ENTRYPOINTS":  "web",
		"CLOUDFLARE_API_TOKEN": "token",
	}
}
