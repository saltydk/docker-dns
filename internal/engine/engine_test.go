package engine

import (
	"strings"
	"testing"

	"docker-dns/internal/cloudflare"
	"docker-dns/internal/traefik"
)

func TestCollectHosts(t *testing.T) {
	routers := map[string]traefik.Router{
		"r1": {
			Name:        "r1",
			EntryPoints: []string{"web"},
			Rule:        "Host(`Example.com.`)",
		},
		"r2": {
			Name:        "r2",
			EntryPoints: []string{"internal"},
			Rule:        "Host(`skip.example.com`)",
		},
	}
	custom := []string{"Custom.com.", "  "}

	hosts := collectHosts(routers, []string{"web"}, custom)
	if _, ok := hosts["example.com"]; !ok {
		t.Fatalf("expected normalized host example.com")
	}
	if _, ok := hosts["custom.com"]; !ok {
		t.Fatalf("expected custom host custom.com")
	}
	if _, ok := hosts["skip.example.com"]; ok {
		t.Fatalf("did not expect host from non-matching entrypoint")
	}
}

func TestValidateNestedProxyChanges(t *testing.T) {
	proxied := true
	dnsOnly := false
	tests := []struct {
		name         string
		host         string
		wanIPs       map[int]string
		existingA    map[string]cloudflare.DNSRecord
		existingAAAA map[string]cloudflare.DNSRecord
		proxyDefault bool
		allowNested  bool
		wantError    bool
	}{
		{
			name:         "single label proxied",
			host:         "test-a.example.com",
			wanIPs:       map[int]string{4: "192.0.2.1"},
			proxyDefault: true,
		},
		{
			name:         "nested create proxied",
			host:         "app.test-a.example.com",
			wanIPs:       map[int]string{4: "192.0.2.1"},
			proxyDefault: true,
			wantError:    true,
		},
		{
			name:         "nested create DNS only",
			host:         "app.test-a.example.com",
			wanIPs:       map[int]string{4: "192.0.2.1"},
			proxyDefault: false,
		},
		{
			name:         "nested paid override",
			host:         "app.test-a.example.com",
			wanIPs:       map[int]string{4: "192.0.2.1"},
			proxyDefault: true,
			allowNested:  true,
		},
		{
			name:   "nested unchanged proxied record",
			host:   "app.test-a.example.com",
			wanIPs: map[int]string{4: "192.0.2.1"},
			existingA: map[string]cloudflare.DNSRecord{
				"app.test-a.example.com": {Content: "192.0.2.1", Proxied: &proxied},
			},
			proxyDefault: true,
		},
		{
			name:   "nested changed existing DNS-only record",
			host:   "app.test-a.example.com",
			wanIPs: map[int]string{4: "192.0.2.2"},
			existingA: map[string]cloudflare.DNSRecord{
				"app.test-a.example.com": {Content: "192.0.2.1", Proxied: &dnsOnly},
			},
			proxyDefault: true,
		},
		{
			name:   "nested changed existing proxied record",
			host:   "app.test-a.example.com",
			wanIPs: map[int]string{4: "192.0.2.2"},
			existingA: map[string]cloudflare.DNSRecord{
				"app.test-a.example.com": {Content: "192.0.2.1", Proxied: &proxied},
			},
			wantError: true,
		},
		{
			name:         "nested IPv6 create proxied",
			host:         "app.test-a.example.com",
			wanIPs:       map[int]string{6: "2001:db8::1"},
			proxyDefault: true,
			wantError:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateNestedProxyChanges(
				test.host,
				"example.com",
				test.wanIPs,
				test.existingA,
				test.existingAAAA,
				test.proxyDefault,
				test.allowNested,
			)
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "refusing to proxy nested") {
					t.Fatalf("error = %v, want nested proxy rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
