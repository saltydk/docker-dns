package wanip

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchIPRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("1", 1025)))
	}))
	t.Cleanup(server.Close)

	provider := Provider{Client: server.Client(), HTTPTimeout: time.Second}
	_, err := provider.fetchIP(t.Context(), server.URL, 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds 1024 bytes") {
		t.Fatalf("fetchIP() error = %v, want response size error", err)
	}
}

func TestFetchIPErrorIncludesEndpointAndStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	provider := Provider{Client: server.Client(), HTTPTimeout: time.Second}
	_, err := provider.fetchIP(t.Context(), server.URL, 4)
	if err == nil || !strings.Contains(err.Error(), server.URL) || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("fetchIP() error = %v, want endpoint and status", err)
	}
}

func TestGetIPReturnsFinalProviderErrors(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	t.Cleanup(first.Close)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(second.Close)

	provider := Provider{
		Client:      &http.Client{Timeout: time.Second},
		MaxRetries:  1,
		HTTPTimeout: time.Second,
		services: func(int) []string {
			return []string{first.URL, second.URL}
		},
	}
	_, err := provider.getIP(t.Context(), 4)
	if err == nil || !strings.Contains(err.Error(), first.URL) || !strings.Contains(err.Error(), second.URL) {
		t.Fatalf("getIP() error = %v, want both provider errors", err)
	}
}

func TestIsValidWANIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		version int
		want    bool
	}{
		{name: "public v4", ip: "8.8.8.8", version: 4, want: true},
		{name: "private v4", ip: "192.168.1.1", version: 4, want: false},
		{name: "loopback v4", ip: "127.0.0.1", version: 4, want: false},
		{name: "link-local v4", ip: "169.254.1.1", version: 4, want: false},
		{name: "multicast v4", ip: "224.0.0.1", version: 4, want: false},
		{name: "public v6", ip: "2001:4860:4860::8888", version: 6, want: true},
		{name: "loopback v6", ip: "::1", version: 6, want: false},
		{name: "link-local v6", ip: "fe80::1", version: 6, want: false},
		{name: "multicast v6", ip: "ff02::1", version: 6, want: false},
		{name: "v6 checked as v4", ip: "2001:4860:4860::8888", version: 4, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isValidWANIP(net.ParseIP(tc.ip), tc.version)
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}
