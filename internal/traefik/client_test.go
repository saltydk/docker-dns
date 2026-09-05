package traefik

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoutersPaginates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "1":
			w.Header().Set("X-Next-Page", "2")
			_, _ = fmt.Fprint(w, "[{\"name\":\"first\",\"entryPoints\":[\"web\"],\"rule\":\"Host(`first.example.com`)\"}]")
		case "2":
			_, _ = fmt.Fprint(w, "[{\"name\":\"second\",\"entryPoints\":[\"web\"],\"rule\":\"Host(`second.example.com`)\"}]")
		default:
			t.Errorf("unexpected page %q", r.URL.Query().Get("page"))
			http.Error(w, "unexpected page", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)

	client := Client{BaseURL: server.URL, Client: server.Client()}
	routers, err := client.Routers(t.Context())
	if err != nil {
		t.Fatalf("Routers() error = %v", err)
	}
	if len(routers) != 2 || routers[0].Name != "first" || routers[1].Name != "second" {
		t.Fatalf("Routers() = %#v, want first and second pages", routers)
	}
}

func TestRoutersRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", (4<<20)+1)))
	}))
	t.Cleanup(server.Close)

	client := Client{BaseURL: server.URL, Client: server.Client()}
	_, err := client.Routers(t.Context())
	if err == nil || !strings.Contains(err.Error(), "exceeds 4194304 bytes") {
		t.Fatalf("Routers() error = %v, want response size error", err)
	}
}

func TestRoutersOversizedErrorIncludesHTTPStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat("x", (4<<20)+1)))
	}))
	t.Cleanup(server.Close)

	client := Client{BaseURL: server.URL, Client: server.Client()}
	_, err := client.Routers(t.Context())
	if err == nil || !strings.Contains(err.Error(), "status 502") || !strings.Contains(err.Error(), "exceeds 4194304 bytes") {
		t.Fatalf("Routers() error = %v, want status and response size", err)
	}
}

func TestRoutersErrorIncludesEndpointAndPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	client := Client{BaseURL: server.URL, Client: server.Client()}
	_, err := client.Routers(t.Context())
	if err == nil || !strings.Contains(err.Error(), server.URL) || !strings.Contains(err.Error(), "page 1") || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("Routers() error = %v, want endpoint, page, and status", err)
	}
}

func TestExtractHosts(t *testing.T) {
	tests := []struct {
		name     string
		rule     string
		expected []string
	}{
		{
			name:     "single host",
			rule:     "Host(`example.com`)",
			expected: []string{"example.com"},
		},
		{
			name:     "multiple hosts single clause",
			rule:     "Host(`a.example.com`, `b.example.com`)",
			expected: []string{"a.example.com", "b.example.com"},
		},
		{
			name:     "multiple clauses",
			rule:     "Host(`a.com`) || Host(`b.com`)",
			expected: []string{"a.com", "b.com"},
		},
		{
			name:     "mixed rule",
			rule:     "Host(`app.example.com`) && PathPrefix(`/`)",
			expected: []string{"app.example.com"},
		},
		{
			name:     "no host rule",
			rule:     "PathPrefix(`/`)",
			expected: nil,
		},
		{
			name:     "non-backtick host",
			rule:     `Host("example.com")`,
			expected: nil,
		},
		{
			name:     "spacing variance",
			rule:     "Host( `a.com` ,`b.com` )",
			expected: []string{"a.com", "b.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractHosts(tc.rule)
			if len(got) != len(tc.expected) {
				t.Fatalf("expected %v, got %v", tc.expected, got)
			}
			for i := range got {
				if got[i] != tc.expected[i] {
					t.Fatalf("expected %v, got %v", tc.expected, got)
				}
			}
		})
	}
}
