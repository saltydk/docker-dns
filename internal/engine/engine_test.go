package engine

import "testing"

import "docker-dns/internal/traefik"

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
