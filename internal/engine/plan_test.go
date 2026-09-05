package engine

import (
	"errors"
	"slices"
	"testing"

	"docker-dns/internal/cloudflare"
	"docker-dns/internal/config"
	"docker-dns/internal/traefik"
)

func TestBuildReconciliationPlanSortsAndBlocksHostsBeforeExecution(t *testing.T) {
	client := &fakeDNSClient{
		zones: []cloudflare.Zone{{ID: "zone", Name: "example.com"}},
		records: map[string][]cloudflare.DNSRecord{
			"zone": {},
		},
	}
	engine := &Engine{
		cfg: config.Config{
			IPVersion:              "4",
			TraefikEntrypoints:     []string{"web"},
			CloudflareProxyDefault: true,
		},
		logger: discardLogger(),
		cf:     client,
	}
	routers := map[string]traefik.Router{
		"valid":   {Name: "valid", EntryPoints: []string{"web"}, Rule: "Host(`z.example.com`)"},
		"blocked": {Name: "blocked", EntryPoints: []string{"web"}, Rule: "Host(`app.deep.example.com`)"},
	}

	plan, err := engine.buildReconciliationPlan(t.Context(), routers, map[int]string{4: "192.0.2.1"})
	if err != nil {
		t.Fatalf("buildReconciliationPlan() error = %v", err)
	}
	if plan.hostCount != 2 || plan.zoneCount != 1 || len(plan.hosts) != 2 {
		t.Fatalf("plan counts = hosts:%d zones:%d plans:%d, want 2, 1, 2", plan.hostCount, plan.zoneCount, len(plan.hosts))
	}
	if plan.hosts[0].host != "app.deep.example.com" || plan.hosts[0].blocked == nil {
		t.Fatalf("first host plan = %#v, want sorted blocked nested host", plan.hosts[0])
	}
	if plan.hosts[1].host != "z.example.com" || len(plan.hosts[1].changes) != 1 || plan.hosts[1].changes[0].kind != changeCreate {
		t.Fatalf("second host plan = %#v, want sorted valid create", plan.hosts[1])
	}
	if len(client.calls) != 0 {
		t.Fatalf("planning issued mutations: %#v", client.calls)
	}
}

func TestBuildReconciliationPlanIsolatesZoneSnapshotFailure(t *testing.T) {
	client := &fakeDNSClient{
		zones: []cloudflare.Zone{
			{ID: "bad-zone", Name: "example.com"},
			{ID: "good-zone", Name: "example.net"},
		},
		records: map[string][]cloudflare.DNSRecord{
			"good-zone": {},
		},
		recordErrors: map[string]error{
			"bad-zone": errors.New("records unavailable"),
		},
	}
	engine := &Engine{
		cfg:    config.Config{IPVersion: "4", TraefikEntrypoints: []string{"web"}},
		logger: discardLogger(),
		cf:     client,
	}
	routers := map[string]traefik.Router{
		"bad":  {Name: "bad", EntryPoints: []string{"web"}, Rule: "Host(`bad.example.com`)"},
		"good": {Name: "good", EntryPoints: []string{"web"}, Rule: "Host(`good.example.net`)"},
	}

	plan, err := engine.buildReconciliationPlan(t.Context(), routers, map[int]string{4: "192.0.2.1"})
	if err != nil {
		t.Fatalf("buildReconciliationPlan() error = %v", err)
	}
	if len(plan.hosts) != 2 || plan.hosts[0].host != "bad.example.com" || plan.hosts[0].blocked == nil {
		t.Fatalf("first host plan = %#v, want blocked bad zone", plan.hosts)
	}
	if plan.hosts[1].host != "good.example.net" || len(plan.hosts[1].changes) != 1 {
		t.Fatalf("second host plan = %#v, want valid good zone", plan.hosts[1])
	}
}

func TestBuildReconciliationPlanInitialZoneFailureIssuesNoWrites(t *testing.T) {
	sentinel := errors.New("zones unavailable")
	client := &fakeDNSClient{zonesErr: sentinel}
	engine := &Engine{
		cfg:    config.Config{IPVersion: "4", TraefikEntrypoints: []string{"web"}},
		logger: discardLogger(),
		cf:     client,
	}
	routers := map[string]traefik.Router{
		"app": {Name: "app", EntryPoints: []string{"web"}, Rule: "Host(`app.example.com`)"},
	}

	_, err := engine.buildReconciliationPlan(t.Context(), routers, map[int]string{4: "192.0.2.1"})
	if !errors.Is(err, sentinel) {
		t.Fatalf("buildReconciliationPlan() error = %v, want sentinel", err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("failed snapshot issued mutations: %#v", client.calls)
	}
}

func TestUpdateCloudflareRecordsSkipsBlockedHost(t *testing.T) {
	client := &fakeDNSClient{
		zones:   []cloudflare.Zone{{ID: "zone", Name: "example.com"}},
		records: map[string][]cloudflare.DNSRecord{"zone": {}},
	}
	engine := &Engine{
		cfg: config.Config{
			IPVersion:              "4",
			TraefikEntrypoints:     []string{"web"},
			CloudflareProxyDefault: true,
		},
		logger: discardLogger(),
		cf:     client,
	}
	routers := map[string]traefik.Router{
		"blocked": {Name: "blocked", EntryPoints: []string{"web"}, Rule: "Host(`app.deep.example.com`)"},
		"valid":   {Name: "valid", EntryPoints: []string{"web"}, Rule: "Host(`valid.example.com`)"},
	}
	failedHosts := make(map[string]struct{})

	err := engine.updateCloudflareRecords(t.Context(), routers, map[int]string{4: "192.0.2.1"}, true, 2, failedHosts)
	if err != nil {
		t.Fatalf("updateCloudflareRecords() error = %v", err)
	}
	wantCalls := []string{"create zone A valid.example.com 192.0.2.1"}
	if !slices.Equal(client.calls, wantCalls) {
		t.Fatalf("calls = %#v, want valid host only", client.calls)
	}
	if _, ok := failedHosts["app.deep.example.com"]; !ok {
		t.Fatalf("failedHosts = %#v, want blocked nested host", failedHosts)
	}
}

func TestPlanHostOrdersCNAMEUpdateAndCreate(t *testing.T) {
	proxied := true
	cache := &zoneCache{
		zoneID: "zone",
		existingA: map[string]cloudflare.DNSRecord{
			"app.example.com": {ID: "a", Type: "A", Name: "app.example.com", Content: "192.0.2.1", Proxied: &proxied},
		},
		existingAAAA: map[string]cloudflare.DNSRecord{},
		existingCNAME: map[string]cloudflare.DNSRecord{
			"app.example.com": {ID: "cname", Type: "CNAME", Name: "app.example.com"},
		},
		duplicateA:     map[string]struct{}{},
		duplicateAAAA:  map[string]struct{}{},
		duplicateCNAME: map[string]struct{}{},
	}

	plan := planHost(config.Config{IPVersion: "both"}, "app.example.com", "example.com", map[int]string{
		4: "192.0.2.2",
		6: "2001:db8::2",
	}, cache)

	if plan.blocked != nil {
		t.Fatalf("plan.blocked = %v", plan.blocked)
	}
	if plan.prerequisite == nil || plan.prerequisite.kind != changeDelete || plan.prerequisite.recordType != "CNAME" || plan.prerequisite.recordID != "cname" {
		t.Fatalf("plan.prerequisite = %#v, want CNAME delete", plan.prerequisite)
	}
	if len(plan.changes) != 2 {
		t.Fatalf("len(plan.changes) = %d, want 2", len(plan.changes))
	}
	update := plan.changes[0]
	if update.kind != changeUpdate || update.recordType != "A" || update.recordID != "a" || update.params.Content != "192.0.2.2" || update.params.Proxied == nil || !*update.params.Proxied {
		t.Fatalf("first change = %#v, want proxied A update", update)
	}
	create := plan.changes[1]
	if create.kind != changeCreate || create.recordType != "AAAA" || create.params.Content != "2001:db8::2" || create.params.Proxied == nil || *create.params.Proxied {
		t.Fatalf("second change = %#v, want DNS-only AAAA create", create)
	}
}

func TestPlanHostDeletesDisabledFamily(t *testing.T) {
	cache := emptyZoneCache("zone")
	cache.existingAAAA["app.example.com"] = cloudflare.DNSRecord{ID: "aaaa", Type: "AAAA", Name: "app.example.com", Content: "2001:db8::1"}

	plan := planHost(config.Config{IPVersion: "4"}, "app.example.com", "example.com", map[int]string{4: "192.0.2.1"}, cache)
	if len(plan.changes) != 2 {
		t.Fatalf("len(plan.changes) = %d, want A create and AAAA delete", len(plan.changes))
	}
	if plan.changes[0].kind != changeCreate || plan.changes[0].recordType != "A" {
		t.Fatalf("first change = %#v, want A create", plan.changes[0])
	}
	if plan.changes[1].kind != changeDelete || plan.changes[1].recordType != "AAAA" || plan.changes[1].recordID != "aaaa" {
		t.Fatalf("second change = %#v, want AAAA delete", plan.changes[1])
	}
}

func TestPlanHostBlocksUnsafeNestedProxy(t *testing.T) {
	plan := planHost(config.Config{
		IPVersion:              "4",
		CloudflareProxyDefault: true,
	}, "app.deep.example.com", "example.com", map[int]string{4: "192.0.2.1"}, emptyZoneCache("zone"))

	if plan.blocked == nil {
		t.Fatal("plan.blocked = nil, want nested proxy error")
	}
	if len(plan.changes) != 0 || plan.prerequisite != nil {
		t.Fatalf("blocked plan contains changes: %#v", plan)
	}
}

func TestPlanHostBlocksBeforeDeletingCNAMEWhenWANIPMissing(t *testing.T) {
	cache := emptyZoneCache("zone")
	cache.existingCNAME["app.example.com"] = cloudflare.DNSRecord{ID: "cname", Type: "CNAME", Name: "app.example.com"}

	plan := planHost(config.Config{IPVersion: "both"}, "app.example.com", "example.com", map[int]string{4: "192.0.2.1"}, cache)
	if plan.blocked == nil {
		t.Fatal("plan.blocked = nil, want missing IPv6 error")
	}
	if plan.prerequisite != nil || len(plan.changes) != 0 {
		t.Fatalf("blocked plan contains changes: %#v", plan)
	}
}

func TestPlanHostSkipsOnlyDuplicateRecordFamily(t *testing.T) {
	cache := emptyZoneCache("zone")
	cache.duplicateA["app.example.com"] = struct{}{}

	plan := planHost(config.Config{IPVersion: "both"}, "app.example.com", "example.com", map[int]string{
		4: "192.0.2.1",
		6: "2001:db8::1",
	}, cache)
	if len(plan.issues) != 1 {
		t.Fatalf("len(plan.issues) = %d, want duplicate A issue", len(plan.issues))
	}
	if len(plan.changes) != 1 || plan.changes[0].recordType != "AAAA" {
		t.Fatalf("plan.changes = %#v, want only AAAA change", plan.changes)
	}
}

func emptyZoneCache(zoneID string) *zoneCache {
	return &zoneCache{
		zoneID:         zoneID,
		existingA:      map[string]cloudflare.DNSRecord{},
		existingAAAA:   map[string]cloudflare.DNSRecord{},
		existingCNAME:  map[string]cloudflare.DNSRecord{},
		duplicateA:     map[string]struct{}{},
		duplicateAAAA:  map[string]struct{}{},
		duplicateCNAME: map[string]struct{}{},
	}
}
