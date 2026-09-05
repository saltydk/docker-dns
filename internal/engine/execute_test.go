package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"testing"

	"docker-dns/internal/cloudflare"
)

func TestExecutePlanSkipsBlockedHostAndExecutesValidHost(t *testing.T) {
	client := &fakeDNSClient{}
	engine := &Engine{logger: discardLogger(), cf: client}
	plan := reconciliationPlan{hosts: []hostPlan{
		{host: "blocked.example.com", blocked: errors.New("unsafe nested proxy")},
		{
			host: "valid.example.com",
			prerequisite: &dnsChange{
				kind: changeDelete, zoneID: "zone", recordID: "cname", recordType: "CNAME",
			},
			changes: []dnsChange{
				{kind: changeCreate, zoneID: "zone", recordType: "A", params: cloudflare.RecordParams{Type: "A", Name: "valid.example.com", Content: "192.0.2.1"}},
				{kind: changeUpdate, zoneID: "zone", recordID: "aaaa", recordType: "AAAA", params: cloudflare.RecordParams{Type: "AAAA", Name: "valid.example.com", Content: "2001:db8::1"}},
			},
		},
	}}

	result, err := engine.executePlan(t.Context(), plan)
	if err != nil {
		t.Fatalf("executePlan() error = %v", err)
	}
	wantCalls := []string{
		"delete zone cname",
		"create zone A valid.example.com 192.0.2.1",
		"update zone aaaa AAAA valid.example.com 2001:db8::1",
	}
	if !slices.Equal(client.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", client.calls, wantCalls)
	}
	if result.created != 1 || result.updated != 1 || result.deleted != 1 {
		t.Fatalf("result counts = created:%d updated:%d deleted:%d, want 1 each", result.created, result.updated, result.deleted)
	}
	if _, ok := result.failedHosts["blocked.example.com"]; !ok {
		t.Fatalf("failedHosts = %#v, want blocked host", result.failedHosts)
	}
}

func TestExecutePlanStopsHostAfterPrerequisiteFailure(t *testing.T) {
	client := &fakeDNSClient{failures: map[string]error{
		"delete zone cname": errors.New("delete failed"),
	}}
	engine := &Engine{logger: discardLogger(), cf: client}
	plan := reconciliationPlan{hosts: []hostPlan{
		{
			host:         "first.example.com",
			prerequisite: &dnsChange{kind: changeDelete, zoneID: "zone", recordID: "cname", recordType: "CNAME"},
			changes: []dnsChange{
				{kind: changeCreate, zoneID: "zone", recordType: "A", params: cloudflare.RecordParams{Type: "A", Name: "first.example.com", Content: "192.0.2.1"}},
			},
		},
		{
			host: "second.example.com",
			changes: []dnsChange{
				{kind: changeCreate, zoneID: "zone", recordType: "A", params: cloudflare.RecordParams{Type: "A", Name: "second.example.com", Content: "192.0.2.2"}},
			},
		},
	}}

	result, err := engine.executePlan(t.Context(), plan)
	if err != nil {
		t.Fatalf("executePlan() error = %v", err)
	}
	wantCalls := []string{
		"delete zone cname",
		"create zone A second.example.com 192.0.2.2",
	}
	if !slices.Equal(client.calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", client.calls, wantCalls)
	}
	if result.created != 1 || result.updated != 0 || result.deleted != 0 {
		t.Fatalf("result counts = created:%d updated:%d deleted:%d, want only second host created", result.created, result.updated, result.deleted)
	}
	if _, ok := result.failedHosts["first.example.com"]; !ok {
		t.Fatalf("failedHosts = %#v, want first host", result.failedHosts)
	}
}

func TestExecutePlanContinuesAfterRecordFamilyFailure(t *testing.T) {
	client := &fakeDNSClient{failures: map[string]error{
		"create zone A app.example.com 192.0.2.1": errors.New("A failed"),
	}}
	engine := &Engine{logger: discardLogger(), cf: client}
	plan := reconciliationPlan{hosts: []hostPlan{
		{
			host: "app.example.com",
			changes: []dnsChange{
				{kind: changeCreate, zoneID: "zone", recordType: "A", params: cloudflare.RecordParams{Type: "A", Name: "app.example.com", Content: "192.0.2.1"}},
				{kind: changeCreate, zoneID: "zone", recordType: "AAAA", params: cloudflare.RecordParams{Type: "AAAA", Name: "app.example.com", Content: "2001:db8::1"}},
			},
		},
	}}

	result, err := engine.executePlan(t.Context(), plan)
	if err != nil {
		t.Fatalf("executePlan() error = %v", err)
	}
	if len(client.calls) != 2 || result.created != 1 {
		t.Fatalf("calls = %#v, created = %d; want both families attempted and one created", client.calls, result.created)
	}
	if _, ok := result.failedHosts["app.example.com"]; !ok {
		t.Fatalf("failedHosts = %#v, want app.example.com", result.failedHosts)
	}
}

func TestExecutePlanRejectsUnknownChange(t *testing.T) {
	client := &fakeDNSClient{}
	engine := &Engine{logger: discardLogger(), cf: client}
	plan := reconciliationPlan{hosts: []hostPlan{{
		host:    "app.example.com",
		changes: []dnsChange{{}},
	}}}

	result, err := engine.executePlan(t.Context(), plan)
	if err != nil {
		t.Fatalf("executePlan() error = %v", err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("unknown change issued mutations: %#v", client.calls)
	}
	if _, ok := result.failedHosts["app.example.com"]; !ok {
		t.Fatalf("failedHosts = %#v, want app.example.com", result.failedHosts)
	}
}

func TestExecutePlanStopsBeforeMutationWhenContextCanceled(t *testing.T) {
	client := &fakeDNSClient{}
	engine := &Engine{logger: discardLogger(), cf: client}
	plan := reconciliationPlan{hosts: []hostPlan{{
		host: "app.example.com",
		changes: []dnsChange{{
			kind: changeCreate, zoneID: "zone", recordType: "A", params: cloudflare.RecordParams{Type: "A", Name: "app.example.com", Content: "192.0.2.1"},
		}},
	}}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := engine.executePlan(ctx, plan)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("executePlan() error = %v, want context cancellation", err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("canceled execution issued mutations: %#v", client.calls)
	}
}

type fakeDNSClient struct {
	calls        []string
	failures     map[string]error
	zones        []cloudflare.Zone
	zonesErr     error
	records      map[string][]cloudflare.DNSRecord
	recordErrors map[string]error
}

func (f *fakeDNSClient) VerifyAuth(context.Context) error { return nil }

func (f *fakeDNSClient) ListZones(context.Context) ([]cloudflare.Zone, error) {
	return f.zones, f.zonesErr
}

func (f *fakeDNSClient) ListDNSRecords(_ context.Context, zoneID string) ([]cloudflare.DNSRecord, error) {
	return f.records[zoneID], f.recordErrors[zoneID]
}

func (f *fakeDNSClient) CreateDNSRecord(_ context.Context, zoneID string, params cloudflare.RecordParams) (cloudflare.DNSRecord, error) {
	key := fmt.Sprintf("create %s %s %s %s", zoneID, params.Type, params.Name, params.Content)
	f.calls = append(f.calls, key)
	return cloudflare.DNSRecord{}, f.failures[key]
}

func (f *fakeDNSClient) UpdateDNSRecord(_ context.Context, zoneID, recordID string, params cloudflare.RecordParams) (cloudflare.DNSRecord, error) {
	key := fmt.Sprintf("update %s %s %s %s %s", zoneID, recordID, params.Type, params.Name, params.Content)
	f.calls = append(f.calls, key)
	return cloudflare.DNSRecord{}, f.failures[key]
}

func (f *fakeDNSClient) DeleteDNSRecord(_ context.Context, zoneID, recordID string) error {
	key := fmt.Sprintf("delete %s %s", zoneID, recordID)
	f.calls = append(f.calls, key)
	return f.failures[key]
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
