package engine

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"golang.org/x/net/publicsuffix"

	"docker-dns/internal/cloudflare"
	"docker-dns/internal/config"
	"docker-dns/internal/traefik"
)

type changeKind uint8

const (
	changeUnknown changeKind = iota
	changeCreate
	changeUpdate
	changeDelete
)

type dnsChange struct {
	kind       changeKind
	zoneID     string
	recordID   string
	recordType string
	params     cloudflare.RecordParams
}

type hostPlan struct {
	host         string
	prerequisite *dnsChange
	changes      []dnsChange
	issues       []error
	blocked      error
}

func (e *Engine) buildReconciliationPlan(
	ctx context.Context,
	routers map[string]traefik.Router,
	wanIPs map[int]string,
) (reconciliationPlan, error) {
	zonesByName, err := e.ensureZones(ctx)
	if err != nil {
		return reconciliationPlan{}, err
	}

	processedHosts := collectHosts(routers, e.cfg.TraefikEntrypoints, e.cfg.CustomURLs)
	processedZones := make(map[string]*zoneCache)
	plan := reconciliationPlan{hostCount: len(processedHosts)}
	for _, host := range slices.Sorted(maps.Keys(processedHosts)) {
		if err := ctx.Err(); err != nil {
			return reconciliationPlan{}, err
		}
		rootDomain, err := publicsuffix.EffectiveTLDPlusOne(host)
		if err != nil {
			e.logger.Warn("Unable to determine root domain", "host", host, "error", err)
			continue
		}

		cache, refreshedZones, ok := e.getZoneCache(ctx, rootDomain, zonesByName, processedZones)
		zonesByName = refreshedZones
		if !ok {
			if err := ctx.Err(); err != nil {
				return reconciliationPlan{}, err
			}
			plan.hosts = append(plan.hosts, hostPlan{
				host:    host,
				blocked: fmt.Errorf("cloudflare zone %q is unavailable", rootDomain),
			})
			continue
		}
		plan.hosts = append(plan.hosts, planHost(e.cfg, host, rootDomain, wanIPs, cache))
	}
	plan.zoneCount = len(processedZones)
	return plan, nil
}

func planHost(cfg config.Config, host, rootDomain string, wanIPs map[int]string, cache *zoneCache) hostPlan {
	plan := hostPlan{host: host}
	if _, duplicate := cache.duplicateCNAME[host]; duplicate {
		plan.blocked = fmt.Errorf("multiple CNAME records found for host %q", host)
		return plan
	}
	requiredVersions := make([]int, 0, 2)
	if cfg.IPVersion == "4" || cfg.IPVersion == "both" {
		requiredVersions = append(requiredVersions, 4)
	}
	if cfg.IPVersion == "6" || cfg.IPVersion == "both" {
		requiredVersions = append(requiredVersions, 6)
	}
	for _, version := range requiredVersions {
		if _, ok := wanIPs[version]; !ok {
			plan.blocked = fmt.Errorf("missing WAN IPv%d address for host %q", version, host)
			return plan
		}
	}
	if err := validateNestedProxyChanges(
		host,
		rootDomain,
		wanIPs,
		cache.existingA,
		cache.existingAAAA,
		cfg.CloudflareProxyDefault,
		cfg.CloudflareAllowNestedProxy,
	); err != nil {
		plan.blocked = err
		return plan
	}

	if record, ok := cache.existingCNAME[host]; ok {
		plan.prerequisite = &dnsChange{
			kind:       changeDelete,
			zoneID:     cache.zoneID,
			recordID:   record.ID,
			recordType: "CNAME",
			params: cloudflare.RecordParams{
				Type: "CNAME",
				Name: host,
			},
		}
	}

	type recordFamily struct {
		version    int
		recordType string
		enabled    bool
		existing   map[string]cloudflare.DNSRecord
		duplicates map[string]struct{}
	}
	families := []recordFamily{
		{
			version:    4,
			recordType: "A",
			enabled:    cfg.IPVersion == "4" || cfg.IPVersion == "both",
			existing:   cache.existingA,
			duplicates: cache.duplicateA,
		},
		{
			version:    6,
			recordType: "AAAA",
			enabled:    cfg.IPVersion == "6" || cfg.IPVersion == "both",
			existing:   cache.existingAAAA,
			duplicates: cache.duplicateAAAA,
		},
	}

	for _, family := range families {
		if _, duplicate := family.duplicates[host]; duplicate {
			plan.issues = append(plan.issues, fmt.Errorf("multiple %s records found for host %q", family.recordType, host))
			continue
		}

		record, exists := family.existing[host]
		if !family.enabled {
			if exists {
				plan.changes = append(plan.changes, dnsChange{
					kind:       changeDelete,
					zoneID:     cache.zoneID,
					recordID:   record.ID,
					recordType: family.recordType,
					params: cloudflare.RecordParams{
						Type: family.recordType,
						Name: host,
					},
				})
			}
			continue
		}

		ip, ok := wanIPs[family.version]
		if !ok {
			plan.issues = append(plan.issues, fmt.Errorf("missing WAN IPv%d address for host %q", family.version, host))
			continue
		}
		if exists && record.Content == ip {
			continue
		}

		proxied := proxiedForCreate(family.recordType, cfg.CloudflareProxyDefault)
		kind := changeCreate
		recordID := ""
		if exists {
			kind = changeUpdate
			recordID = record.ID
			proxied = proxiedForUpdate(record, family.recordType, cfg.CloudflareProxyDefault)
		}
		plan.changes = append(plan.changes, dnsChange{
			kind:       kind,
			zoneID:     cache.zoneID,
			recordID:   recordID,
			recordType: family.recordType,
			params: cloudflare.RecordParams{
				Type:    family.recordType,
				Name:    host,
				Content: ip,
				Proxied: &proxied,
			},
		})
	}

	return plan
}
