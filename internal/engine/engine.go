package engine

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"docker-dns/internal/cloudflare"
	"docker-dns/internal/config"
	"docker-dns/internal/retry"
	"docker-dns/internal/traefik"
	"docker-dns/internal/wanip"
)

type Engine struct {
	cfg     config.Config
	logger  *slog.Logger
	cf      *cloudflare.Client
	traefik *traefik.Client
	wan     *wanip.Provider

	zonesByName map[string]string
}

func New(cfg config.Config, logger *slog.Logger, cf *cloudflare.Client, tf *traefik.Client, wan *wanip.Provider) *Engine {
	return &Engine{
		cfg:     cfg,
		logger:  logger,
		cf:      cf,
		traefik: tf,
		wan:     wan,
	}
}

func (e *Engine) Run(ctx context.Context) error {
	e.logger.Info("Saltbox Cloudflare DNS container starting.")

	if err := e.cf.VerifyAuth(ctx); err != nil {
		e.logger.Error("Cloudflare auth failed", "error", err)
		return err
	}

	select {
	case <-time.After(e.cfg.StartupDelay):
	case <-ctx.Done():
		return ctx.Err()
	}

	firstRun := true
	var wanIPs map[int]string

	var routers map[string]traefik.Router
	for {
		routersList, err := e.traefik.Routers(ctx)
		if err != nil {
			e.logger.Error("Error fetching Traefik routers", "error", err)
			if err := sleepWithContext(ctx, e.cfg.Delay); err != nil {
				return err
			}
			continue
		}
		routers = mapRouters(routersList)
		break
	}

	failedHosts := make(map[string]struct{})

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		newRoutersList, err := e.traefik.Routers(ctx)
		if err != nil {
			e.logger.Error("Error fetching Traefik routers", "error", err)
			if err := sleepWithContext(ctx, e.cfg.Delay); err != nil {
				return err
			}
			continue
		}
		newRouters := mapRouters(newRoutersList)

		newWANIPs, err := e.wan.GetIPs(ctx, e.cfg.IPVersion)
		if err != nil {
			e.logger.Error("Error fetching WAN IPs", "error", err)
			if err := sleepWithContext(ctx, e.cfg.Delay); err != nil {
				return err
			}
			continue
		}

		if !firstRun {
			e.logger.Debug("WAN IPs", "previous", wanIPs, "current", newWANIPs)
		}

		if !reflect.DeepEqual(newWANIPs, wanIPs) {
			e.logger.Info("WAN IPs changed", "ips", newWANIPs)
			wanIPs = newWANIPs
		}

		addedRouters := diffRouters(routers, newRouters)
		newCount := len(addedRouters)

		prevFailed := copySet(failedHosts)
		failedHosts = make(map[string]struct{})
		e.updateCloudflareRecords(ctx, newRouters, wanIPs, firstRun, newCount, failedHosts)
		if firstRun {
			firstRun = false
		}

		if len(prevFailed) > 0 {
			e.logger.Info("Retrying failed hosts", "count", len(prevFailed))
			for host := range prevFailed {
				if _, ok := failedHosts[host]; ok {
					e.logger.Info("Host failed again", "host", host)
				} else {
					e.logger.Info("Host succeeded on retry", "host", host)
				}
			}
		}

		routers = newRouters

		if err := sleepWithContext(ctx, e.cfg.Delay); err != nil {
			return err
		}
	}
}

type zoneCache struct {
	zoneID         string
	existingA      map[string]cloudflare.DNSRecord
	existingAAAA   map[string]cloudflare.DNSRecord
	existingCNAME  map[string]cloudflare.DNSRecord
	duplicateA     map[string]struct{}
	duplicateAAAA  map[string]struct{}
	duplicateCNAME map[string]struct{}
}

func (e *Engine) updateCloudflareRecords(
	ctx context.Context,
	routers map[string]traefik.Router,
	wanIPs map[int]string,
	firstRun bool,
	newCount int,
	failedHosts map[string]struct{},
) {
	if firstRun {
		e.logger.Info("Initial DNS validation/update starting", "routers", len(routers), "new", newCount)
	} else {
		e.logger.Info("DNS update pass starting", "routers", len(routers), "new", newCount)
	}

	zonesByName, err := e.ensureZones(ctx)
	if err != nil {
		e.logger.Error("Failed to list Cloudflare zones", "error", err)
		return
	}

	processedZones := make(map[string]*zoneCache)
	entrypoints := e.cfg.TraefikEntrypoints
	customURLs := e.cfg.CustomURLs
	updatedCount := 0
	createdCount := 0
	deletedCount := 0

	processHost := func(host string) {
		if host == "" {
			return
		}

		rootDomain, err := publicsuffix.EffectiveTLDPlusOne(host)
		if err != nil {
			e.logger.Warn("Unable to determine root domain", "host", host, "error", err)
			return
		}

		var (
			cache *zoneCache
			ok    bool
		)
		cache, zonesByName, ok = e.getZoneCache(ctx, rootDomain, zonesByName, processedZones)
		if !ok {
			return
		}

		existingA := cache.existingA
		existingAAAA := cache.existingAAAA
		existingCNAME := cache.existingCNAME
		duplicateA := cache.duplicateA
		duplicateAAAA := cache.duplicateAAAA
		duplicateCNAME := cache.duplicateCNAME

		if _, ok := duplicateCNAME[host]; ok {
			e.logger.Error("Multiple CNAME records found for host", "host", host)
			failedHosts[host] = struct{}{}
			return
		}
		if record, ok := existingCNAME[host]; ok {
			e.logger.Info("Found CNAME record, deleting", "host", host)
			err := retry.Do(ctx, e.cfg.CFRetryAttempts, e.cfg.CFRetryMinDelay, e.cfg.CFRetryMaxDelay, func() error {
				return e.cf.DeleteDNSRecord(ctx, cache.zoneID, record.ID)
			})
			if err != nil {
				e.logger.Error("Error deleting CNAME record", "host", host, "error", err)
				failedHosts[host] = struct{}{}
				return
			}
			deletedCount++
		}

		for version, ip := range wanIPs {
			var recordType string
			var existing map[string]cloudflare.DNSRecord
			switch version {
			case 4:
				recordType = "A"
				existing = existingA
				if _, ok := duplicateA[host]; ok {
					e.logger.Error("Multiple A records found for host", "host", host)
					failedHosts[host] = struct{}{}
					continue
				}
			case 6:
				recordType = "AAAA"
				existing = existingAAAA
				if _, ok := duplicateAAAA[host]; ok {
					e.logger.Error("Multiple AAAA records found for host", "host", host)
					failedHosts[host] = struct{}{}
					continue
				}
			default:
				e.logger.Error("Invalid IP version", "version", version)
				continue
			}

			if record, ok := existing[host]; ok {
				if record.Content == ip {
					if firstRun {
						e.logger.Debug("Record already updated", "type", recordType, "host", host)
					}
					continue
				}

				proxied := proxiedForUpdate(record, recordType, e.cfg.CloudflareProxyDefault)
				e.logger.Info("Updating record", "type", recordType, "host", host, "proxied", proxied)
				err := retry.Do(ctx, e.cfg.CFRetryAttempts, e.cfg.CFRetryMinDelay, e.cfg.CFRetryMaxDelay, func() error {
					_, err := e.cf.UpdateDNSRecord(ctx, cache.zoneID, record.ID, cloudflare.RecordParams{
						Type:    recordType,
						Name:    host,
						Content: ip,
						Proxied: &proxied,
					})
					return err
				})
				if err != nil {
					e.logger.Error("Error updating record", "type", recordType, "host", host, "error", err)
					failedHosts[host] = struct{}{}
				} else {
					updatedCount++
				}
			} else {
				proxied := proxiedForCreate(recordType, e.cfg.CloudflareProxyDefault)
				e.logger.Info("Adding record", "type", recordType, "host", host, "proxied", proxied)
				err := retry.Do(ctx, e.cfg.CFRetryAttempts, e.cfg.CFRetryMinDelay, e.cfg.CFRetryMaxDelay, func() error {
					_, err := e.cf.CreateDNSRecord(ctx, cache.zoneID, cloudflare.RecordParams{
						Type:    recordType,
						Name:    host,
						Content: ip,
						Proxied: &proxied,
					})
					return err
				})
				if err != nil {
					e.logger.Error("Error adding record", "type", recordType, "host", host, "error", err)
					failedHosts[host] = struct{}{}
				} else {
					createdCount++
				}
			}
		}

		if e.cfg.IPVersion != "4" && e.cfg.IPVersion != "both" {
			if _, ok := duplicateA[host]; ok {
				e.logger.Error("Multiple A records found for host", "host", host)
				failedHosts[host] = struct{}{}
				return
			}
			if record, ok := existingA[host]; ok {
				e.logger.Info("Removing A record (IPv4 disabled)", "host", host)
				err := retry.Do(ctx, e.cfg.CFRetryAttempts, e.cfg.CFRetryMinDelay, e.cfg.CFRetryMaxDelay, func() error {
					return e.cf.DeleteDNSRecord(ctx, cache.zoneID, record.ID)
				})
				if err != nil {
					e.logger.Error("Error deleting A record", "host", host, "error", err)
					failedHosts[host] = struct{}{}
				} else {
					deletedCount++
				}
			}
		}

		if e.cfg.IPVersion != "6" && e.cfg.IPVersion != "both" {
			if _, ok := duplicateAAAA[host]; ok {
				e.logger.Error("Multiple AAAA records found for host", "host", host)
				failedHosts[host] = struct{}{}
				return
			}
			if record, ok := existingAAAA[host]; ok {
				e.logger.Info("Removing AAAA record (IPv6 disabled)", "host", host)
				err := retry.Do(ctx, e.cfg.CFRetryAttempts, e.cfg.CFRetryMinDelay, e.cfg.CFRetryMaxDelay, func() error {
					return e.cf.DeleteDNSRecord(ctx, cache.zoneID, record.ID)
				})
				if err != nil {
					e.logger.Error("Error deleting AAAA record", "host", host, "error", err)
					failedHosts[host] = struct{}{}
				} else {
					deletedCount++
				}
			}
		}
	}

	processedHosts := collectHosts(routers, entrypoints, customURLs)
	for host := range processedHosts {
		processHost(host)
	}

	if firstRun {
		e.logger.Info(
			"Initial DNS validation/update complete",
			"routers", len(routers),
			"new", newCount,
			"hosts", len(processedHosts),
			"zones", len(processedZones),
			"failed_hosts", len(failedHosts),
			"updated", updatedCount,
			"created", createdCount,
			"deleted", deletedCount,
		)
	} else {
		e.logger.Info(
			"DNS update pass complete",
			"routers", len(routers),
			"new", newCount,
			"hosts", len(processedHosts),
			"zones", len(processedZones),
			"failed_hosts", len(failedHosts),
			"updated", updatedCount,
			"created", createdCount,
			"deleted", deletedCount,
		)
	}
}

func anyEntrypoint(routerEntrypoints, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, r := range routerEntrypoints {
		if slices.Contains(allowed, r) {
			return true
		}
	}
	return false
}

func mapRouters(routers []traefik.Router) map[string]traefik.Router {
	out := make(map[string]traefik.Router, len(routers))
	for _, r := range routers {
		out[r.Name] = r
	}
	return out
}

func diffRouters(oldMap, newMap map[string]traefik.Router) map[string]traefik.Router {
	out := make(map[string]traefik.Router)
	for k, v := range newMap {
		if _, ok := oldMap[k]; !ok {
			out[k] = v
		}
	}
	return out
}

func copySet(in map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for k := range in {
		out[k] = struct{}{}
	}
	return out
}

func proxiedForCreate(recordType string, defaultValue bool) bool {
	switch recordType {
	case "A", "AAAA", "CNAME":
		return defaultValue
	default:
		return false
	}
}

func proxiedForUpdate(record cloudflare.DNSRecord, recordType string, defaultValue bool) bool {
	if record.Proxied != nil {
		return *record.Proxied
	}
	return proxiedForCreate(recordType, defaultValue)
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) String() string {
	return fmt.Sprintf("engine{ipVersion:%s}", e.cfg.IPVersion)
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(host, ".")
}

func collectHosts(routers map[string]traefik.Router, entrypoints, customURLs []string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, router := range routers {
		if len(router.EntryPoints) > 0 && !anyEntrypoint(router.EntryPoints, entrypoints) {
			continue
		}
		hosts := traefik.ExtractHosts(router.Rule)
		for _, host := range hosts {
			host = normalizeHost(host)
			if host == "" {
				continue
			}
			out[host] = struct{}{}
		}
	}
	for _, host := range customURLs {
		host = normalizeHost(host)
		if host == "" {
			continue
		}
		out[host] = struct{}{}
	}
	return out
}

func (e *Engine) ensureZones(ctx context.Context) (map[string]string, error) {
	if e.zonesByName == nil {
		return e.refreshZones(ctx)
	}
	return e.zonesByName, nil
}

func (e *Engine) refreshZones(ctx context.Context) (map[string]string, error) {
	zones, err := e.cf.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	zonesByName := make(map[string]string, len(zones))
	for _, z := range zones {
		zonesByName[z.Name] = z.ID
	}
	e.zonesByName = zonesByName
	return zonesByName, nil
}

func (e *Engine) getZoneCache(
	ctx context.Context,
	rootDomain string,
	zonesByName map[string]string,
	processedZones map[string]*zoneCache,
) (*zoneCache, map[string]string, bool) {
	if cache, ok := processedZones[rootDomain]; ok {
		return cache, zonesByName, true
	}

	zoneID, ok := zonesByName[rootDomain]
	if !ok {
		var err error
		zonesByName, err = e.refreshZones(ctx)
		if err != nil {
			e.logger.Error("Failed to refresh Cloudflare zones", "error", err)
			return nil, zonesByName, false
		}
		zoneID, ok = zonesByName[rootDomain]
	}
	if !ok {
		e.logger.Warn("Zone ID not found", "domain", rootDomain)
		return nil, zonesByName, false
	}

	records, err := e.cf.ListDNSRecords(ctx, zoneID)
	if err != nil {
		e.logger.Warn("Failed to list DNS records, refreshing zones", "zone", rootDomain, "error", err)
		zonesByName, err = e.refreshZones(ctx)
		if err != nil {
			e.logger.Error("Failed to refresh Cloudflare zones", "error", err)
			return nil, zonesByName, false
		}
		zoneID, ok = zonesByName[rootDomain]
		if !ok {
			e.logger.Warn("Zone ID not found after refresh", "domain", rootDomain)
			return nil, zonesByName, false
		}
		records, err = e.cf.ListDNSRecords(ctx, zoneID)
		if err != nil {
			e.logger.Error("Failed to list DNS records", "zone", rootDomain, "error", err)
			return nil, zonesByName, false
		}
	}

	existingA := make(map[string]cloudflare.DNSRecord)
	existingAAAA := make(map[string]cloudflare.DNSRecord)
	existingCNAME := make(map[string]cloudflare.DNSRecord)
	duplicateA := make(map[string]struct{})
	duplicateAAAA := make(map[string]struct{})
	duplicateCNAME := make(map[string]struct{})
	for _, record := range records {
		switch record.Type {
		case "A":
			if _, ok := existingA[record.Name]; ok {
				duplicateA[record.Name] = struct{}{}
			} else {
				existingA[record.Name] = record
			}
		case "AAAA":
			if _, ok := existingAAAA[record.Name]; ok {
				duplicateAAAA[record.Name] = struct{}{}
			} else {
				existingAAAA[record.Name] = record
			}
		case "CNAME":
			if _, ok := existingCNAME[record.Name]; ok {
				duplicateCNAME[record.Name] = struct{}{}
			} else {
				existingCNAME[record.Name] = record
			}
		}
	}

	cache := &zoneCache{
		zoneID:         zoneID,
		existingA:      existingA,
		existingAAAA:   existingAAAA,
		existingCNAME:  existingCNAME,
		duplicateA:     duplicateA,
		duplicateAAAA:  duplicateAAAA,
		duplicateCNAME: duplicateCNAME,
	}
	processedZones[rootDomain] = cache
	return cache, zonesByName, true
}
