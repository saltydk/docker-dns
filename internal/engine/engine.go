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

	routersList, err := e.traefik.Routers(ctx)
	if err != nil {
		e.logger.Error("Error fetching Traefik routers", "error", err)
		return err
	}
	routers := mapRouters(routersList)

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

		prevFailed := copySet(failedHosts)
		failedHosts = make(map[string]struct{})
		e.updateCloudflareRecords(ctx, newRouters, wanIPs, firstRun, failedHosts)

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

		addedRouters := diffRouters(routers, newRouters)
		routers = newRouters
		if len(addedRouters) > 0 {
			e.updateCloudflareRecords(ctx, addedRouters, wanIPs, false, failedHosts)
		} else if firstRun {
			firstRun = false
		} else {
			e.logger.Info("Router scan", "routers", len(newRouters), "new", len(addedRouters))
		}

		if err := sleepWithContext(ctx, e.cfg.Delay); err != nil {
			return err
		}
	}
}

type zoneCache struct {
	zoneID  string
	records []cloudflare.DNSRecord
}

func (e *Engine) updateCloudflareRecords(
	ctx context.Context,
	routers map[string]traefik.Router,
	wanIPs map[int]string,
	firstRun bool,
	failedHosts map[string]struct{},
) {
	if firstRun {
		e.logger.Info("Initial DNS validation/update starting", "routers", len(routers))
	} else {
		e.logger.Info("DNS update pass starting", "routers", len(routers))
	}

	zones, err := e.cf.ListZones(ctx)
	if err != nil {
		e.logger.Error("Failed to list Cloudflare zones", "error", err)
		return
	}
	zonesByName := make(map[string]string, len(zones))
	for _, z := range zones {
		zonesByName[z.Name] = z.ID
	}

	processedZones := make(map[string]*zoneCache)
	processedHosts := make(map[string]struct{})
	entrypoints := e.cfg.TraefikEntrypoints
	customURLs := e.cfg.CustomURLs

	processHost := func(host string) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			return
		}

		rootDomain, err := publicsuffix.EffectiveTLDPlusOne(host)
		if err != nil {
			e.logger.Warn("Unable to determine root domain", "host", host, "error", err)
			return
		}

		cache, ok := processedZones[rootDomain]
		if !ok {
			zoneID, ok := zonesByName[rootDomain]
			if !ok {
				e.logger.Warn("Zone ID not found", "domain", rootDomain)
				return
			}
			records, err := e.cf.ListDNSRecords(ctx, zoneID)
			if err != nil {
				e.logger.Error("Failed to list DNS records", "zone", rootDomain, "error", err)
				return
			}
			cache = &zoneCache{zoneID: zoneID, records: records}
			processedZones[rootDomain] = cache
		}

		existingA := make(map[string]cloudflare.DNSRecord)
		existingAAAA := make(map[string]cloudflare.DNSRecord)
		existingCNAME := make(map[string]cloudflare.DNSRecord)
		for _, record := range cache.records {
			switch record.Type {
			case "A":
				existingA[record.Name] = record
			case "AAAA":
				existingAAAA[record.Name] = record
			case "CNAME":
				existingCNAME[record.Name] = record
			}
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
		}

		for version, ip := range wanIPs {
			var recordType string
			var existing map[string]cloudflare.DNSRecord
			switch version {
			case 4:
				recordType = "A"
				existing = existingA
			case 6:
				recordType = "AAAA"
				existing = existingAAAA
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
				}
			}
		}

		if e.cfg.IPVersion != "6" && e.cfg.IPVersion != "both" {
			if record, ok := existingAAAA[host]; ok {
				e.logger.Info("Removing AAAA record (IPv6 disabled)", "host", host)
				err := retry.Do(ctx, e.cfg.CFRetryAttempts, e.cfg.CFRetryMinDelay, e.cfg.CFRetryMaxDelay, func() error {
					return e.cf.DeleteDNSRecord(ctx, cache.zoneID, record.ID)
				})
				if err != nil {
					e.logger.Error("Error deleting AAAA record", "host", host, "error", err)
					failedHosts[host] = struct{}{}
				}
			}
		}
	}

	for _, router := range routers {
		if len(router.EntryPoints) > 0 && !anyEntrypoint(router.EntryPoints, entrypoints) {
			continue
		}
		hosts := traefik.ExtractHosts(router.Rule)
		for _, host := range hosts {
			if _, ok := processedHosts[host]; ok {
				continue
			}
			processHost(host)
			processedHosts[host] = struct{}{}
		}
	}

	for _, host := range customURLs {
		if _, ok := processedHosts[host]; ok {
			continue
		}
		processHost(host)
		processedHosts[host] = struct{}{}
	}

	if firstRun {
		e.logger.Info(
			"Initial DNS validation/update complete",
			"routers", len(routers),
			"hosts", len(processedHosts),
			"zones", len(processedZones),
			"failed_hosts", len(failedHosts),
		)
	} else {
		e.logger.Info(
			"DNS update pass complete",
			"routers", len(routers),
			"hosts", len(processedHosts),
			"zones", len(processedZones),
			"failed_hosts", len(failedHosts),
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
