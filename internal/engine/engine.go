package engine

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"docker-dns/internal/cloudflare"
	"docker-dns/internal/config"
	"docker-dns/internal/traefik"
)

type Engine struct {
	cfg     config.Config
	logger  *slog.Logger
	cf      dnsClient
	traefik routerSource
	wan     wanIPSource

	zonesByName map[string]string
}

type dnsClient interface {
	VerifyAuth(context.Context) error
	ListZones(context.Context) ([]cloudflare.Zone, error)
	ListDNSRecords(context.Context, string) ([]cloudflare.DNSRecord, error)
	CreateDNSRecord(context.Context, string, cloudflare.RecordParams) (cloudflare.DNSRecord, error)
	UpdateDNSRecord(context.Context, string, string, cloudflare.RecordParams) (cloudflare.DNSRecord, error)
	DeleteDNSRecord(context.Context, string, string) error
}

type routerSource interface {
	Routers(context.Context) ([]traefik.Router, error)
}

type wanIPSource interface {
	GetIPs(context.Context, string) (map[int]string, error)
}

func New(cfg config.Config, logger *slog.Logger, cf dnsClient, tf routerSource, wan wanIPSource) *Engine {
	return &Engine{
		cfg:     cfg,
		logger:  logger,
		cf:      cf,
		traefik: tf,
		wan:     wan,
	}
}

func (e *Engine) Run(ctx context.Context) error {
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

		if !maps.Equal(newWANIPs, wanIPs) {
			e.logger.Info("WAN IPs changed", "ips", newWANIPs)
			wanIPs = newWANIPs
		}

		addedRouters := diffRouters(routers, newRouters)
		newCount := len(addedRouters)

		prevFailed := copySet(failedHosts)
		failedHosts = make(map[string]struct{})
		if err := e.updateCloudflareRecords(ctx, newRouters, wanIPs, firstRun, newCount, failedHosts); err != nil {
			return err
		}
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

func (e *Engine) updateCloudflareRecords(
	ctx context.Context,
	routers map[string]traefik.Router,
	wanIPs map[int]string,
	firstRun bool,
	newCount int,
	failedHosts map[string]struct{},
) error {
	if firstRun {
		e.logger.Info("Initial DNS validation/update starting", "routers", len(routers), "new", newCount)
	} else {
		e.logger.Info("DNS update pass starting", "routers", len(routers), "new", newCount)
	}

	plan, err := e.buildReconciliationPlan(ctx, routers, wanIPs)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		e.logger.Error("Failed to list Cloudflare zones", "error", err)
		return nil
	}

	result, err := e.executePlan(ctx, plan)
	for host := range result.failedHosts {
		failedHosts[host] = struct{}{}
	}
	if err != nil {
		return err
	}

	if firstRun {
		e.logger.Info(
			"Initial DNS validation/update complete",
			"routers", len(routers),
			"new", newCount,
			"hosts", plan.hostCount,
			"zones", plan.zoneCount,
			"failed_hosts", len(failedHosts),
			"updated", result.updated,
			"created", result.created,
			"deleted", result.deleted,
		)
	} else {
		e.logger.Info(
			"DNS update pass complete",
			"routers", len(routers),
			"new", newCount,
			"hosts", plan.hostCount,
			"zones", plan.zoneCount,
			"failed_hosts", len(failedHosts),
			"updated", result.updated,
			"created", result.created,
			"deleted", result.deleted,
		)
	}
	return nil
}

func validateNestedProxyChanges(
	host string,
	rootDomain string,
	wanIPs map[int]string,
	existingA map[string]cloudflare.DNSRecord,
	existingAAAA map[string]cloudflare.DNSRecord,
	proxyDefault bool,
	allowNestedProxy bool,
) error {
	if allowNestedProxy || !isNestedHost(host, rootDomain) {
		return nil
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
			continue
		}

		record, exists := existing[host]
		if exists && record.Content == ip {
			continue
		}
		proxied := proxiedForCreate(recordType, proxyDefault)
		if exists {
			proxied = proxiedForUpdate(record, recordType, proxyDefault)
		}
		if proxied {
			return fmt.Errorf(
				"refusing to proxy nested Cloudflare record %q in zone %q; set CLOUDFLARE_ALLOW_NESTED_PROXY=true only when the zone supports it",
				host,
				rootDomain,
			)
		}
	}

	return nil
}

func isNestedHost(host, rootDomain string) bool {
	relative, found := strings.CutSuffix(host, "."+rootDomain)
	return found && strings.Contains(relative, ".")
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
