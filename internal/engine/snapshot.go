package engine

import (
	"context"

	"docker-dns/internal/cloudflare"
)

type zoneCache struct {
	zoneID         string
	existingA      map[string]cloudflare.DNSRecord
	existingAAAA   map[string]cloudflare.DNSRecord
	existingCNAME  map[string]cloudflare.DNSRecord
	duplicateA     map[string]struct{}
	duplicateAAAA  map[string]struct{}
	duplicateCNAME map[string]struct{}
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
	for _, zone := range zones {
		zonesByName[zone.Name] = zone.ID
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
