package engine

import (
	"context"
	"fmt"
)

type reconciliationPlan struct {
	hosts     []hostPlan
	hostCount int
	zoneCount int
}

type passResult struct {
	created     int
	updated     int
	deleted     int
	failedHosts map[string]struct{}
}

func (e *Engine) executePlan(ctx context.Context, plan reconciliationPlan) (passResult, error) {
	result := passResult{failedHosts: make(map[string]struct{})}
	for _, host := range plan.hosts {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if host.blocked != nil {
			e.logger.Error("Host reconciliation blocked", "host", host.host, "error", host.blocked)
			result.failedHosts[host.host] = struct{}{}
			continue
		}
		for _, issue := range host.issues {
			e.logger.Error("Host reconciliation issue", "host", host.host, "error", issue)
			result.failedHosts[host.host] = struct{}{}
		}

		if host.prerequisite != nil {
			e.logChange(*host.prerequisite)
			if err := e.executeChange(ctx, *host.prerequisite); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return result, ctxErr
				}
				e.logChangeError(*host.prerequisite, err)
				result.failedHosts[host.host] = struct{}{}
				continue
			}
			result.deleted++
		}

		for _, change := range host.changes {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			e.logChange(change)
			if err := e.executeChange(ctx, change); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return result, ctxErr
				}
				e.logChangeError(change, err)
				result.failedHosts[host.host] = struct{}{}
				continue
			}
			switch change.kind {
			case changeCreate:
				result.created++
			case changeUpdate:
				result.updated++
			case changeDelete:
				result.deleted++
			}
		}
	}
	return result, nil
}

func (e *Engine) executeChange(ctx context.Context, change dnsChange) error {
	switch change.kind {
	case changeCreate:
		_, err := e.cf.CreateDNSRecord(ctx, change.zoneID, change.params)
		return err
	case changeUpdate:
		_, err := e.cf.UpdateDNSRecord(ctx, change.zoneID, change.recordID, change.params)
		return err
	case changeDelete:
		return e.cf.DeleteDNSRecord(ctx, change.zoneID, change.recordID)
	default:
		return fmt.Errorf("unknown DNS change kind %d", change.kind)
	}
}

func (e *Engine) logChange(change dnsChange) {
	switch change.kind {
	case changeCreate:
		e.logger.Info("Adding record", "type", change.recordType, "host", change.params.Name, "proxied", pointerValue(change.params.Proxied))
	case changeUpdate:
		e.logger.Info("Updating record", "type", change.recordType, "host", change.params.Name, "proxied", pointerValue(change.params.Proxied))
	case changeDelete:
		if change.recordType == "CNAME" {
			e.logger.Info("Found CNAME record, deleting", "host", change.params.Name)
		} else {
			e.logger.Info("Removing record (IP family disabled)", "type", change.recordType, "host", change.params.Name)
		}
	}
}

func (e *Engine) logChangeError(change dnsChange, err error) {
	e.logger.Error("Error applying DNS change", "operation", change.kind.String(), "type", change.recordType, "host", change.params.Name, "error", err)
}

func (k changeKind) String() string {
	switch k {
	case changeCreate:
		return "create"
	case changeUpdate:
		return "update"
	case changeDelete:
		return "delete"
	default:
		return "unknown"
	}
}

func pointerValue(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}
