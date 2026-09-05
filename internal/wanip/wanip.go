package wanip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxResponseBytes = 1024

type Provider struct {
	Client      *http.Client
	Logger      *slog.Logger
	MaxRetries  int
	RetryDelay  time.Duration
	HTTPTimeout time.Duration
	services    func(int) []string
}

func (p *Provider) GetIPs(ctx context.Context, ipVersion string) (map[int]string, error) {
	ips := make(map[int]string)
	switch ipVersion {
	case "both":
		ip4, err := p.getIP(ctx, 4)
		if err != nil {
			return nil, err
		}
		ip6, err := p.getIP(ctx, 6)
		if err != nil {
			return nil, err
		}
		ips[4] = ip4
		ips[6] = ip6
	case "4":
		ip4, err := p.getIP(ctx, 4)
		if err != nil {
			return nil, err
		}
		ips[4] = ip4
	case "6":
		ip6, err := p.getIP(ctx, 6)
		if err != nil {
			return nil, err
		}
		ips[6] = ip6
	default:
		return nil, fmt.Errorf("invalid IP version: %s", ipVersion)
	}
	return ips, nil
}

func (p *Provider) getIP(ctx context.Context, version int) (string, error) {
	services := ipServices(version)
	if p.services != nil {
		services = p.services(version)
	}
	maxRetries := max(p.MaxRetries, 1)
	var finalErrors []error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		attemptErrors := make([]error, 0, len(services))
		for _, url := range services {
			ip, err := p.fetchIP(ctx, url, version)
			if err == nil {
				return ip, nil
			}
			attemptErrors = append(attemptErrors, err)
		}
		finalErrors = attemptErrors
		if attempt < maxRetries {
			if p.Logger != nil {
				p.Logger.Warn("Failed to obtain WAN IP, retrying", "version", version, "delay", p.RetryDelay)
			}
			select {
			case <-time.After(p.RetryDelay):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
	}
	if err := errors.Join(finalErrors...); err != nil {
		return "", fmt.Errorf("failed to obtain a valid WAN IPv%d address after %d tries: %w", version, maxRetries, err)
	}
	return "", fmt.Errorf("failed to obtain a valid WAN IPv%d address after %d tries", version, maxRetries)
}

func (p *Provider) fetchIP(ctx context.Context, url string, version int) (string, error) {
	client := p.Client
	if client == nil {
		client = &http.Client{}
	}
	ctx, cancel := context.WithTimeout(ctx, p.HTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating WAN IP request for %s: %w", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting WAN IP from %s: %w", url, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("requesting WAN IP from %s: status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading WAN IP response from %s: %w", url, err)
	}
	if len(body) > maxResponseBytes {
		return "", fmt.Errorf("WAN IP response from %s exceeds %d bytes", url, maxResponseBytes)
	}

	ipStr := ""
	if strings.Contains(url, "format=json") {
		var payload struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return "", fmt.Errorf("decoding WAN IP response from %s: %w", url, err)
		}
		ipStr = strings.TrimSpace(payload.IP)
	} else {
		ipStr = strings.TrimSpace(string(body))
	}

	if ipStr == "" {
		return "", fmt.Errorf("empty IP response from %s", url)
	}

	ip := net.ParseIP(ipStr)
	if !isValidWANIP(ip, version) {
		return "", fmt.Errorf("invalid WAN IP from %s: %s", url, ipStr)
	}

	return ipStr, nil
}

func isValidWANIP(ip net.IP, version int) bool {
	if ip == nil {
		return false
	}
	if version == 4 && ip.To4() == nil {
		return false
	}
	if version == 6 && ip.To4() != nil {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	return true
}

func ipServices(version int) []string {
	if version == 6 {
		return []string{
			"https://ipify6.saltbox.dev?format=json",
			"https://api6.ipify.org?format=json",
			"https://ipv6.icanhazip.com",
		}
	}
	return []string{
		"https://ipify.saltbox.dev?format=json",
		"https://api4.ipify.org?format=json",
		"https://ipv4.icanhazip.com",
	}
}
