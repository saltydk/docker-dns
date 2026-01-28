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

type Provider struct {
	Client      *http.Client
	Logger      *slog.Logger
	MaxRetries  int
	RetryDelay  time.Duration
	HTTPTimeout time.Duration
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
	maxRetries := max(p.MaxRetries, 1)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		for _, url := range services {
			ip, err := p.fetchIP(ctx, url, version)
			if err == nil {
				return ip, nil
			}
		}
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
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	ipStr := ""
	if strings.Contains(url, "format=json") {
		var payload struct {
			IP string `json:"ip"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return "", err
		}
		ipStr = strings.TrimSpace(payload.IP)
	} else {
		ipStr = strings.TrimSpace(string(body))
	}

	if ipStr == "" {
		return "", errors.New("empty IP response")
	}

	ip := net.ParseIP(ipStr)
	if !isValidWANIP(ip, version) {
		return "", fmt.Errorf("invalid WAN IP: %s", ipStr)
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
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
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
