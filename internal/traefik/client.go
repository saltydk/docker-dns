package traefik

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const maxResponseBytes = 4 << 20

var hostRuleRegexp = regexp.MustCompile(`Host\(([^)]*)\)`)
var backtickRegexp = regexp.MustCompile("`([^`]*)`")

// Router represents a subset of Traefik router fields.
type Router struct {
	Name        string   `json:"name"`
	EntryPoints []string `json:"entryPoints"`
	Rule        string   `json:"rule"`
}

type Client struct {
	BaseURL string
	Client  *http.Client
}

// Routers returns all routers from Traefik with pagination.
func (c *Client) Routers(ctx context.Context) ([]Router, error) {
	page := 1
	perPage := 100
	all := make([]Router, 0, 128)

	for {
		endpoint := fmt.Sprintf("%s/api/http/routers", strings.TrimRight(c.BaseURL, "/"))
		q := url.Values{}
		q.Set("page", strconv.Itoa(page))
		q.Set("per_page", strconv.Itoa(perPage))
		fullURL := endpoint + "?" + q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating Traefik routers request for page %d: %w", page, err)
		}

		resp, err := c.httpClient().Do(req)
		if err != nil {
			return nil, fmt.Errorf("requesting Traefik routers page %d from %s: %w", page, fullURL, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading Traefik routers page %d from %s: %w", page, fullURL, err)
		}
		if len(body) > maxResponseBytes {
			return nil, fmt.Errorf("traefik routers response for page %d from %s: status %d, exceeds %d bytes", page, fullURL, resp.StatusCode, maxResponseBytes)
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("requesting Traefik routers page %d from %s: status %d", page, fullURL, resp.StatusCode)
		}

		var routers []Router
		if err := json.Unmarshal(body, &routers); err != nil {
			return nil, fmt.Errorf("decoding Traefik routers page %d from %s: %w", page, fullURL, err)
		}

		if len(routers) == 0 {
			break
		}
		all = append(all, routers...)

		nextPage := page
		if header := resp.Header.Get("X-Next-Page"); header != "" {
			if v, err := strconv.Atoi(header); err == nil {
				nextPage = v
			}
		}
		if nextPage <= page {
			break
		}
		page = nextPage
	}

	return all, nil
}

// ExtractHosts returns hostnames from a Traefik rule string.
// Only Host(`...`) with backticks is supported.
func ExtractHosts(rule string) []string {
	clauses := hostRuleRegexp.FindAllStringSubmatch(rule, -1)
	if len(clauses) == 0 {
		return nil
	}

	out := make([]string, 0, len(clauses))
	for _, clause := range clauses {
		if len(clause) < 2 || clause[1] == "" {
			continue
		}
		hosts := backtickRegexp.FindAllStringSubmatch(clause[1], -1)
		for _, host := range hosts {
			if len(host) > 1 && host[1] != "" {
				out = append(out, host[1])
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (c *Client) httpClient() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return http.DefaultClient
}
