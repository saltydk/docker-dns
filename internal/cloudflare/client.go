package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	cf "github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/dns"
	"github.com/cloudflare/cloudflare-go/v6/option"
	"github.com/cloudflare/cloudflare-go/v6/shared"
	"github.com/cloudflare/cloudflare-go/v6/zones"
)

type Auth struct {
	APIToken string
	APIKey   string
	Email    string
}

type Client struct {
	api    *cf.Client
	Logger *slog.Logger
}

type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type DNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied *bool  `json:"proxied"`
}

type RecordParams struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied *bool  `json:"proxied,omitempty"`
}

func New(auth Auth, httpClient *http.Client, logger *slog.Logger) (*Client, error) {
	opts := []option.RequestOption{
		option.WithMaxRetries(0),
	}
	if httpClient != nil {
		opts = append(opts, option.WithHTTPClient(httpClient))
	}
	if auth.APIToken != "" {
		opts = append(opts, option.WithAPIToken(auth.APIToken))
	} else {
		if auth.APIKey != "" {
			opts = append(opts, option.WithAPIKey(auth.APIKey))
		}
		if auth.Email != "" {
			opts = append(opts, option.WithAPIEmail(auth.Email))
		}
	}

	client := cf.NewClient(opts...)
	return &Client{api: client, Logger: logger}, nil
}

func (c *Client) VerifyAuth(ctx context.Context) error {
	_, err := c.api.Zones.List(ctx, zones.ZoneListParams{
		PerPage: cf.F(1.0),
	})
	return classifyError(err)
}

func (c *Client) ListZones(ctx context.Context) ([]Zone, error) {
	pager := c.api.Zones.ListAutoPaging(ctx, zones.ZoneListParams{
		PerPage: cf.F(50.0),
	})

	out := make([]Zone, 0, 64)
	for pager.Next() {
		z := pager.Current()
		out = append(out, Zone{ID: z.ID, Name: z.Name})
	}
	if err := pager.Err(); err != nil {
		return nil, classifyError(err)
	}
	return out, nil
}

func (c *Client) ListDNSRecords(ctx context.Context, zoneID string) ([]DNSRecord, error) {
	pager := c.api.DNS.Records.ListAutoPaging(ctx, dns.RecordListParams{
		ZoneID:  cf.F(zoneID),
		PerPage: cf.F(100.0),
	})

	out := make([]DNSRecord, 0, 128)
	for pager.Next() {
		current := pager.Current()
		rec, err := mapRecord(&current)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := pager.Err(); err != nil {
		return nil, classifyError(err)
	}
	return out, nil
}

func (c *Client) CreateDNSRecord(ctx context.Context, zoneID string, params RecordParams) (DNSRecord, error) {
	body, err := recordNewBody(params)
	if err != nil {
		return DNSRecord{}, err
	}
	res, err := c.api.DNS.Records.New(ctx, dns.RecordNewParams{
		ZoneID: cf.F(zoneID),
		Body:   body,
	})
	if err != nil {
		return DNSRecord{}, classifyError(err)
	}
	return mapRecord(res)
}

func (c *Client) UpdateDNSRecord(ctx context.Context, zoneID, recordID string, params RecordParams) (DNSRecord, error) {
	body, err := recordUpdateBody(params)
	if err != nil {
		return DNSRecord{}, err
	}
	res, err := c.api.DNS.Records.Update(ctx, recordID, dns.RecordUpdateParams{
		ZoneID: cf.F(zoneID),
		Body:   body,
	})
	if err != nil {
		return DNSRecord{}, classifyError(err)
	}
	return mapRecord(res)
}

func (c *Client) DeleteDNSRecord(ctx context.Context, zoneID, recordID string) error {
	_, err := c.api.DNS.Records.Delete(ctx, recordID, dns.RecordDeleteParams{
		ZoneID: cf.F(zoneID),
	})
	return classifyError(err)
}

func recordNewBody(params RecordParams) (dns.RecordNewParamsBodyUnion, error) {
	switch strings.ToUpper(params.Type) {
	case "A":
		rec := dns.ARecordParam{
			Name:    cf.F(params.Name),
			Type:    cf.F(dns.ARecordTypeA),
			Content: cf.F(params.Content),
		}
		if params.Proxied != nil {
			rec.Proxied = cf.F(*params.Proxied)
		}
		return rec, nil
	case "AAAA":
		rec := dns.AAAARecordParam{
			Name:    cf.F(params.Name),
			Type:    cf.F(dns.AAAARecordTypeAAAA),
			Content: cf.F(params.Content),
		}
		if params.Proxied != nil {
			rec.Proxied = cf.F(*params.Proxied)
		}
		return rec, nil
	default:
		return nil, fmt.Errorf("unsupported record type: %s", params.Type)
	}
}

func recordUpdateBody(params RecordParams) (dns.RecordUpdateParamsBodyUnion, error) {
	switch strings.ToUpper(params.Type) {
	case "A":
		rec := dns.ARecordParam{
			Name:    cf.F(params.Name),
			Type:    cf.F(dns.ARecordTypeA),
			Content: cf.F(params.Content),
		}
		if params.Proxied != nil {
			rec.Proxied = cf.F(*params.Proxied)
		}
		return rec, nil
	case "AAAA":
		rec := dns.AAAARecordParam{
			Name:    cf.F(params.Name),
			Type:    cf.F(dns.AAAARecordTypeAAAA),
			Content: cf.F(params.Content),
		}
		if params.Proxied != nil {
			rec.Proxied = cf.F(*params.Proxied)
		}
		return rec, nil
	default:
		return nil, fmt.Errorf("unsupported record type: %s", params.Type)
	}
}

func mapRecord(resp *dns.RecordResponse) (DNSRecord, error) {
	if resp == nil {
		return DNSRecord{}, errors.New("empty record response")
	}
	proxied := resp.Proxied
	recordType := string(resp.Type)
	return DNSRecord{
		ID:      resp.ID,
		Type:    recordType,
		Name:    resp.Name,
		Content: resp.Content,
		Proxied: &proxied,
	}, nil
}

func classifyError(err error) error {
	if err == nil {
		return nil
	}
	var apiErr *cf.Error
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("cloudflare auth failed: invalid token or key/email: %w", err)
		case http.StatusForbidden:
			return fmt.Errorf("cloudflare permission denied: auth lacks required permissions (Zone:Read, DNS:Edit): %w", err)
		default:
			if detail := formatErrorDetails(apiErr.Errors); detail != "" {
				return fmt.Errorf("cloudflare API error: %s: %w", detail, err)
			}
		}
	}
	return err
}

func formatErrorDetails(errors []shared.ErrorData) string {
	if len(errors) == 0 {
		return ""
	}
	const max = 3
	parts := make([]string, 0, max)
	for i, e := range errors {
		if i >= max {
			break
		}
		if e.Message == "" && e.Code == 0 {
			continue
		}
		if e.Message == "" {
			parts = append(parts, fmt.Sprintf("%d", e.Code))
			continue
		}
		if e.Code == 0 {
			parts = append(parts, e.Message)
			continue
		}
		parts = append(parts, fmt.Sprintf("%d: %s", e.Code, e.Message))
	}
	return strings.Join(parts, "; ")
}
