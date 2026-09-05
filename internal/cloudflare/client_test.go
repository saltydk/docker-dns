package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cf "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/option"
	"github.com/cloudflare/cloudflare-go/v7/shared"

	"docker-dns/internal/retry"
)

func TestDNSMutationsRetryTransientFailures(t *testing.T) {
	tests := []struct {
		name   string
		invoke func(context.Context, *Client) error
	}{
		{
			name: "create",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.CreateDNSRecord(ctx, "zone", RecordParams{Type: "A", Name: "example.com", Content: "192.0.2.1"})
				return err
			},
		},
		{
			name: "update",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.UpdateDNSRecord(ctx, "zone", "record", RecordParams{Type: "A", Name: "example.com", Content: "192.0.2.1"})
				return err
			},
		},
		{
			name: "delete",
			invoke: func(ctx context.Context, client *Client) error {
				return client.DeleteDNSRecord(ctx, "zone", "record")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var attempts atomic.Int32
			server := httptestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if attempts.Add(1) == 1 {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = fmt.Fprint(w, `{"errors":[{"code":1000,"message":"temporary"}]}`)
					return
				}
				_, _ = fmt.Fprint(w, `{"result":{"id":"record","type":"A","name":"example.com","content":"192.0.2.1","proxied":false}}`)
			})

			client := Client{
				api:         newTestAPIClient(server),
				retryPolicy: retry.Policy{Attempts: 2},
			}
			if err := test.invoke(t.Context(), &client); err != nil {
				t.Fatalf("mutation error = %v", err)
			}
			if got := attempts.Load(); got != 2 {
				t.Fatalf("attempts = %d, want 2", got)
			}
		})
	}
}

func TestDeleteDNSRecordDoesNotRetryPermanentFailure(t *testing.T) {
	var attempts atomic.Int32
	server := httptestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		attempts.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"errors":[{"code":1001,"message":"forbidden"}]}`)
	})

	client := Client{
		api: newTestAPIClient(server),
		retryPolicy: retry.Policy{
			Attempts: 3,
		},
	}
	err := client.DeleteDNSRecord(t.Context(), "zone", "record")
	if err == nil {
		t.Fatal("DeleteDNSRecord() error = nil, want permanent failure")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

func httptestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func newTestAPIClient(server *httptest.Server) *cf.Client {
	return cf.NewClient(
		option.WithBaseURL(server.URL),
		option.WithHTTPClient(server.Client()),
		option.WithMaxRetries(0),
		option.WithAPIToken("token"),
	)
}

func TestRetryDecisionClassifiesHTTPStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		header     http.Header
		wantRetry  bool
	}{
		{name: "bad request", statusCode: http.StatusBadRequest},
		{name: "unauthorized", statusCode: http.StatusUnauthorized},
		{name: "forbidden", statusCode: http.StatusForbidden},
		{name: "not found", statusCode: http.StatusNotFound},
		{name: "request timeout", statusCode: http.StatusRequestTimeout, wantRetry: true},
		{name: "conflict", statusCode: http.StatusConflict, wantRetry: true},
		{name: "rate limited", statusCode: http.StatusTooManyRequests, wantRetry: true},
		{name: "server error", statusCode: http.StatusInternalServerError, wantRetry: true},
		{name: "last server error", statusCode: 599, wantRetry: true},
		{name: "nonstandard status", statusCode: 600},
		{name: "header forces retry", statusCode: http.StatusBadRequest, header: http.Header{"X-Should-Retry": {"true"}}, wantRetry: true},
		{name: "header prevents retry", statusCode: http.StatusInternalServerError, header: http.Header{"X-Should-Retry": {"false"}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := &cf.Error{
				StatusCode: test.statusCode,
				Response: &http.Response{
					StatusCode: test.statusCode,
					Header:     test.header,
				},
			}
			if got := retryDecision(err).Retry; got != test.wantRetry {
				t.Fatalf("retryDecision().Retry = %v, want %v", got, test.wantRetry)
			}
		})
	}
}

func TestRetryDecisionParsesRetryAfter(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		header http.Header
		want   time.Duration
	}{
		{name: "milliseconds", header: http.Header{"Retry-After-Ms": {"1500"}}, want: 1500 * time.Millisecond},
		{name: "seconds", header: http.Header{"Retry-After": {"3"}}, want: 3 * time.Second},
		{name: "HTTP date", header: http.Header{"Retry-After": {now.Add(5 * time.Second).In(time.FixedZone("GMT", 0)).Format(http.TimeFormat)}}, want: 5 * time.Second},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := &cf.Error{
				StatusCode: http.StatusTooManyRequests,
				Response: &http.Response{
					StatusCode: http.StatusTooManyRequests,
					Header:     test.header,
				},
			}
			decision := retryDecisionAt(err, now)
			if decision.RetryAfter == nil || *decision.RetryAfter != test.want {
				t.Fatalf("retryDecisionAt().RetryAfter = %v, want %v", decision.RetryAfter, test.want)
			}
		})
	}
}

func TestRetryDecisionClassifiesTransportErrors(t *testing.T) {
	transportErr := &url.Error{
		Op:  "Post",
		URL: "https://api.cloudflare.com",
		Err: &net.DNSError{IsTimeout: true},
	}
	if !retryDecision(transportErr).Retry {
		t.Fatal("retryDecision() did not retry transport error")
	}
	if retryDecision(errors.New("local failure")).Retry {
		t.Fatal("retryDecision() retried unknown local error")
	}
}

func TestClassifyErrorAuth(t *testing.T) {
	err := classifyError(&cf.Error{StatusCode: 401})
	if err == nil || !strings.Contains(err.Error(), "cloudflare auth failed") {
		t.Fatalf("expected auth failed error, got %v", err)
	}
}

func TestClassifyErrorPermission(t *testing.T) {
	err := classifyError(&cf.Error{StatusCode: 403})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected permission denied error, got %v", err)
	}
}

func TestClassifyErrorDetails(t *testing.T) {
	apiErr := &cf.Error{
		StatusCode: 400,
		Errors: []shared.ErrorData{
			{Code: 1001, Message: "bad request"},
		},
	}
	err := classifyError(apiErr)
	if err == nil || !strings.Contains(err.Error(), "1001: bad request") {
		t.Fatalf("expected error detail, got %v", err)
	}
}

func TestClassifyErrorPassthrough(t *testing.T) {
	sentinel := errors.New("plain error")
	err := classifyError(sentinel)
	if err != sentinel {
		t.Fatalf("expected passthrough error, got %v", err)
	}
}
