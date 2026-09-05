package cloudflare

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	cf "github.com/cloudflare/cloudflare-go/v7"

	"docker-dns/internal/retry"
)

func retryDecision(err error) retry.Decision {
	return retryDecisionAt(err, time.Now())
}

func retryDecisionAt(err error, now time.Time) retry.Decision {
	var apiErr *cf.Error
	if errors.As(err, &apiErr) {
		statusCode := apiErr.StatusCode
		var header http.Header
		if apiErr.Response != nil {
			header = apiErr.Response.Header
			if statusCode == 0 {
				statusCode = apiErr.Response.StatusCode
			}
		}

		decision := retry.Decision{}
		switch strings.ToLower(strings.TrimSpace(header.Get("X-Should-Retry"))) {
		case "true":
			decision.Retry = true
		case "false":
			return decision
		default:
			decision.Retry = statusCode == http.StatusRequestTimeout ||
				statusCode == http.StatusConflict ||
				statusCode == http.StatusTooManyRequests ||
				(statusCode >= http.StatusInternalServerError && statusCode <= 599)
		}
		if decision.Retry {
			decision.RetryAfter = parseRetryAfter(header, now)
		}
		return decision
	}

	var networkErr net.Error
	return retry.Decision{Retry: errors.As(err, &networkErr)}
}

func parseRetryAfter(header http.Header, now time.Time) *time.Duration {
	if header == nil {
		return nil
	}
	if value := header.Get("Retry-After-Ms"); value != "" {
		if milliseconds, err := strconv.ParseFloat(value, 64); err == nil {
			delay := time.Duration(milliseconds * float64(time.Millisecond))
			return &delay
		}
	}
	if value := header.Get("Retry-After"); value != "" {
		if seconds, err := strconv.ParseFloat(value, 64); err == nil {
			delay := time.Duration(seconds * float64(time.Second))
			return &delay
		}
		if retryAt, err := http.ParseTime(value); err == nil {
			delay := retryAt.Sub(now)
			return &delay
		}
	}
	return nil
}
