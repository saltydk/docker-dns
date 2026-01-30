package cloudflare

import (
	"errors"
	"strings"
	"testing"

	cf "github.com/cloudflare/cloudflare-go/v6"
	"github.com/cloudflare/cloudflare-go/v6/shared"
)

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
