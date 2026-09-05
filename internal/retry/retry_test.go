package retry

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestDoRetriesRetryableErrorUntilSuccess(t *testing.T) {
	sentinel := errors.New("temporary")
	attempts := 0

	err := Do(t.Context(), Policy{Attempts: 3}, func(err error) Decision {
		return Decision{Retry: errors.Is(err, sentinel)}
	}, func() error {
		attempts++
		if attempts < 3 {
			return sentinel
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestDoDoesNotRetryPermanentError(t *testing.T) {
	sentinel := errors.New("permanent")
	attempts := 0

	err := Do(t.Context(), Policy{Attempts: 3}, func(error) Decision {
		return Decision{}
	}, func() error {
		attempts++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Do() error = %v, want sentinel", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestDoStopsBeforeCallingFunctionWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	attempts := 0

	err := Do(ctx, Policy{Attempts: 3}, func(error) Decision {
		return Decision{Retry: true}
	}, func() error {
		attempts++
		return errors.New("should not run")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Do() error = %v, want context cancellation", err)
	}
	if attempts != 0 {
		t.Fatalf("attempts = %d, want 0", attempts)
	}
}

func TestDoCapsRetryAfterAtMaximumDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		retryAfter := 20 * time.Second
		attempts := 0
		started := time.Now()

		err := Do(t.Context(), Policy{
			Attempts: 2,
			MinDelay: time.Second,
			MaxDelay: 10 * time.Second,
		}, func(error) Decision {
			return Decision{Retry: true, RetryAfter: &retryAfter}
		}, func() error {
			attempts++
			if attempts == 1 {
				return errors.New("temporary")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("Do() error = %v", err)
		}
		if elapsed := time.Since(started); elapsed != 10*time.Second {
			t.Fatalf("elapsed = %v, want 10s", elapsed)
		}
	})
}

func TestDoClampsRetryAfterAtMinimumDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		retryAfter := time.Second
		attempts := 0
		started := time.Now()

		err := Do(t.Context(), Policy{
			Attempts: 2,
			MinDelay: 4 * time.Second,
			MaxDelay: 10 * time.Second,
		}, func(error) Decision {
			return Decision{Retry: true, RetryAfter: &retryAfter}
		}, func() error {
			attempts++
			if attempts == 1 {
				return errors.New("temporary")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("Do() error = %v", err)
		}
		if elapsed := time.Since(started); elapsed != 4*time.Second {
			t.Fatalf("elapsed = %v, want 4s", elapsed)
		}
	})
}

func TestRetryDelayNeverFallsBelowMinimum(t *testing.T) {
	policy := Policy{MinDelay: 4 * time.Second, MaxDelay: 10 * time.Second}
	for range 100 {
		if delay := retryDelay(policy, 0, nil); delay < policy.MinDelay {
			t.Fatalf("retryDelay() = %v, below minimum %v", delay, policy.MinDelay)
		}
	}
}
