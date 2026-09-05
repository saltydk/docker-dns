package retry

import (
	"context"
	"math/rand/v2"
	"time"
)

// Policy bounds the total number of attempts and the exponential backoff.
type Policy struct {
	Attempts int
	MinDelay time.Duration
	MaxDelay time.Duration
}

// Decision describes whether an error is transient and any server-directed delay.
type Decision struct {
	Retry      bool
	RetryAfter *time.Duration
}

// Classifier decides whether an operation error is safe to retry.
type Classifier func(error) Decision

// Do retries fn according to policy when classify marks the error as transient.
func Do(ctx context.Context, policy Policy, classify Classifier, fn func() error) error {
	attempts := max(policy.Attempts, 1)
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := fn()
		if err == nil {
			return nil
		}
		if attempt == attempts-1 || classify == nil {
			return err
		}

		decision := classify(err)
		if !decision.Retry {
			return err
		}
		if err := wait(ctx, retryDelay(policy, attempt, decision.RetryAfter)); err != nil {
			return err
		}
	}
	return nil
}

func retryDelay(policy Policy, retryNumber int, retryAfter *time.Duration) time.Duration {
	minDelay := max(policy.MinDelay, 0)
	maxDelay := max(policy.MaxDelay, minDelay)
	if retryAfter != nil {
		return min(max(*retryAfter, minDelay), maxDelay)
	}

	delay := minDelay
	for range retryNumber {
		if maxDelay > 0 && delay >= maxDelay/2 {
			delay = maxDelay
			break
		}
		delay *= 2
	}
	if maxDelay > 0 {
		delay = min(delay, maxDelay)
	}
	if delay < 4 {
		return delay
	}
	return max(delay-rand.N(delay/4), minDelay)
}

func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
