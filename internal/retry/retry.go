package retry

import (
	"context"
	"time"
)

// Do retries fn with exponential backoff. It stops early if ctx is canceled.
func Do(ctx context.Context, attempts int, minDelay, maxDelay time.Duration, fn func() error) error {
	if attempts < 1 {
		attempts = 1
	}

	var err error
	delay := minDelay
	for i := 0; i < attempts; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		if i == attempts-1 {
			break
		}
		if delay > maxDelay {
			delay = maxDelay
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return ctx.Err()
		}
		delay *= 2
		if delay < minDelay {
			delay = minDelay
		}
	}
	return err
}
