package azuresecrets

import (
	"context"
	"testing"
	"time"
)

func TestRetry(t *testing.T) {
	t.Skip()
	f := func() (bool, error) {
		return false, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(114500 * time.Millisecond)
		cancel()
	}()

	Retry(ctx, &RetryConfig{Precise: true, Base: 1000 * time.Millisecond, Max: 5 * time.Second, Ramp: 1.0}, f)
}
