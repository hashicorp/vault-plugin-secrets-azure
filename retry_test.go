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
		time.Sleep(5000 * time.Millisecond)
		cancel()
	}()

	Retry(ctx, RetryConfig{
		Jitter:  false,
		Base:    1000 * time.Millisecond,
		Timeout: 50 * time.Second,
		Ramp:    1.1}, f)
}
