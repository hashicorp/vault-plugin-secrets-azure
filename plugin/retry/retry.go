package retry

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"time"
)

// RetryConfig defines the retry cadence and duration for the
// Retry function. Some examples of the total elapsed time
// for n retries using a Base of 1 second and various Ramp values:
//
//            time for n retries
//    | Ramp |  5  | 10  | 20    |
//    |------+-----+-----+-------|
//    |  1.0 | 5s  | 10s | 20s   |
//    |  1.1 | 7s  | 18s | 1m    |
//    |  1.2 | 9s  | 31s | 3m45s |
//    | 1.25 | 10s | 42s | 7m    |
//
type RetryConfig struct {
	Base    time.Duration // start and minimum retry duration
	Timeout time.Duration // max total retry runtime. 0 == indefinite
	Ramp    float64       // rate of delay increase
	Jitter  bool          // randomize between [Base, delay)
}

// Retry calls func f() at a cadence defined by cfg.
// Retries continue until f() returns true, Timeout has elapsed,
// or the context is cancelled.
func Retry(ctx context.Context, cfg RetryConfig, f func() (bool, error)) error {
	rand.Seed(time.Now().Unix())

	var endCh <-chan time.Time
	if cfg.Timeout != 0 {
		endCh = time.NewTimer(cfg.Timeout).C
	}

	for count := 0; ; count++ {
		if done, err := f(); done {
			return err
		}

		b := float64(cfg.Base)
		dur := int64(math.Max(b, b*math.Pow(cfg.Ramp, float64(count))))
		if cfg.Jitter {
			dur = rand.Int63n(dur)
		}
		delay := time.NewTimer(time.Duration(dur))

		select {
		case <-delay.C:
		case <-endCh:
			return errors.New("retry: timeout")
		case <-ctx.Done():
			return errors.New("retry: cancelled")
		}
	}
}
