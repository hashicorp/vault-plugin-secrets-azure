package azuresecrets

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/hashicorp/vault/logical"
)

func GetInternalString(req *logical.Request, name string) (data string, err error) {
	if dataRaw, ok := req.Secret.InternalData[name]; ok {
		if data, ok = dataRaw.(string); ok {
			return
		} else {
			return "", fmt.Errorf("internal data '%s' is invalid", name)
		}
	}
	return "", fmt.Errorf("internal data '%s' not found", name)
}

type RetryConfig struct {
	Base    time.Duration
	Ramp    float64
	Max     time.Duration
	Precise bool
}

/*
   |      | 5   | 10  | 20    |
   |------+-----+-----+-------|
   |  1.0 | 5s  | 10s | 20s   |
   |  1.1 | 7s  | 18s | 1m    |
   |  1.2 | 9s  | 31s | 3m45s |
   | 1.25 | 10s | 42s | 7m    |
*/
func Retry(ctx context.Context, cfg *RetryConfig, f func() (bool, error)) error {
	rand.Seed(time.Now().Unix())

	var count int

	end := time.NewTimer(cfg.Max)
	for {
		count++

		if done, err := f(); done {
			return err
		}

		b := float64(cfg.Base)
		dur := int64(math.Max(b, b*math.Pow(cfg.Ramp, float64(count))))
		if !cfg.Precise {
			dur = rand.Int63n(dur)
		}
		delay := time.NewTimer(time.Duration(dur))

		select {
		case <-delay.C:
		case <-end.C:
			return errors.New("retry: timeout")
		case <-ctx.Done():
			return errors.New("retry: cancelled")
		}
	}
}
