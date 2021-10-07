package ticker

import (
	"context"
	"sync/atomic"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/vrecan/life"
)

const (
	stateUndefined = iota
	stateWaiting
	stateRunning
	stateClosed
)

type RunnerDetails struct {
	// ID of the runner. This may be either randomly generated or provided when calling ticker.Run
	ID string

	// RunTime is the time that the runner was expected to run. This may not be the time that it is actually executed
	// due to the parallelism specified by the ticker.
	RunTime time.Time
	NextRun time.Time
}

type RunFunc func(ctx context.Context, logger log.Logger, runnerDetails RunnerDetails) error
type ErrorCallbackFunc func(ctx context.Context, logger log.Logger, err error)

type runner struct {
	*life.Life
	pool    routinePool
	state   *int32
	logger  log.Logger
	getTime func() time.Time

	id        string
	nextRun   time.Time
	sleepTime time.Duration

	contextTimeout time.Duration
	runFunc        RunFunc
	errFunc        ErrorCallbackFunc
}

func (r *runner) run() {
	// Don't allow restarting
	if atomic.LoadInt32(r.state) == stateClosed {
		return
	}

	atomic.SwapInt32(r.state, stateWaiting)

	if r.getTime == nil {
		r.getTime = time.Now
	}

	waitTime := r.nextRun.Sub(r.getTime())
	timer := time.NewTimer(waitTime)
	defer timer.Stop()

	for {
		select {
		case <-r.Life.Done:
			return
		// Wait for the tick to occur
		case <-timer.C:
			// now is the expected time that this should execute, but due to the semaphore pool this may be delayed
			now := r.getTime()

			select {
			// Ticker has fired but since parallel execution may not happen right away, check if Close has been called
			case <-r.Life.Done:
				return

			// Wait for parallel execution
			case <-r.pool.AcquireChan():
				r.nextRun = r.getTime().Add(r.sleepTime)
				r.execute(now, r.nextRun)
				r.pool.Done()

				waitTime := r.nextRun.Sub(r.getTime())
				timer.Reset(waitTime)
			}
		}
	}
}

// execute the underlying RunFunc. The runTime argument is the time that this should
// have been executed, but it may be delayed due to the semaphore limiting parallel
// execution.
func (r *runner) execute(runTime time.Time, nextRun time.Time) {
	atomic.SwapInt32(r.state, stateRunning)
	defer atomic.SwapInt32(r.state, stateWaiting)
	r.logger.Debug("Executing", "timeout", r.contextTimeout, "stateRunning", r.running())

	ctx := context.Background()
	if r.contextTimeout > 0 {
		c, cancel := context.WithDeadline(context.Background(), r.getTime().Add(r.contextTimeout))
		defer cancel()
		ctx = c
	}
	rd := RunnerDetails{
		ID:      r.id,
		RunTime: runTime,
		NextRun: nextRun,
	}
	err := r.runFunc(ctx, r.logger, rd)
	if err != nil && r.errFunc != nil {
		r.errFunc(ctx, r.logger, err)
	}
}

func (r *runner) running() bool {
	curState := atomic.LoadInt32(r.state)
	return curState == stateRunning
}

func (r *runner) Close() error {
	r.logger.Info("Closing runner")
	atomic.SwapInt32(r.state, stateClosed)
	return r.Life.Close()
}
