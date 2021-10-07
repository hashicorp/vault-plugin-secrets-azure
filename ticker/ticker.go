package ticker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vrecan/life"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-uuid"
)

type routinePool interface {
	AcquireChan() chan struct{}
	Done()
}

// noopPool adheres to the routinePool interface but never blocks the caller. This assumes the channel returned
// from AcquireChan will be read from immediately
type noopPool struct {
	c chan struct{}
}

func (p noopPool) AcquireChan() chan struct{} {
	p.c <- struct{}{}
	return p.c
}
func (noopPool) Done() {}

// Ticker runs any number of functions based on a regular ticker. Each function is run with a separate underlying ticker
// which allows for any combination of schedules. Each function is also executed in a separate goroutine to allow
// for high parallelism. This parallelism can be restricted by specifying the `parallel` value > 0. If `parallel`
// is 0, this will not restrict concurrently executing goroutines.
// Note: Each RunFunc will be in its own goroutine, but the `parallel` argument restricts how many can be executing at
// the same time. If the RunFuncs take sufficient amount of time and `parallel` is specified small enough, the scheduling
// of the functions may not be on time as not enough compute time is provided to the Ticker.
type Ticker struct {
	logger log.Logger

	mu      *sync.Mutex
	pool    routinePool
	runners map[string]*runner
	getTime func() time.Time
}

// NewTicker constructor. `parallel`
func NewTicker(logger log.Logger, parallel int) (*Ticker, error) {
	if logger == nil {
		return nil, fmt.Errorf("missing logger")
	}
	if parallel < 0 {
		return nil, fmt.Errorf("parallel must be >= 0")
	}

	var pool routinePool
	if parallel > 0 {
		pool = NewSemaphore(parallel)
	} else {
		pool = noopPool{c: make(chan struct{}, 10)}
	}
	ticker := &Ticker{
		logger:  logger,
		mu:      new(sync.Mutex),
		pool:    pool,
		runners: map[string]*runner{},
		getTime: time.Now,
	}
	return ticker, nil
}

type runnerOpt func(*runner) error

// ID of the RunFunc goroutine. This ID will be shown in the log and returned from the Run function.
// If no ID is specified, a unique one will be provided
func ID(id string) runnerOpt {
	return func(r *runner) error {
		r.id = id
		r.logger = r.logger.With("id", id)
		return nil
	}
}

// Timeout provided to the context of the RunFunc call
func Timeout(timeout time.Duration) runnerOpt {
	return func(r *runner) error {
		r.contextTimeout = timeout
		return nil
	}
}

// FirstRun indicates when the RunFunc should be executed first. After the first run, the tickRate will take effect.
func FirstRun(t time.Time) runnerOpt {
	return func(r *runner) error {
		r.nextRun = t
		return nil
	}
}

func ErrorCallback(f ErrorCallbackFunc) runnerOpt {
	return func(r *runner) error {
		r.errFunc = f
		return nil
	}
}

// Run a given RunFunc on a cadence specified by `tickRate`. Each RunFunc will be run in parallel.
func (t *Ticker) Run(tickRate time.Duration, runFunc RunFunc, opts ...runnerOpt) (id string, err error) {
	merr := new(multierror.Error)
	if tickRate < 0 {
		merr = multierror.Append(merr, fmt.Errorf("tickRate must be >= 0"))
	}
	if runFunc == nil {
		merr = multierror.Append(merr, fmt.Errorf("missing runFunc"))
	}
	if merr.ErrorOrNil() != nil {
		return "", merr.ErrorOrNil()
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	id, err = uuid.GenerateUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %s", err)
	}

	subLogger := t.logger.With("id", id)

	runner := &runner{
		Life:           life.NewLife(),
		pool:           t.pool,
		state:          new(int32),
		logger:         subLogger,
		id:             id,
		getTime:        t.getTime,
		nextRun:        t.getTime().Add(tickRate),
		sleepTime:      tickRate,
		contextTimeout: 0,
		runFunc:        runFunc,
		errFunc: func(ctx context.Context, logger log.Logger, err error) {
			logger.Error("Failed to execute", "error", err)
		},
	}
	runner.SetRun(runner.run)

	merr = new(multierror.Error)
	for _, opt := range opts {
		merr = multierror.Append(merr, opt(runner))
	}

	if merr.ErrorOrNil() != nil {
		return "", merr.ErrorOrNil()
	}

	// If a runner with the same ID already exists, replace it and close the original
	if runner, exists := t.runners[runner.id]; exists {
		runner.Close()
		delete(t.runners, runner.id)
	}
	runner.Start()
	t.runners[runner.id] = runner

	return runner.id, nil
}

// Stop a given RunFunc specified by the provided id. Returns true if the ID exists, or false if the ID does not exist.
func (t *Ticker) Stop(id string) bool {
	t.logger.Debug("Stopping runner", "id", id)
	t.mu.Lock()
	defer t.mu.Unlock()

	runner, exists := t.runners[id]
	if !exists {
		return false
	}

	runner.Close()
	delete(t.runners, id)
	return true
}

// Close all RunFuncs. If closed, Run can still be called again to add new RunFuncs to the ticker.
func (t *Ticker) Close() error {
	t.logger.Trace("Closing ticker")
	t.mu.Lock()
	defer t.mu.Unlock()

	// Close all the runners in parallel and record any errors they return
	errs := make(chan error, len(t.runners))
	wg := &sync.WaitGroup{}
	wg.Add(len(t.runners))

	for i, r := range t.runners {
		go func(id string, runner *runner) {
			defer wg.Done()

			t.logger.Trace("Closing runner", "id", id)
			err := runner.Close()
			if err != nil {
				errs <- err
			}
		}(i, r)
	}

	// Wait for the parallel closing to finish
	wg.Wait()

	// Collect all the errors
	close(errs)
	merr := new(multierror.Error)
	for err := range errs {
		merr = multierror.Append(merr, err)
	}

	t.runners = map[string]*runner{}
	t.logger.Trace("Done closing ticker")
	return merr.ErrorOrNil()
}

type TickerStats struct {
	NumRunners int
	Running    int
	Waiting    int
}

// GetStats of the ticker. This includes basic stats about how many RunFuncs are specified and how many are running or
// waiting. The numbers may be slightly incorrect as this does not lock the underlying RunFuncs before retrieving stats.
// A given RunFunc may change from running to waiting, or vice versa during the execution of GetStats. This function
// prevent adding or removing RunFuncs from the Ticker during execution.
func (t *Ticker) GetStats() TickerStats {
	t.mu.Lock()
	defer t.mu.Unlock()

	numTickers := len(t.runners)
	running := 0
	waiting := 0
	for _, runner := range t.runners {
		if runner.running() {
			running++
		} else {
			waiting++
		}
	}

	stats := TickerStats{
		NumRunners: numTickers,
		Running:    running,
		Waiting:    waiting,
	}
	return stats
}
