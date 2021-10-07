package ticker

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	log "github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
)

func TestTicker_basic(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger := log.New(&log.LoggerOptions{
		Level: log.Off,
	})

	tick, err := NewTicker(logger, 0)
	require.NoError(t, err)
	t.Cleanup(func() {
		tick.Close()
	})

	// Set up fake time so we can control when things are triggered
	now := time.Now()
	fakeTime := now
	fakeTimeFunc := func() time.Time {
		return fakeTime
	}
	tick.getTime = fakeTimeFunc

	// Set up controlled semaphore to also control when things are triggered
	sem := fakeSemaphore{make(chan struct{}, 10)}
	tick.pool = sem

	calledChan := make(chan struct{}, 1)
	t.Cleanup(func() { close(calledChan) })
	runFunc := func(ctx context.Context, logger log.Logger, _ RunnerDetails) error {
		calledChan <- struct{}{}
		return nil
	}

	// Start tick run which should execute immediately, but is halted by the fake semaphore
	id, err := tick.Run(1*time.Second, runFunc, FirstRun(now))
	require.NoError(t, err)
	require.NotEmpty(t, id)
	runner, exists := tick.runners[id]
	require.True(t, exists)
	require.NotNil(t, runner)

	// Trigger fake semaphore to allow the run to continue
	sem.Trigger()

	timer := time.NewTimer(10 * time.Millisecond)
	t.Cleanup(func() { timer.Stop() })

	select {
	case <-timer.C:
		t.Fatalf("Timed out waiting for execution")
	case <-calledChan:
		// Passed
	}

	stopped := tick.Stop(id)
	require.True(t, stopped)
}

func TestTicker_basic_with_timeout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger := log.New(&log.LoggerOptions{
		Level: log.Off,
	})

	tick, err := NewTicker(logger, 0)
	require.NoError(t, err)
	t.Cleanup(func() {
		tick.Close()
	})

	// Set up fake time so we can control when things are triggered
	// now := time.Now()
	// fakeTime := now
	// fakeTimeFunc := func() time.Time {
	// 	return fakeTime
	// }
	// tick.getTime = fakeTimeFunc
	//
	// // Set up controlled semaphore to also control when things are triggered
	// sem := fakeSemaphore{make(chan struct{}, 10)}
	// tick.pool = sem

	calledChan := make(chan time.Time, 1)
	t.Cleanup(func() { close(calledChan) })

	var actualCtx context.Context
	runFunc := func(ctx context.Context, logger log.Logger, _ RunnerDetails) error {
		actualCtx = ctx
		calledChan <- time.Now()
		return nil
	}

	// Start tick run which should execute immediately, but is halted by the fake semaphore
	timeout := 1 * time.Second
	id, err := tick.Run(1*time.Second, runFunc, FirstRun(time.Now()), Timeout(timeout))
	require.NoError(t, err)
	require.NotEmpty(t, id)
	runner, exists := tick.runners[id]
	require.True(t, exists)
	require.NotNil(t, runner)

	// Trigger fake semaphore to allow the run to continue
	// sem.Trigger()

	timer := time.NewTimer(1 * time.Second)
	t.Cleanup(func() { timer.Stop() })

	var calledTime time.Time
	select {
	case <-timer.C:
		t.Fatalf("Timed out waiting for execution")
	case calledTime = <-calledChan:
		// runFunc called
	}

	require.NotNil(t, actualCtx)
	ctxDeadline, ok := actualCtx.Deadline()
	require.True(t, ok)
	require.WithinDuration(t, ctxDeadline, calledTime.Add(timeout), 20*time.Millisecond)
}

func TestTicker_errorCallback(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger := log.New(&log.LoggerOptions{
		Level: log.Off,
	})

	tick, err := NewTicker(logger, 0)
	require.NoError(t, err)
	t.Cleanup(func() {
		tick.Close()
	})

	// Set up fake time so we can control when things are triggered
	now := time.Now()
	fakeTime := now
	fakeTimeFunc := func() time.Time {
		return fakeTime
	}
	tick.getTime = fakeTimeFunc

	// Set up controlled semaphore to also control when things are triggered
	sem := fakeSemaphore{make(chan struct{}, 10)}
	tick.pool = sem

	expectedErr := fmt.Errorf("this error came from the runFunc")
	runFunc := func(ctx context.Context, logger log.Logger, _ RunnerDetails) error {
		return expectedErr
	}

	// Capture the error for comparison later
	actualErrChan := make(chan error, 1)
	errCallbackFunc := func(ctx context.Context, logger log.Logger, err error) {
		actualErrChan <- err
	}

	// Start tick run which should execute immediately, but is halted by the fake semaphore
	id, err := tick.Run(1*time.Second, runFunc, FirstRun(now), ErrorCallback(errCallbackFunc))
	require.NoError(t, err)
	require.NotEmpty(t, id)
	runner, exists := tick.runners[id]
	require.True(t, exists)
	require.NotNil(t, runner)

	// Trigger fake semaphore to allow the run to continue
	sem.Trigger()

	timer := time.NewTimer(10 * time.Millisecond)
	t.Cleanup(func() { timer.Stop() })

	var actualErr error
	select {
	case <-timer.C:
		t.Fatalf("Timed out waiting for error callback")
	case err := <-actualErrChan:
		actualErr = err
	}

	require.Equal(t, expectedErr, actualErr)
}

func TestTicker_parallel(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger := log.New(&log.LoggerOptions{
		Level: log.Off,
	})

	tick, err := NewTicker(logger, 0)
	require.NoError(t, err)
	t.Cleanup(func() {
		tick.Close()
	})

	// Set up fake time so we can control when things are triggered
	now := time.Now()
	fakeTime := now
	fakeTimeFunc := func() time.Time {
		return fakeTime
	}
	tick.getTime = fakeTimeFunc

	numRuns := 10

	// Set up controlled semaphore to also control when things are triggered
	sem := fakeSemaphore{make(chan struct{}, numRuns)}
	tick.pool = sem

	calledChan := make(chan struct{}, numRuns)
	t.Cleanup(func() { close(calledChan) })

	runFunc := func(ctx context.Context, logger log.Logger, _ RunnerDetails) error {
		calledChan <- struct{}{}
		return nil
	}

	// Start tick run which should execute immediately, but is halted by the fake semaphore
	for i := 0; i < numRuns; i++ {
		id, err := tick.Run(1*time.Second, runFunc, FirstRun(now))
		require.NoError(t, err)
		require.NotEmpty(t, id)
		runner, exists := tick.runners[id]
		require.True(t, exists)
		require.NotNil(t, runner)
	}

	// Make sure none of the runs actually execute
	time.Sleep(10 * time.Millisecond)
	select {
	case <-calledChan:
		t.Fatalf("Test failure: runFunc shouldn't have been called yet")
	default:
		// Pass
	}

	timer := time.NewTimer(100 * time.Millisecond)
	t.Cleanup(func() { timer.Stop() })

	// Trigger the runs one at a time
	count := 0
	for i := 1; i <= numRuns; i++ {
		sem.Trigger()

		select {
		case <-timer.C:
			t.Fatalf("Timed out waiting for runFun to execute")
		case <-calledChan:
			count++
		}
	}
	require.Equal(t, numRuns, count)
}

func TestTicker_parallel_realtime(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger := log.New(&log.LoggerOptions{
		Level: log.Off,
	})

	tick, err := NewTicker(logger, 0)
	require.NoError(t, err)
	t.Cleanup(func() {
		tick.Close()
	})

	calledChan := make(chan time.Time, 1)
	t.Cleanup(func() { close(calledChan) })

	runFunc := func(ctx context.Context, logger log.Logger, _ RunnerDetails) error {
		calledChan <- time.Now()
		return nil
	}

	tickRate := 100 * time.Millisecond
	now := time.Now()
	id, err := tick.Run(tickRate, runFunc)
	require.NoError(t, err)
	require.NotEmpty(t, id)
	runner, exists := tick.runners[id]
	require.True(t, exists)
	require.NotNil(t, runner)

	// Shouldn't run because the wait time is longer
	time.Sleep(10 * time.Millisecond)
	select {
	case <-calledChan:
		t.Fatalf("Test failure: runFunc shouldn't have been called yet")
	default:
		// Pass
	}

	// Put an upper limit on this just so the test doesn't run super long
	timer := time.NewTimer(5 * time.Second)
	t.Cleanup(func() { timer.Stop() })

	for i := 1; i <= 4; i++ {
		select {
		case <-timer.C:
			t.Fatalf("Timed out waiting for executions")
		case actualTime := <-calledChan:
			expectedTime := now.Add(time.Duration(i) * tickRate)
			require.WithinDuration(t, expectedTime, actualTime, tickRate/2)
		}
	}
}

func TestTicker_parallel_limited_realtime(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	logger := log.New(&log.LoggerOptions{
		Level: log.Off,
	})

	parallelism := 2
	tick, err := NewTicker(logger, parallelism)
	require.NoError(t, err)
	t.Cleanup(func() {
		tick.Close()
	})

	seed := time.Now().UnixNano()
	// Printing the seed so this can be reproduced (well, more reproducible since we're still
	// dealing with the goroutine scheduler)
	t.Logf("RNG Seed: %d", seed)
	rng := rand.New(rand.NewSource(seed))
	seed++ // Use a different seed for the runners below

	numRunning := new(int32)

	numRunners := 10
	for i := 0; i < numRunners; i++ {
		runFunc := sleepyRun(numRunning, seed+int64(i))
		// Give some variability to the tick rate of each runner (50-100ms)
		tickRate := time.Duration(rng.Intn(100)+50) * time.Millisecond
		id, err := tick.Run(tickRate, runFunc)
		require.NoError(t, err)
		require.NotEmpty(t, id)
		runner, exists := tick.runners[id]
		require.True(t, exists)
		require.NotNil(t, runner)
	}

	// Put an upper limit on this just so the test doesn't run super long
	timer := time.NewTimer(1 * time.Second)
	t.Cleanup(func() { timer.Stop() })

	minConcurrentRuns := math.MaxInt
	maxConcurrentRuns := math.MinInt
LOOP:
	for {
		select {
		case <-timer.C:
			break LOOP
		default:
			// This could potentially be flaky if we aren't careful, but it seems to be stable for now
			actualRunning := atomic.LoadInt32(numRunning)
			require.GreaterOrEqual(t, actualRunning, int32(0))
			require.LessOrEqual(t, actualRunning, int32(parallelism))
			minConcurrentRuns = min(minConcurrentRuns, int(actualRunning))
			maxConcurrentRuns = max(maxConcurrentRuns, int(actualRunning))
		}
	}

	require.Equal(t, 0, minConcurrentRuns)
	require.LessOrEqual(t, maxConcurrentRuns, parallelism)
}

func sleepyRun(numRunning *int32, seed int64) RunFunc {
	rng := rand.New(rand.NewSource(seed))

	return func(ctx context.Context, logger log.Logger, _ RunnerDetails) error {
		atomic.AddInt32(numRunning, 1)
		sleepTime := time.Duration(rng.Intn(9)+1) * time.Millisecond
		time.Sleep(sleepTime)
		atomic.AddInt32(numRunning, -1)
		return nil
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func TestTickerConstructor_error(t *testing.T) {
	type testCase struct {
		logger    log.Logger
		parallel  int
		expectErr bool
	}

	tests := map[string]testCase{
		"nil logger": {
			logger:    nil,
			parallel:  0,
			expectErr: true,
		},
		"negative parallel": {
			logger:    log.Default(),
			parallel:  -1,
			expectErr: true,
		},
		"happy path": {
			logger:    log.Default(),
			parallel:  10,
			expectErr: false,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ticker, err := NewTicker(test.logger, test.parallel)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			if test.expectErr {
				require.Nil(t, ticker)
			} else {
				require.NotNil(t, ticker)
			}
		})
	}
}

func TestRunner_errors(t *testing.T) {
	type testCase struct {
		tickRate  time.Duration
		runFunc   RunFunc
		opts      []runnerOpt
		expectErr bool
		assertID  func(t require.TestingT, obj interface{}, args ...interface{})
	}

	tests := map[string]testCase{
		"negative tick rate": {
			tickRate: -1,
			runFunc: func(_ context.Context, _ log.Logger, _ RunnerDetails) error {
				return nil
			},
			expectErr: true,
			assertID:  require.Empty,
		},
		"nil runFunc": {
			tickRate:  1 * time.Second,
			runFunc:   nil,
			expectErr: true,
			assertID:  require.Empty,
		},
		"default ID": {
			tickRate: 1 * time.Second,
			runFunc: func(_ context.Context, _ log.Logger, _ RunnerDetails) error {
				return nil
			},
			expectErr: false,
			assertID:  require.NotEmpty,
		},
		"custom ID": {
			tickRate: 1 * time.Second,
			runFunc: func(_ context.Context, _ log.Logger, _ RunnerDetails) error {
				return nil
			},
			opts: []runnerOpt{
				ID("test-id"),
			},
			expectErr: false,
			assertID: func(t require.TestingT, id interface{}, _ ...interface{}) {
				require.Equal(t, "test-id", id)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			logger := log.New(&log.LoggerOptions{
				Level: log.Off,
			})
			ticker, err := NewTicker(logger, 0)
			require.NoError(t, err)
			require.NotNil(t, ticker)
			t.Cleanup(func() { ticker.Close() })

			id, err := ticker.Run(test.tickRate, test.runFunc, test.opts...)
			if test.expectErr && err == nil {
				t.Fatalf("err expected, got nil")
			}
			if !test.expectErr && err != nil {
				t.Fatalf("no error expected, got: %s", err)
			}
			test.assertID(t, id)
		})
	}
}

func TestDuplicateRunner(t *testing.T) {
	logger := log.New(&log.LoggerOptions{
		Level: log.Off,
	})
	ticker, err := NewTicker(logger, 0)
	require.NoError(t, err)
	require.NotNil(t, ticker)
	t.Cleanup(func() { ticker.Close() })

	firstFuncChan := make(chan struct{}, 1)
	firstFunc := func(ctx context.Context, logger log.Logger, runnerDetails RunnerDetails) error {
		firstFuncChan <- struct{}{}
		return nil
	}
	secondFuncChan := make(chan struct{}, 1)
	secondFunc := func(ctx context.Context, logger log.Logger, runnerDetails RunnerDetails) error {
		secondFuncChan <- struct{}{}
		return nil
	}

	id := "test-id"

	firstID, err := ticker.Run(100*time.Millisecond, firstFunc, ID(id))
	require.NoError(t, err)
	require.Equal(t, id, firstID)

	secondID, err := ticker.Run(100*time.Millisecond, secondFunc, ID(id))
	require.NoError(t, err)
	require.Equal(t, id, secondID)

	require.Len(t, ticker.runners, 1)

	timer := time.NewTimer(250 * time.Millisecond) // Prevents the test from running too long
	t.Cleanup(func() { timer.Stop() })

	select {
	case <-timer.C:
		t.Fatalf("Timed out waiting for second function")
	case <-secondFuncChan:
		// Pass
	}

	// Wait for the timer to give enough time for the first function to potentially run
	<-timer.C

	select {
	case <-firstFuncChan:
		t.Fatalf("First function ran when it shouldn't have")
	default:
		// Pass
	}
}

func TestGetStats(t *testing.T) {
	logger := log.New(&log.LoggerOptions{
		Level: log.Off,
	})
	ticker, err := NewTicker(logger, 0)
	require.NoError(t, err)
	require.NotNil(t, ticker)
	t.Cleanup(func() { ticker.Close() })

	numRunners := 10
	runningChan := make(chan struct{}, numRunners)
	notRunningChan := make(chan struct{}, numRunners)
	runFunc := func(ctx context.Context, logger log.Logger, runnerDetails RunnerDetails) error {
		runningChan <- struct{}{}
		time.Sleep(50 * time.Millisecond)
		notRunningChan <- struct{}{}
		return nil
	}

	for i := 0; i < numRunners; i++ {
		id, err := ticker.Run(100*time.Millisecond, runFunc)
		require.NoError(t, err)
		require.NotEmpty(t, id)
	}

	actual := ticker.GetStats()
	expectedStats := TickerStats{
		NumRunners: numRunners,
		Running:    0,
		Waiting:    numRunners,
	}
	require.Equal(t, expectedStats, actual)

	timer := time.NewTimer(1 * time.Second) // Prevents the test from taking too long
	t.Cleanup(func() { timer.Stop() })
	for i := 0; i < numRunners; i++ {
		select {
		case <-runningChan:
			// Good
		case <-timer.C:
			t.Fatalf("Timed out waiting for runners to activate")
		}
	}

	actual = ticker.GetStats()
	expectedStats = TickerStats{
		NumRunners: numRunners,
		Running:    numRunners,
		Waiting:    0,
	}
	require.Equal(t, expectedStats, actual)

	for i := 0; i < numRunners; i++ {
		select {
		case <-notRunningChan:
			// Good
		case <-timer.C:
			t.Fatalf("Timed out waiting for runners to finish")
		}
	}

	actual = ticker.GetStats()
	expectedStats = TickerStats{
		NumRunners: numRunners,
		Running:    0,
		Waiting:    numRunners,
	}
	require.Equal(t, expectedStats, actual)
}

type fakeSemaphore struct {
	c chan struct{}
}

func (s fakeSemaphore) AcquireChan() chan struct{} {
	return s.c
}

func (s fakeSemaphore) Done() {
	// Noop so the test can control execution
}

func (s fakeSemaphore) Trigger() {
	s.c <- struct{}{}
}
