package ticker

// Semaphore that works with channels so it can be in a select statement
type Semaphore struct {
	c chan struct{}
}

// NewSemaphore that can be used in a select statement
func NewSemaphore(size int) *Semaphore {
	s := &Semaphore{
		c: make(chan struct{}, size),
	}
	// Populate the channel so AcquireChan can work immediately
	for i := 0; i < size; i++ {
		s.c <- struct{}{}
	}
	return s
}

func (s *Semaphore) AcquireChan() chan struct{} {
	// Create a new channel so there isn't potential for misuse by callers even though this loses some performance
	c := make(chan struct{}, 1)
	go func() {
		// Wait for the main channel to have a value (either from init, or from a Done call)
		<-s.c
		// Push to the returned channel so the caller can unblock
		c <- struct{}{}
	}()
	return c
}

// Done releases the semaphore. If Done is called before AcquireChan is called,
// this will block as no bounds checking is done here
func (s *Semaphore) Done() {
	s.c <- struct{}{}
}
