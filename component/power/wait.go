package power

import (
	"context"
	"time"
)

// WaitUntil waits for an optional background task's deadline while the device
// and network are active. It stops its timer while paused. An overdue deadline
// is delayed by resumeDelay after resuming, allowing downloads to settle and
// stagger; callers such as clock synchronization can pass zero for prompt work.
// It returns false on cancellation.
func WaitUntil(ctx context.Context, deadline time.Time, resumeDelay time.Duration) bool {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	wasPaused := false
	for {
		if ctx.Err() != nil {
			return false
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		paused, changed := BackgroundState()
		if paused {
			wasPaused = true
			select {
			case <-ctx.Done():
				return false
			case <-changed:
				continue
			}
		}
		if wasPaused && !deadline.After(time.Now()) && resumeDelay > 0 {
			deadline = time.Now().Add(resumeDelay)
		}
		wasPaused = false
		timer.Reset(time.Until(deadline))
		select {
		case <-ctx.Done():
			return false
		case <-changed:
			continue
		case <-timer.C:
			if paused, _ := BackgroundState(); !paused && ctx.Err() == nil {
				return true
			}
		}
	}
}
