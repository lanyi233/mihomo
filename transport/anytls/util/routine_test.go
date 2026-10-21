package util

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

func TestRoutineCancellationSkipsPendingCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		StartRoutine(ctx, time.Hour, func() { calls++ })
		synctest.Wait()
		cancel()
		synctest.Wait()
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		if calls != 0 {
			t.Fatalf("callback ran %d times after cancellation", calls)
		}
	})
}
