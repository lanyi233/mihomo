package power

import (
	"context"
	"testing"
	"time"
)

func TestWaitUntilPausedCancellation(t *testing.T) {
	SetDevicePaused(true)
	defer SetDevicePaused(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	go func() { done <- WaitUntil(ctx, time.Now(), 0) }()
	select {
	case <-done:
		t.Fatal("paused maintenance became ready")
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case ready := <-done:
		if ready {
			t.Fatal("cancelled maintenance became ready")
		}
	case <-time.After(time.Second):
		t.Fatal("paused wait ignored cancellation")
	}
}

func TestWaitUntilResumeDelaysOverdueWork(t *testing.T) {
	SetDevicePaused(true)
	defer SetDevicePaused(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan bool, 1)
	const settle = 50 * time.Millisecond
	go func() { done <- WaitUntil(ctx, time.Now().Add(-time.Hour), settle) }()
	select {
	case <-done:
		t.Fatal("paused work became ready")
	case <-time.After(30 * time.Millisecond):
	}
	resumed := time.Now()
	SetDevicePaused(false)
	select {
	case ready := <-done:
		if !ready || time.Since(resumed) < settle {
			t.Fatal("overdue maintenance skipped the resume settle delay")
		}
	case <-time.After(time.Second):
		t.Fatal("maintenance did not resume")
	}
}

func TestWaitUntilKeepsFutureDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline := time.Now().Add(30 * time.Millisecond)
	if !WaitUntil(ctx, deadline, time.Hour) || time.Now().Before(deadline) {
		t.Fatal("active maintenance did not honor its deadline")
	}
}
