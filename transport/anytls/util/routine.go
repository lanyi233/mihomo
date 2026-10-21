package util

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/metacubex/mihomo/log"
)

func StartRoutine(ctx context.Context, d time.Duration, f func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorln("[BUG] %v %s", r, string(debug.Stack()))
			}
		}()
		timer := time.NewTimer(d)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if ctx.Err() != nil {
					return
				}
				f()
				timer.Reset(d)
			}
		}
	}()
}
