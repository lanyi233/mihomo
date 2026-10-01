package ntp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/power"
	"github.com/metacubex/mihomo/component/proxydialer"
	M "github.com/metacubex/sing/common/metadata"
)

type ntpTestDialer struct {
	proxydialer.SingDialer
	attempts chan struct{}
}

func (d ntpTestDialer) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	d.attempts <- struct{}{}
	return nil, errors.New("test NTP endpoint unavailable")
}

func TestNTPInitialSyncHonorsPause(t *testing.T) {
	for _, paused := range []bool{false, true} {
		name := "online"
		if paused {
			name = "paused"
		}
		t.Run(name, func(t *testing.T) {
			power.SetDevicePaused(paused)
			defer power.SetDevicePaused(false)
			ctx, cancel := context.WithCancel(context.Background())
			attempts := make(chan struct{}, 3)
			srv := &Service{ctx: ctx, cancel: cancel, interval: time.Hour, dialer: ntpTestDialer{attempts: attempts}}
			done := make(chan struct{})
			go func() { defer close(done); srv.loopUpdate() }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("NTP service did not stop")
				}
			})
			if paused {
				select {
				case <-attempts:
					t.Fatal("NTP dialed while paused")
				case <-time.After(30 * time.Millisecond):
				}
				power.SetDevicePaused(false)
			}
			select {
			case <-attempts:
			case <-time.After(time.Second):
				t.Fatal("initial NTP sync waited for its hour-long period")
			}
		})
	}
}
