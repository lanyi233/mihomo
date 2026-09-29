package sing_tun

import (
	"context"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/logger"

	"github.com/stretchr/testify/require"
)

// fakeUtun reproduces what sing-tun's darwin NativeTun does to a read loop
// that is busy when the device closes: before Close there is traffic, so the
// loop is never parked where the stop pipe could reach it; after Close every
// recvmsg_x lands on a closed, soon reused, descriptor number and fails with an
// errno the loop does not count as closed.
type fakeUtun struct {
	closed          atomic.Bool
	readsAfterClose atomic.Int64
}

func (f *fakeUtun) Read([]byte) (int, error)    { return 0, os.ErrClosed }
func (f *fakeUtun) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeUtun) Close() error                { f.closed.Store(true); return nil }
func (f *fakeUtun) BatchSize() int              { return 1 }

func (f *fakeUtun) BatchRead() ([]*buf.Buffer, error) {
	if f.closed.Load() {
		f.readsAfterClose.Add(1)
		return nil, syscall.ENOTSOCK
	}
	time.Sleep(time.Millisecond)
	packet := buf.New()
	packet.Extend(20) // not a valid IP packet; the stack drops it
	return []*buf.Buffer{packet}, nil
}

func (f *fakeUtun) BatchWrite([]*buf.Buffer) error {
	if f.closed.Load() {
		return syscall.ENOTSOCK
	}
	return nil
}

// guardedFakeUtun is guardedNativeTun over the fake, counting what reaches the
// guard after Close so the test can tell a loop that exited from one that is
// still spinning on the guard.
type guardedFakeUtun struct {
	*fakeUtun
	guard           closeGuard
	callsAfterClose atomic.Int64
}

func (t *guardedFakeUtun) BatchRead() ([]*buf.Buffer, error) {
	if t.guard.closed.Load() {
		t.callsAfterClose.Add(1)
	}
	return t.guard.batchRead(t.fakeUtun)
}

func (t *guardedFakeUtun) BatchWrite(buffers []*buf.Buffer) error {
	return t.guard.batchWrite(t.fakeUtun, buffers)
}

func (t *guardedFakeUtun) Close() error { return t.guard.close(t.fakeUtun) }

// closeUnderTraffic runs sing-tun's own darwin batch loop (mipstack's, which is
// userspace and so runs on any OS) over device, closes the device while the
// loop is busy, and gives the loop time to show whether it stopped.
func closeUnderTraffic(t *testing.T, device tun.DarwinTUN) {
	t.Helper()
	stack, err := tun.NewMipstack(tun.StackOptions{
		Context: context.Background(),
		Tun:     device,
		TunOptions: tun.Options{
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			EXP_RecvMsgX: true,
		},
		Logger: logger.NOP(),
	})
	require.NoError(t, err)
	require.NoError(t, stack.Start())
	t.Cleanup(func() { _ = stack.Close() })

	time.Sleep(20 * time.Millisecond)
	require.NoError(t, device.Close())
	time.Sleep(200 * time.Millisecond)
}

func TestCloseGuardEndsTheDarwinReadLoop(t *testing.T) {
	device := &guardedFakeUtun{fakeUtun: &fakeUtun{}}
	closeUnderTraffic(t, device)

	// One read can still land: a call that passed the guard's check just
	// before Close reaches the device after it (see closeGuard). What the
	// guard rules out is the loop carrying on.
	require.LessOrEqual(t, device.readsAfterClose.Load(), int64(1),
		"reads kept reaching the closed descriptor")
	require.LessOrEqual(t, device.callsAfterClose.Load(), int64(1),
		"the loop kept reading after the guard reported the device closed")
}

// Without the guard the same close leaves the loop spinning. This is the bug
// the guard exists for, pinned so the test above is known to be able to fail;
// if sing-tun starts ending the loop itself, this fails and the guard can go.
func TestUnguardedDarwinReadLoopSpinsAfterClose(t *testing.T) {
	device := &fakeUtun{}
	closeUnderTraffic(t, device)

	reads := device.readsAfterClose.Load()
	t.Logf("%d reads of the closed descriptor in 200ms", reads)
	require.Greater(t, reads, int64(1000))
}

func TestCloseGuardPassesTrafficThroughBeforeClose(t *testing.T) {
	device := &guardedFakeUtun{fakeUtun: &fakeUtun{}}

	buffers, err := device.BatchRead()
	require.NoError(t, err)
	require.Len(t, buffers, 1)
	buf.ReleaseMulti(buffers)
	require.NoError(t, device.BatchWrite(nil))

	require.NoError(t, device.Close())
	_, err = device.BatchRead()
	require.ErrorIs(t, err, os.ErrClosed)
	require.ErrorIs(t, device.BatchWrite(nil), os.ErrClosed)
}
