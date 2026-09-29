package sing_tun

import (
	"os"
	"sync/atomic"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
)

// closeGuard lets the stack's read loop outlive a close of the macOS utun it
// reads from.
//
// sing-tun's NativeTun reads and batch-writes through the raw descriptor
// number, and its Close signals the stop pipe and closes that number without
// waiting for the loop. The stop pipe only wakes a loop parked in poll; one
// that is busy with a batch -- which is where it is whenever there is traffic
// -- comes back to recvmsg_x on a number that is already closed and is soon
// reused. That errno is EBADF or ENOTSOCK, neither of which the stacks'
// batchLoopDarwin counts as closed, so the loop never exits: it logs
// "batch read packet" as fast as the syscall fails (hundreds of thousands of
// lines a second, pinning the CPU and flushing the log), and once the number
// is reused by the next utun it silently reads that device's packets into a
// stack that has already been torn down.
//
// Every call after Close fails with os.ErrClosed without touching the
// descriptor, so the loop's next call ends it. What this cannot cover is a
// call that passed the check just before Close and reaches the syscall after
// it; that window is the buffer setup inside one BatchRead rather than a whole
// batch plus forever, and the call after it exits.
type closeGuard struct {
	closed atomic.Bool
}

func (g *closeGuard) batchRead(device tun.DarwinTUN) ([]*buf.Buffer, error) {
	if g.closed.Load() {
		return nil, os.ErrClosed
	}
	buffers, err := device.BatchRead()
	if err != nil && g.closed.Load() {
		return nil, os.ErrClosed
	}
	return buffers, err
}

// batchWrite is guarded too: after Close the number may already belong to a
// regular file, and writev would put packet bytes into it.
func (g *closeGuard) batchWrite(device tun.DarwinTUN, buffers []*buf.Buffer) error {
	if g.closed.Load() {
		return os.ErrClosed
	}
	return device.BatchWrite(buffers)
}

func (g *closeGuard) close(device tun.Tun) error {
	g.closed.Store(true)
	return device.Close()
}
