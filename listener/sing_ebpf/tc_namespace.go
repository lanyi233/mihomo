//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"fmt"
	"os"
	goruntime "runtime"
	"sync"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/sagernet/netlink"
	"github.com/vishvananda/netns"
)

// TCNamespace isolates transparent listeners and replies from host NAT and port
// ownership. It is unnamed: no mount point, helper process or /run/netns entry.
// Close it only after its runtime and all consumer sockets have been closed.
type TCNamespace struct {
	access sync.RWMutex
	handle netns.NsHandle
	open   bool
}

func NewTCNamespace() (*TCNamespace, error) {
	var handle netns.NsHandle = -1
	err := runTCNamespaceThread(-1, func() error {
		var err error
		handle, err = netns.New()
		if err != nil {
			return err
		}
		loopback, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		return netlink.LinkSetUp(loopback)
	})
	if err != nil {
		if handle.IsOpen() {
			_ = handle.Close()
		}
		return nil, E.Cause(err, "create TC socket-assignment network namespace")
	}
	return &TCNamespace{handle: handle, open: true}, nil
}

// Path is suitable for a socket factory such as sing-box's namespace listener.
// The owner must remain alive until the socket factory has returned.
func (n *TCNamespace) Path() string {
	if n == nil {
		return ""
	}
	n.access.RLock()
	defer n.access.RUnlock()
	if !n.open {
		return ""
	}
	return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), n.handle)
}

func (n *TCNamespace) with(block func() error) error {
	if n == nil {
		return E.New("TC network namespace is required")
	}
	n.access.RLock()
	defer n.access.RUnlock()
	if !n.open {
		return os.ErrClosed
	}
	return runTCNamespaceThread(n.handle, block)
}

// A failed restore never releases a foreign-netns OS thread to Go's scheduler.
// The callback must be synchronous and must not spawn work expecting this netns.
func runTCNamespaceThread(target netns.NsHandle, block func() error) error {
	type result struct {
		err        error
		panicValue any
	}
	done := make(chan result, 1)
	go func() {
		goruntime.LockOSThread()
		original, err := netns.Get()
		if err != nil {
			goruntime.UnlockOSThread()
			done <- result{err: err}
			return
		}
		var callErr error
		returned := false
		defer func() {
			panicValue := recover()
			if !returned && panicValue == nil {
				callErr = E.New("TC namespace callback exited without returning")
			}
			restoreErr := netns.Set(original)
			closeErr := original.Close()
			if restoreErr == nil {
				goruntime.UnlockOSThread()
			}
			done <- result{err: E.Errors(callErr, restoreErr, closeErr), panicValue: panicValue}
		}()
		if target.IsOpen() {
			if callErr = netns.Set(target); callErr != nil {
				returned = true
				return
			}
		}
		callErr = block()
		returned = true
	}()
	res := <-done
	if res.panicValue != nil {
		panic(res.panicValue)
	}
	return res.err
}

func (n *TCNamespace) Close() error {
	if n == nil {
		return nil
	}
	n.access.Lock()
	defer n.access.Unlock()
	if !n.open {
		return nil
	}
	n.open = false
	return n.handle.Close()
}
