//go:build with_ebpf && (linux || android)

package ebpf

import (
	"time"

	E "github.com/metacubex/sing/common/exceptions"
)

// The UDP session timeout is compiled into each backend's control record, so
// the kernel can expire a flow without userspace. It comes from the listener's
// udp-timeout, which a config reload can change while everything else about the
// listener stays the same -- and rebuilding the backend to carry one new number
// would take every established redirect with it. The kernel compares the
// timeout against each flow's last-seen stamp rather than baking a deadline
// into it, so a value written here applies to the flows that already exist.

// SetUDPTimeout replaces the UDP session timeout the cgroup programs enforce.
// It is a no-op on a backend built without UDP, which has no timeout to carry.
func (b *CgroupBackend) SetUDPTimeout(timeout time.Duration) error {
	if b == nil {
		return errBackendClosed
	}
	seconds, err := cgroupUDPTimeoutSeconds(timeout)
	if err != nil {
		return err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err = b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	if !b.runtime.enable_udp || seconds == b.udpTimeoutSeconds {
		return nil
	}
	previous := b.udpTimeoutSeconds
	b.udpTimeoutSeconds = seconds
	// listenerPort is only set once the programs are loaded and the control
	// record exists; before that, LoadPrograms writes the new value itself.
	if b.listenerPort == 0 {
		return nil
	}
	if err = b.updateCgroupControl(b.listenerPort); err != nil {
		b.udpTimeoutSeconds = previous
		return E.Cause(err, "update eBPF cgroup UDP timeout control")
	}
	return nil
}

// UDPTimeoutSeconds reports the timeout currently compiled into the cgroup
// control record.
func (b *CgroupBackend) UDPTimeoutSeconds() uint32 {
	if b == nil {
		return 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.udpTimeoutSeconds
}

// SetUDPTimeout replaces the UDP session timeout the shared packet-rewrite
// programs enforce.
func (b *SharedNetworkBackend) SetUDPTimeout(timeout time.Duration) error {
	if b == nil {
		return errBackendClosed
	}
	seconds, err := sharedNetworkUDPTimeoutSeconds(timeout)
	if err != nil {
		return err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err = b.requireUsableLocked(); err != nil {
		return err
	}
	if seconds == b.control.UDPTimeoutSeconds {
		return nil
	}
	previous := b.control.UDPTimeoutSeconds
	b.control.UDPTimeoutSeconds = seconds
	if err = b.updateControl(); err != nil {
		b.control.UDPTimeoutSeconds = previous
		return E.Cause(err, "update shared packet-rewrite UDP timeout control")
	}
	return nil
}

// UDPTimeoutSeconds reports the timeout currently compiled into the shared
// packet-rewrite control record.
func (b *SharedNetworkBackend) UDPTimeoutSeconds() uint32 {
	if b == nil {
		return 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.control.UDPTimeoutSeconds
}
