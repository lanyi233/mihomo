//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"

	E "github.com/metacubex/sing/common/exceptions"
)

// The FakeIP ranges are compiled into every backend's control record so a fake
// destination is intercepted before any bypass policy can let it through. The
// compiled policy is an immutable snapshot taken when the inbound starts, but
// the ranges come from the DNS section, which a config reload can change while
// the listener itself stays untouched. Without a runtime path the control
// record would keep whatever range the process started with, and a fake-ip
// range that sits inside a bypassed range (100.64.0.0/10, say) would have
// every fake address bypassed instead of proxied.

const (
	// tcFlagFakeIPIPv4 and tcFlagFakeIPIPv6 mirror the literal bits
	// policyVector.tcFlags encodes for the TC control record.
	tcFlagFakeIPIPv4 = 1 << 10
	tcFlagFakeIPIPv6 = 1 << 11
)

func normalizeFakeIPRanges(ipv4 netip.Prefix, ipv6 netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	normalizedIPv4, err := normalizeAddressPrefix("IPv4 FakeIP range", ipv4, true)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, err
	}
	normalizedIPv6, err := normalizeAddressPrefix("IPv6 FakeIP range", ipv6, false)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, err
	}
	return normalizedIPv4, normalizedIPv6, nil
}

// SetFakeIPRanges replaces the fake-ip ranges the cgroup programs force
// interception for, and reports whether anything changed. The cgroup control
// record is rebuilt from the backend's own state, so a change made before
// LoadPrograms is simply picked up when the record is first written.
func (b *CgroupBackend) SetFakeIPRanges(ipv4 netip.Prefix, ipv6 netip.Prefix) (bool, error) {
	if b == nil {
		return false, errBackendClosed
	}
	normalizedIPv4, normalizedIPv6, err := normalizeFakeIPRanges(ipv4, ipv6)
	if err != nil {
		return false, err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err = b.health.requireUsable(b.runtime != nil); err != nil {
		return false, err
	}
	if normalizedIPv4 == b.fakeIPIPv4 && normalizedIPv6 == b.fakeIPIPv6 {
		return false, nil
	}
	previousIPv4, previousIPv6 := b.fakeIPIPv4, b.fakeIPIPv6
	b.fakeIPIPv4 = normalizedIPv4
	b.fakeIPIPv6 = normalizedIPv6
	// listenerPort is only set once the programs are loaded and the control
	// record exists; before that, LoadPrograms writes the new value itself.
	if b.listenerPort != 0 {
		if err = b.updateCgroupControl(b.listenerPort); err != nil {
			b.fakeIPIPv4 = previousIPv4
			b.fakeIPIPv6 = previousIPv6
			return false, E.Cause(err, "update eBPF cgroup fake-ip control")
		}
	}
	return true, nil
}

// FakeIPRanges reports the ranges currently compiled into the cgroup control
// record.
func (b *CgroupBackend) FakeIPRanges() (netip.Prefix, netip.Prefix) {
	if b == nil {
		return netip.Prefix{}, netip.Prefix{}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.fakeIPIPv4, b.fakeIPIPv6
}

// SetFakeIPRanges replaces the fake-ip ranges the TC programs force
// interception for, and reports whether anything changed.
func (b *TCBackend) SetFakeIPRanges(ipv4 netip.Prefix, ipv6 netip.Prefix) (bool, error) {
	if b == nil {
		return false, errBackendClosed
	}
	normalizedIPv4, normalizedIPv6, err := normalizeFakeIPRanges(ipv4, ipv6)
	if err != nil {
		return false, err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return false, errBackendClosed
	}
	previous := b.control
	b.control.Flags &^= tcFlagFakeIPIPv4 | tcFlagFakeIPIPv6
	b.control.FakeIPIPv4Prefix = [4]byte{}
	b.control.FakeIPIPv4Mask = [4]byte{}
	b.control.FakeIPIPv6Prefix = [16]byte{}
	b.control.FakeIPIPv6Mask = [16]byte{}
	if normalizedIPv4.IsValid() {
		b.control.Flags |= tcFlagFakeIPIPv4
		b.control.FakeIPIPv4Prefix = normalizedIPv4.Addr().As4()
		b.control.FakeIPIPv4Mask = prefixMask4(normalizedIPv4.Bits())
	}
	if normalizedIPv6.IsValid() {
		b.control.Flags |= tcFlagFakeIPIPv6
		b.control.FakeIPIPv6Prefix = normalizedIPv6.Addr().As16()
		b.control.FakeIPIPv6Mask = prefixMask16(normalizedIPv6.Bits())
	}
	if b.control == previous {
		return false, nil
	}
	if err = b.updateControlLocked(); err != nil {
		b.control = previous
		return false, err
	}
	return true, nil
}

// SetFakeIPRanges replaces the fake-ip ranges the shared packet-rewrite
// programs force interception for, and reports whether anything changed.
func (b *SharedNetworkBackend) SetFakeIPRanges(ipv4 netip.Prefix, ipv6 netip.Prefix) (bool, error) {
	if b == nil {
		return false, errBackendClosed
	}
	normalizedIPv4, normalizedIPv6, err := normalizeFakeIPRanges(ipv4, ipv6)
	if err != nil {
		return false, err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err = b.requireUsableLocked(); err != nil {
		return false, err
	}
	previous := b.control
	b.control.Flags &^= sharedNetworkFlagFakeIPIPv4 | sharedNetworkFlagFakeIPIPv6
	b.control.FakeIPIPv4Prefix = [4]byte{}
	b.control.FakeIPIPv4Mask = [4]byte{}
	b.control.FakeIPIPv6Prefix = [16]byte{}
	b.control.FakeIPIPv6Mask = [16]byte{}
	if normalizedIPv4.IsValid() {
		b.control.Flags |= sharedNetworkFlagFakeIPIPv4
		b.control.FakeIPIPv4Prefix = normalizedIPv4.Addr().As4()
		b.control.FakeIPIPv4Mask = prefixMask4(normalizedIPv4.Bits())
	}
	if normalizedIPv6.IsValid() {
		b.control.Flags |= sharedNetworkFlagFakeIPIPv6
		b.control.FakeIPIPv6Prefix = normalizedIPv6.Addr().As16()
		b.control.FakeIPIPv6Mask = prefixMask16(normalizedIPv6.Bits())
	}
	if b.control == previous {
		return false, nil
	}
	if err = b.updateControl(); err != nil {
		b.control = previous
		return false, err
	}
	return true, nil
}
