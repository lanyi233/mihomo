//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"hash/fnv"
	"io"
	"os"
	"strconv"
	"strings"

	core "github.com/metacubex/mihomo/common/ebpf"
	E "github.com/metacubex/sing/common/exceptions"
)

// An interface's route_localnet is a single value that every sing-ebpf
// runtime in the network namespace depending on it shares.
// Every runtime that depends on such a value holds a lease on it for as long as
// it does. The lease carries the value to restore once nobody depends on the
// setting any more: the original the holder found when it changed the setting,
// a value inherited from the lease of the runtime that did, or
// tcSysctlLeaseNoRestore. A runtime that leaves while another lease exists
// leaves the setting in place, and the last one to leave restores it.
//
// A value to restore can only be inherited when a runtime claims the setting.
// If the setting is changed again while several runtimes run and the one that
// changed it leaves first, the value to restore is lost and the setting stays
// as the runtimes left it: never pulled from under a running runtime.
//
// Leases are enumerated through /proc/net/unix. If that listing cannot be read,
// a runtime inherits nothing and restores nothing: a setting left changed is
// the failure that cannot break a running runtime.

// tcSysctlLeaseNoRestore is the value of a lease whose holder depends on a
// setting it found in place, so that leaving restores nothing.
const tcSysctlLeaseNoRestore = "-"

func tcSysctlLeaseKey(path string) string {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(path))
	return "sysctl-" + strconv.FormatUint(hash.Sum64(), 16)
}

// lockTCSysctlLease serializes the read-modify-write of a shared setting with
// the lease bookkeeping of every other runtime.
func lockTCSysctlLease(key string) (io.Closer, error) {
	return core.AcquireInstanceMutex("lease/"+key, core.DefaultInstanceMutexTimeout)
}

// otherTCSysctlLeases lists the values of the other runtimes' leases on key.
// It reports false if they cannot be listed.
func otherTCSysctlLeases(key string, own *core.InstanceLease) ([]string, bool) {
	values, err := core.InstanceLeaseValues(key, own)
	return values, err == nil
}

// lastTCSysctlLease reports whether own is known to be the only lease on key.
func lastTCSysctlLease(key string, own *core.InstanceLease) bool {
	values, listed := otherTCSysctlLeases(key, own)
	return listed && len(values) == 0
}

// inheritedTCSysctlRestore is the value to restore that another runtime's lease
// carries, if any.
func inheritedTCSysctlRestore(key string) string {
	values, _ := otherTCSysctlLeases(key, nil)
	for _, value := range values {
		if value != tcSysctlLeaseNoRestore {
			return value
		}
	}
	return tcSysctlLeaseNoRestore
}

// renewTCSysctlLease makes *lease carry restore.
func renewTCSysctlLease(key string, lease **core.InstanceLease, restore string) error {
	if *lease != nil && (*lease).Value() == restore {
		return nil
	}
	next, err := core.AcquireInstanceLease(key, restore)
	if err != nil {
		return err
	}
	if err = closeOwned(lease); err != nil {
		return E.Errors(err, next.Close())
	}
	*lease = next
	return nil
}

// readTCSysctl reads a setting the way the kernel prints it.
func readTCSysctl(path string) (string, error) {
	value, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(value)), nil
}

// claimSharedRewriteLocalnet enables route_localnet on the interface and holds
// a lease on it.
func claimSharedRewriteLocalnet(interfaceName string, lease **core.InstanceLease) error {
	path := sharedRewriteLocalnetPath(interfaceName)
	key := tcSysctlLeaseKey(path)
	if *lease != nil {
		// The lease keeps every other runtime from restoring the setting, so a
		// repair round only has work when something else disabled it.
		if value, err := readTCSysctl(path); err == nil && value == "1" {
			return nil
		}
	}
	mutex, err := lockTCSysctlLease(key)
	if err != nil {
		return err
	}
	defer mutex.Close()
	changed, err := ensureSharedRewriteLocalnet(interfaceName)
	if err != nil {
		return err
	}
	var restore string
	switch {
	case changed:
		restore = "0"
	case *lease != nil:
		restore = (*lease).Value()
	default:
		restore = inheritedTCSysctlRestore(key)
	}
	if err = renewTCSysctlLease(key, lease, restore); err != nil {
		if changed && *lease == nil {
			return E.Errors(err, restoreSharedRewriteLocalnet(interfaceName))
		}
		return err
	}
	return nil
}

// releaseSharedRewriteLocalnet gives up a route_localnet lease. The last
// holder disables the setting again if a holder had enabled it.
func releaseSharedRewriteLocalnet(interfaceName string, lease **core.InstanceLease) error {
	if *lease == nil {
		return nil
	}
	key := tcSysctlLeaseKey(sharedRewriteLocalnetPath(interfaceName))
	mutex, err := lockTCSysctlLease(key)
	if err != nil {
		return err
	}
	defer mutex.Close()
	if (*lease).Value() != tcSysctlLeaseNoRestore && lastTCSysctlLease(key, *lease) {
		if err = restoreSharedRewriteLocalnet(interfaceName); err != nil {
			return err
		}
	}
	return closeOwned(lease)
}

func claimSharedArpAnnounce(name string, lease **core.InstanceLease) error {
	path := tcInterfaceSysctlPath(name, "arp_announce")
	key := tcSysctlLeaseKey(path)
	mutex, err := lockTCSysctlLease(key)
	if err != nil {
		return err
	}
	defer mutex.Close()
	restore, err := raiseSharedArpAnnounce(name)
	if err != nil {
		return err
	}
	if restore == "" {
		if *lease != nil {
			restore = (*lease).Value()
		} else {
			restore = inheritedTCSysctlRestore(key)
		}
	}
	if err = renewTCSysctlLease(key, lease, restore); err != nil {
		if *lease == nil && restore != tcSysctlLeaseNoRestore {
			return E.Errors(err, restoreSharedArpAnnounce(name, restore))
		}
		return err
	}
	return nil
}
func releaseSharedArpAnnounce(name string, lease **core.InstanceLease) error {
	if *lease == nil {
		return nil
	}
	key := tcSysctlLeaseKey(tcInterfaceSysctlPath(name, "arp_announce"))
	mutex, err := lockTCSysctlLease(key)
	if err != nil {
		return err
	}
	defer mutex.Close()
	if (*lease).Value() != tcSysctlLeaseNoRestore && lastTCSysctlLease(key, *lease) {
		if err = restoreSharedArpAnnounce(name, (*lease).Value()); err != nil {
			return err
		}
	}
	return closeOwned(lease)
}
