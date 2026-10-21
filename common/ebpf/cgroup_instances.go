//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bufio"
	"errors"
	"fmt"
	E "github.com/metacubex/sing/common/exceptions"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

var cgroupSharedLockTimeout = 2 * time.Second

// lockSharedCgroupFile marks the cgroup as managed by an interception backend and
// reports whether this backend is the only one alive on it.
//
// Every backend of this build keeps a shared lock on the cgroup directory for
// its lifetime, so several backends can run on one cgroup. Builds without
// multi-instance support keep an exclusive lock instead, which keeps them and
// this build off the same cgroup. A backend starts by taking the lock
// exclusively: getting it proves that no other backend is alive on the cgroup,
// so every interception program found there is stale and may be reclaimed.
// shareCgroupLock then downgrades it before anything is attached.
//
// A lock that stays held exclusively is reported as EBUSY, so callers matching
// on it keep working, but it is described for what is known rather than what is
// likely: the holder may be a running instance of such a build or a handle one
// kept after a close that did not finish.
func lockSharedCgroupFile(cgroupFile *os.File) (bool, error) {
	err := unix.Flock(int(cgroupFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, unix.EWOULDBLOCK) {
		return false, eBPFOperationError("lock cgroup", err)
	}
	return false, shareCgroupLock(cgroupFile)
}

// shareCgroupLock takes or downgrades to the shared lock. An exclusive holder of
// this build only keeps it while it reclaims stale programs.
func shareCgroupLock(cgroupFile *os.File) error {
	deadline := time.Now().Add(cgroupSharedLockTimeout)
	for {
		err := unix.Flock(int(cgroupFile.Fd()), unix.LOCK_SH|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return eBPFOperationError("lock cgroup", err)
		}
		if !time.Now().Before(deadline) {
			return E.Cause(unix.EBUSY,
				"the exclusive lock on this cgroup is already held, "+
					"either by an active instance of a sing-ebpf build without multi-instance support "+
					"or by an earlier close of one that did not finish: ",
				"lock cgroup")
		}
		time.Sleep(instanceMutexRetry)
	}
}

// acquireCgroupSlot takes one of the cgroup's instance slots. The slot keys
// the kernel names of this backend's programs, which is what lets a backend
// that shares the cgroup with others reclaim the stale programs of its own
// slot and only those. Slot names live in the caller's network namespace, as
// do the redirect routes a backend depends on, so backends sharing a cgroup are
// expected to share one.
func acquireCgroupSlot(cgroupFile *os.File) (*InstanceSlot, error) {
	var status unix.Stat_t
	if err := unix.Fstat(int(cgroupFile.Fd()), &status); err != nil {
		return nil, eBPFOperationError("inspect cgroup", err)
	}
	base := "@sing-ebpf-cgroup-" + strconv.FormatUint(uint64(status.Dev), 16) + "-" + strconv.FormatUint(status.Ino, 16)
	slot, err := AcquireInstanceSlot(func(slot int) string { return InstanceSlotName(base, slot) })
	if errors.Is(err, ErrInstanceSlotsExhausted) {
		return nil, E.New("cgroup is already managed by ", MaxInstanceSlots, " sing-ebpf interception backends")
	}
	if err != nil {
		return nil, E.Cause(err, "lock cgroup slot")
	}
	return slot, nil
}

func cgroupKernelProgramName(base string, slot int) string {
	if slot == 0 {
		return base
	}
	return base + "_" + strconv.FormatUint(uint64(slot), 16)
}

// cgroupProgramSlot returns the slot an interception program name belongs to,
// or -1 for any other name. The sing_ebpf_ programs of older releases come
// from single-instance builds, whose leftovers are slot 0's.
func cgroupProgramSlot(name string) int {
	if strings.HasPrefix(name, "sing_ebpf_") {
		return 0
	}
	for _, definition := range cgroupProgramDefinitions {
		if name == definition.name {
			return 0
		}
		suffix, found := strings.CutPrefix(name, definition.name+"_")
		if !found || len(suffix) != 1 {
			continue
		}
		slot, err := strconv.ParseUint(suffix, 16, 8)
		if err == nil && slot > 0 && slot < MaxInstanceSlots {
			return int(slot)
		}
	}
	return -1
}

var procLocksPath = "/proc/locks"

// cgroupSharedAcrossNetworkNamespaces reports whether a process in another
// network namespace holds a lock on the cgroup. Slot names are abstract socket
// names, which that namespace does not see, so a backend there may hold the
// same slot number as this one and reclaiming "this slot's" programs could
// detach its live ones. Incomplete ownership information is treated as foreign
// so stale cleanup cannot detach a potentially live peer.
func cgroupSharedAcrossNetworkNamespaces(cgroupFile *os.File) bool {
	var status unix.Stat_t
	if err := unix.Fstat(int(cgroupFile.Fd()), &status); err != nil {
		return true
	}
	own, err := os.Readlink("/proc/thread-self/ns/net")
	if err != nil {
		if own, err = os.Readlink("/proc/self/ns/net"); err != nil {
			return true
		}
	}
	locks, err := os.Open(procLocksPath)
	if err != nil {
		return true
	}
	defer locks.Close()
	file := fmt.Sprintf("%02x:%02x:%d", unix.Major(uint64(status.Dev)), unix.Minor(uint64(status.Dev)), status.Ino)
	return foreignNetworkNamespaceLockHolder(locks, file, os.Getpid(), own, func(pid int) (string, error) {
		return os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/net")
	})
}

// foreignNetworkNamespaceLockHolder scans a /proc/locks listing for a flock
// on file held by a process whose network namespace differs from own. A
// holder whose namespace cannot be read counts as foreign unless it has
// exited.
func foreignNetworkNamespaceLockHolder(
	locks io.Reader,
	file string,
	ownPID int,
	own string,
	networkNamespace func(pid int) (string, error),
) bool {
	scanner := bufio.NewScanner(locks)
	for scanner.Scan() {
		// "1: FLOCK  ADVISORY  READ 1234 00:1d:5678 0 EOF", with "->" after
		// the number for a waiter.
		fields := strings.Fields(scanner.Text())
		index := slices.Index(fields, "FLOCK")
		if index < 0 || len(fields) < index+5 || fields[index+4] != file {
			continue
		}
		pid, err := strconv.Atoi(fields[index+3])
		if err != nil || pid <= 0 || pid == ownPID {
			continue
		}
		namespace, err := networkNamespace(pid)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || namespace != own {
			return true
		}
	}
	return scanner.Err() != nil
}

func (b *CgroupBackend) InstanceSlot() int {
	if b == nil {
		return 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return 0
	}
	return b.runtime.instanceSlot.Index()
}
