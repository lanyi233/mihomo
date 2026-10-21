//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"errors"
	"os"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// No self-bypass or cgroup interception release hook is present: application
// socket metadata must be reclaimed by the process tracker itself.
func TestProcessTrackerPolicySocketReleaseIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test process tracker metadata cleanup")
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Fatal(err)
	}
	path, dedicated := createIntegrationCgroup(t, root, 170)
	if !dedicated {
		t.Skip("cannot create a dedicated cgroup")
	}
	moveCurrentProcessToCgroup(t, path, root)
	for _, policy := range []bool{false, true} {
		name := "owner_only"
		if policy {
			name = "uid_policy"
		}
		t.Run(name, func(t *testing.T) {
			owners, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.LRUHash, KeySize: 8, ValueSize: 8, MaxEntries: 8})
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.LRUHash, KeySize: 8, ValueSize: 4, MaxEntries: 8})
			if err != nil {
				_ = owners.Close()
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = metadata.Close() })
			tracker := &ProcessTracker{owners: owners}
			t.Cleanup(func() { _ = tracker.Close() })
			if policy {
				tracker.policyUID, err = CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{Type: CiliumEBPF.LPMTrie, KeySize: 8, ValueSize: 1, MaxEntries: 1, Flags: bpfFlagNoPrealloc})
				if err != nil {
					t.Fatal(err)
				}
				uid := uint32(os.Getuid())
				if err = populateUIDPolicyMap(tracker.policyUID, compileUIDRanges([]UIDRange{{Start: uid, End: uid}})); err != nil {
					t.Fatal(err)
				}
				tracker.metadata = metadata
			}
			tracker.attachReleaseCleanup(path)
			if !tracker.ReleaseCleanup() {
				t.Fatal("process tracker socket-release hook did not attach")
			}
			for _, hook := range processTrackerHooks(ProcessTrackerConfig{EnableTCP: true, EnableUDP: true, EnableIPv6: true}) {
				program, err := newProcessTrackerProgram(hook, owners.FD(), tracker.policyUIDFD(), tracker.metadataFD(), false)
				if err != nil {
					t.Fatal(err)
				}
				tracker.programs = append(tracker.programs, program)
				link, err := attachCgroupProgramShared(path, program, hook.attachType)
				if err != nil {
					t.Fatal(err)
				}
				tracker.links = append(tracker.links, link)
			}
			for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
				for _, kind := range []int{unix.SOCK_STREAM, unix.SOCK_DGRAM} {
					// Churn beyond capacity; cleanup must not depend on eviction.
					for iteration := 0; iteration < 24; iteration++ {
						assertProcessTrackerSocketReleased(t, tracker, metadata, family, kind, iteration%2 == 0)
					}
				}
			}
		})
	}
}

func assertProcessTrackerSocketReleased(t *testing.T, tracker *ProcessTracker, metadata *CiliumEBPF.Map, family, kind int, removeOwner bool) {
	t.Helper()
	fd, err := unix.Socket(family, kind|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil {
		t.Fatal(err)
	}
	var destination unix.Sockaddr = &unix.SockaddrInet4{Port: 1, Addr: [4]byte{127, 0, 0, 1}}
	if family == unix.AF_INET6 {
		destination = &unix.SockaddrInet6{Port: 1, Addr: [16]byte{15: 1}}
	}
	if kind == unix.SOCK_STREAM {
		err = unix.Connect(fd, destination)
	} else {
		err = unix.Sendto(fd, []byte{1}, 0, destination)
	}
	if err != nil && !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatal(err)
	}
	var owner ProcessSocketOwner
	if err = tracker.owners.Lookup(&cookie, &owner); err != nil {
		t.Fatalf("socket was not tracked (family=%d kind=%d): %v", family, kind, err)
	}
	if tracker.metadata != nil {
		var value uint32
		if err = metadata.Lookup(&cookie, &value); err != nil || value != SocketMetadataPolicyBypass {
			t.Fatalf("policy metadata = %d, want bypass: %v", value, err)
		}
	}
	if removeOwner {
		// Owner LRU eviction must not prevent metadata cleanup.
		if err = tracker.owners.Delete(&cookie); err != nil {
			t.Fatal(err)
		}
	}
	if err = unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	fd = -1
	deadline := time.Now().Add(time.Second)
	for {
		var value uint32
		ownerErr := tracker.owners.Lookup(&cookie, &owner)
		metadataErr := metadata.Lookup(&cookie, &value)
		if errors.Is(ownerErr, CiliumEBPF.ErrKeyNotExist) && errors.Is(metadataErr, CiliumEBPF.ErrKeyNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("closed socket retained (family=%d kind=%d): owner=%v metadata=%v value=%d", family, kind, ownerErr, metadataErr, value)
		}
		time.Sleep(time.Millisecond)
	}
}
