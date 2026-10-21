//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestSelfBypassPreparationLifecycle(t *testing.T) {
	bypass, err := NewSelfBypassWithCapacity(64)
	if err != nil {
		t.Fatal(err)
	}
	if bypass.Map() != nil || bypass.IsClosed() {
		t.Fatal("construction must leave an open owner without a kernel map")
	}
	if err = bypass.Close(); err != nil || !bypass.IsClosed() {
		t.Fatalf("close unprepared owner: %v", err)
	}
	if err = bypass.Prepare(); !errors.Is(err, errSelfBypassClosed) {
		t.Fatalf("prepare after close = %v", err)
	}
	if err = bypass.AttachCgroup(SelfBypassCgroupConfig{EnableUDP: true}); !errors.Is(err, errSelfBypassClosed) {
		t.Fatalf("attach after close = %v", err)
	}
	// A callback already copied by the dialer may run after unregistration.
	if err = bypass.RegisterSocket(nil); err != nil || bypass.Map() != nil {
		t.Fatalf("late socket callback recreated a closed map: %v", err)
	}
}

func TestSelfBypassPreparationStopsWhileCloseNeedsRetry(t *testing.T) {
	hook := &trackerTestLink{err: errors.New("detach failed")}
	bypass := &SelfBypass{capacity: 64, links: []cgroupProgramLink{hook}}
	if err := bypass.Close(); !errors.Is(err, hook.err) || bypass.IsClosed() {
		t.Fatalf("pending detach was lost: %v", err)
	}
	if err := bypass.Prepare(); !errors.Is(err, errSelfBypassClosed) {
		t.Fatalf("preparation was allowed during close: %v", err)
	}
	hook.err = nil
	if err := bypass.Close(); err != nil || !bypass.IsClosed() {
		t.Fatalf("close retry did not finish: %v", err)
	}
}

func TestNewSelfBypassRejectsInvalidCapacity(t *testing.T) {
	for _, capacity := range []uint32{0, MaxConfigurableMapCapacity + 1} {
		if _, err := NewSelfBypassWithCapacity(capacity); err == nil {
			t.Fatalf("capacity %d was accepted", capacity)
		}
	}
}

func TestProcessCgroupExclusive(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "cgroup.procs")
	pid := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(path, []byte(pid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exclusive, err := processCgroupExclusive(directory)
	if err != nil || !exclusive {
		t.Fatalf("single-process cgroup was not exclusive: exclusive=%v err=%v", exclusive, err)
	}
	if err = os.WriteFile(path, []byte(pid+"\n"+strconv.Itoa(os.Getpid()+1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exclusive, err = processCgroupExclusive(directory)
	if err != nil || exclusive {
		t.Fatalf("shared cgroup was treated as exclusive: exclusive=%v err=%v", exclusive, err)
	}
}

func TestProcessCgroupExclusiveRejectsPopulatedDescendant(t *testing.T) {
	directory := t.TempDir()
	pid := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(filepath.Join(directory, "cgroup.procs"), []byte(pid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(directory, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid()+1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exclusive, err := processCgroupExclusive(directory)
	if err != nil || exclusive {
		t.Fatalf("populated descendant was treated as exclusive: exclusive=%v err=%v", exclusive, err)
	}
}

func TestSelfBypassInstructionsUseSocketCookie(t *testing.T) {
	for name, instructions := range map[string]asm.Instructions{
		"create":      selfBypassCreateInstructions(1, 42),
		"release":     selfBypassReleaseInstructions(1),
		"socket_addr": selfBypassSocketAddrInstructions(1, 42),
	} {
		found := false
		for _, instruction := range instructions {
			if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnGetSocketCookie {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s self-bypass instructions do not read the socket cookie", name)
		}
	}
}

func TestSelfBypassOwnerTGID(t *testing.T) {
	namespace, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		t.Skipf("PID namespace is not readable: %v", err)
	}
	owner, err := selfBypassOwnerTGID()
	if namespace != initialPIDNamespaceLink {
		if err == nil {
			t.Fatalf("owner %d accepted outside the initial PID namespace (%s)", owner, namespace)
		}
		return
	}
	if err != nil || owner != uint32(os.Getpid()) {
		t.Fatalf("owner = %d, %v; want %d", owner, err, os.Getpid())
	}
}

func TestSelfBypassSocketAddrHooks(t *testing.T) {
	hooks := selfBypassSocketAddrHooks(SelfBypassCgroupConfig{
		EnableTCP:  true,
		EnableUDP:  true,
		EnableIPv6: true,
	})
	if len(hooks) != 4 {
		t.Fatalf("unexpected dual-stack self-bypass hook count: %d", len(hooks))
	}
	if hooks[0].attachType != CiliumEBPF.AttachCGroupInet4Connect ||
		hooks[1].attachType != CiliumEBPF.AttachCGroupInet6Connect ||
		hooks[2].attachType != CiliumEBPF.AttachCGroupUDP4Sendmsg ||
		hooks[3].attachType != CiliumEBPF.AttachCGroupUDP6Sendmsg {
		t.Fatalf("unexpected self-bypass hooks: %+v", hooks)
	}
	ipv4Only := selfBypassSocketAddrHooks(SelfBypassCgroupConfig{EnableTCP: true})
	if len(ipv4Only) != 1 || ipv4Only[0].attachType != CiliumEBPF.AttachCGroupInet4Connect {
		t.Fatalf("unexpected IPv4-only self-bypass hooks: %+v", ipv4Only)
	}
}

func TestSelfBypassModes(t *testing.T) {
	tests := []struct {
		mode         SelfBypassMode
		name         string
		cleanup      string
		cgroupAttach bool
	}{
		{SelfBypassUserspace, "userspace_socket_cookie", "lru_fallback", false},
		{SelfBypassCgroupSocket, "cgroup_socket_cookie", "socket_release", true},
		{SelfBypassCgroupSocketAddr, "cgroup_socket_addr", "lru_fallback", true},
		{SelfBypassCgroupSocketAddrRelease, "cgroup_socket_addr_release", "socket_release", true},
		{SelfBypassUserspaceRelease, "userspace_socket_cookie_release", "socket_release", false},
	}
	for _, test := range tests {
		if test.mode.String() != test.name {
			t.Fatalf("mode %d string = %q, want %q", test.mode, test.mode.String(), test.name)
		}
		if test.mode.CleanupMode() != test.cleanup {
			t.Fatalf("mode %s cleanup = %q, want %q", test.name, test.mode.CleanupMode(), test.cleanup)
		}
		bypass := &SelfBypass{}
		bypass.mode.Store(uint32(test.mode))
		if bypass.CgroupAttached() != test.cgroupAttach {
			t.Fatalf("mode %s cgroup attached = %v, want %v", test.name, bypass.CgroupAttached(), test.cgroupAttach)
		}
	}
}
