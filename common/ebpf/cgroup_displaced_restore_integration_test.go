//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// Where another owner holds a cgroup hook exclusively, as netd does on the
// cgroup v2 root from Android 15, attaching can only replace its program.
// Detaching must then hand the hook back to that program rather than leave it
// empty.
func TestCgroupDetachRestoresADisplacedOwnerIntegration(t *testing.T) {
	requireEBPFIntegration(t, "take over and hand back an exclusively held cgroup hook")
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, dedicated := createIntegrationCgroup(t, root, 930)
	if !dedicated {
		t.Skip("no dedicated cgroup to attach to")
	}
	cgroupDir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cgroupDir.Close()
	cgroupFD := int(cgroupDir.Fd())

	owner, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         "owner_conn4",
		Type:         CiliumEBPF.CGroupSockAddr,
		AttachType:   CiliumEBPF.AttachCGroupInet4Connect,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
	})
	if err != nil {
		t.Fatalf("load the other owner's program: %v", err)
	}
	defer owner.Close()
	if err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  cgroupFD,
		Program: owner,
		Attach:  CiliumEBPF.AttachCGroupInet4Connect,
	}); err != nil {
		t.Fatalf("attach the other owner's program exclusively: %v", err)
	}
	t.Cleanup(func() { _ = rawDetachProgram(cgroupFD, owner, CiliumEBPF.AttachCGroupInet4Connect) })
	ownerID := cgroupProgramID(t, owner)

	selfBypassMap, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := CompilePolicy(PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareCgroup(CgroupConfig{
		Path:          path,
		EnableTCP:     true,
		RedirectIPv4:  netip.MustParsePrefix("127.128.0.0/9"),
		MapCapacity:   CgroupMapCapacity{TCPRedirect: 64, UDPRedirect: 64, UDPPeer: 64, UDPFlow: 64, SocketBypass: 8},
		UDPTimeout:    time.Minute,
		Policy:        policy,
		SelfBypassMap: selfBypassMap,
	})
	_ = selfBypassMap.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.LoadPrograms(41100); err != nil {
		t.Fatal(err)
	}
	if err = backend.Attach(); err != nil {
		t.Fatalf("attach over an exclusively held hook: %v", err)
	}
	oursID := cgroupProgramID(t, backend.runtime.programs[cgroupProgramConnect4])
	if ids := queryConnect4IDs(t, cgroupFD); !slices.Equal(ids, []CiliumEBPF.ProgramID{oursID}) {
		t.Fatalf("connect4 holds %v after attach, want only ours %v", ids, oursID)
	}
	if hooks := backend.DisplacedHooks(); len(hooks) != 1 || !strings.Contains(hooks[0], "owner_conn4") {
		t.Fatalf("displaced hooks %q, want the other owner's connect4 program", hooks)
	}

	if err = backend.Close(); err != nil {
		t.Fatal(err)
	}
	if ids := queryConnect4IDs(t, cgroupFD); !slices.Equal(ids, []CiliumEBPF.ProgramID{ownerID}) {
		t.Fatalf("connect4 holds %v after close, want the other owner's %v back", ids, ownerID)
	}
}

func cgroupProgramID(t *testing.T, program *CiliumEBPF.Program) CiliumEBPF.ProgramID {
	t.Helper()
	info, err := program.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("kernel did not report a program ID")
	}
	return id
}

func queryConnect4IDs(t *testing.T, cgroupFD int) []CiliumEBPF.ProgramID {
	t.Helper()
	ids, err := queryCgroupProgramIDs(cgroupFD, CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatalf("query connect4: %v", err)
	}
	return ids
}
