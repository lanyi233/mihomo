//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"os"
	"slices"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// The socket-release probe attaches a program only to see whether the hook takes
// one, so it has to leave the hook as it found it. In particular it must not take
// the hook from a program another owner attached exclusively: that attachment
// refuses ALLOW_MULTI with EPERM, and replacing it instead would leave the hook
// empty once the probe detaches.
func TestSocketReleaseProbeLeavesTheHookAsFoundIntegration(t *testing.T) {
	requireEBPFIntegration(t, "probe the cgroup socket-release hook")
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, dedicated := createIntegrationCgroup(t, root, 900)
	if !dedicated {
		t.Skip("no dedicated cgroup to attach to")
	}
	cgroupFile, err := os.Open(path)
	if err != nil {
		t.Fatalf("open cgroup: %v", err)
	}
	defer cgroupFile.Close()
	cgroupFD := int(cgroupFile.Fd())

	supported, err := probeSocketReleaseSupport(cgroupFD)
	if err != nil {
		t.Fatalf("probe an empty hook: %v", err)
	}
	if !supported {
		t.Skip("kernel lacks the socket-release hook")
	}
	if ids := querySocketReleaseIDs(t, cgroupFD); len(ids) != 0 {
		t.Fatalf("probe left programs %v on the hook", ids)
	}

	owner, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         "sb_rel_owner",
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCgroupInetSockRelease,
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
		Attach:  CiliumEBPF.AttachCgroupInetSockRelease,
	}); err != nil {
		t.Fatalf("attach the other owner's program exclusively: %v", err)
	}
	t.Cleanup(func() { _ = rawDetachProgram(cgroupFD, owner, CiliumEBPF.AttachCgroupInetSockRelease) })
	ownerInfo, err := owner.Info()
	if err != nil {
		t.Fatalf("inspect the other owner's program: %v", err)
	}
	ownerID, ok := ownerInfo.ID()
	if !ok {
		t.Fatal("kernel did not report the other owner's program ID")
	}

	supported, err = probeSocketReleaseSupport(cgroupFD)
	if err != nil {
		t.Fatalf("probe a hook held exclusively: %v", err)
	}
	if supported {
		t.Fatal("probe reported a hook held exclusively by another owner as usable")
	}
	if ids := querySocketReleaseIDs(t, cgroupFD); !slices.Equal(ids, []CiliumEBPF.ProgramID{ownerID}) {
		t.Fatalf("hook holds %v after the probe, want only the other owner's %v", ids, ownerID)
	}
}

func querySocketReleaseIDs(t *testing.T, cgroupFD int) []CiliumEBPF.ProgramID {
	t.Helper()
	ids, err := queryCgroupProgramIDs(cgroupFD, CiliumEBPF.AttachCgroupInetSockRelease)
	if err != nil {
		t.Fatalf("query the socket-release hook: %v", err)
	}
	return ids
}
