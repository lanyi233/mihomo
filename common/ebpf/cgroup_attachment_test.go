//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"slices"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func replaceCgroupAttachOperations(
	t *testing.T,
	linkErr error,
	rawAttach func(link.RawAttachProgramOptions) error,
) {
	t.Helper()
	originalAttachRawLink := attachRawLink
	originalRawAttachProgram := rawAttachProgram
	originalQuery := queryCgroupPrograms
	t.Cleanup(func() {
		attachRawLink = originalAttachRawLink
		rawAttachProgram = originalRawAttachProgram
		queryCgroupPrograms = originalQuery
	})
	attachRawLink = func(link.RawLinkOptions) (*link.RawLink, error) {
		return nil, linkErr
	}
	rawAttachProgram = rawAttach
	// An empty hook: the only state in which the exclusive fallback would
	// otherwise be attempted.
	queryCgroupPrograms = func(link.QueryOptions) (*link.QueryResult, error) {
		return &link.QueryResult{}, nil
	}
}

// The process tracker shares the cgroup v2 root with the interception
// backend. If it could fall back to an unflagged attach, the root hook would
// enter single-program mode and the kernel would then reject the backend's
// own attachment with EPERM, which surfaced as "refusing to replace existing
// cgroup program owner" for sb_ebpf_conn4.
func TestSharedCgroupAttachNeverUsesExclusiveFallback(t *testing.T) {
	var flags []uint32
	replaceCgroupAttachOperations(t, unix.EPERM, func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EPERM
		}
		return nil
	})
	programLink, err := attachCgroupProgramShared(t.TempDir(), nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err == nil {
		_ = programLink.Close()
		t.Fatal("shared cgroup attach succeeded through an exclusive attachment")
	}
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("shared cgroup attach error = %v, want EPERM", err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI}) {
		t.Fatalf("flags=%v, want only BPF_F_ALLOW_MULTI", flags)
	}
}

func TestSharedCgroupAttachUsesLegacyMulti(t *testing.T) {
	var flags []uint32
	replaceCgroupAttachOperations(t, unix.EINVAL, func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		return nil
	})
	programLink, err := attachCgroupProgramShared(t.TempDir(), nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	legacyLink, loaded := programLink.(*legacyCgroupProgramLink)
	if !loaded {
		t.Fatalf("link type = %T, want legacy cgroup link", programLink)
	}
	legacyLink.detachProgram = func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error { return nil }
	if err = legacyLink.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI}) {
		t.Fatalf("flags=%v, want only BPF_F_ALLOW_MULTI", flags)
	}
}

func TestExclusiveCgroupAttachKeepsLegacyFallbackOnEmptyHook(t *testing.T) {
	var flags []uint32
	replaceCgroupAttachOperations(t, unix.EINVAL, func(current link.RawAttachProgramOptions) error {
		flags = append(flags, current.Flags)
		if current.Flags == unix.BPF_F_ALLOW_MULTI {
			return unix.EINVAL
		}
		return nil
	})
	programLink, err := attachCgroupProgram(t.TempDir(), nil, CiliumEBPF.AttachCGroupInet4Connect)
	if err != nil {
		t.Fatal(err)
	}
	legacyLink := programLink.(*legacyCgroupProgramLink)
	legacyLink.detachProgram = func(int, *CiliumEBPF.Program, CiliumEBPF.AttachType) error { return nil }
	if err = legacyLink.Close(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(flags, []uint32{unix.BPF_F_ALLOW_MULTI, 0}) {
		t.Fatalf("flags=%v, want [ALLOW_MULTI, 0]", flags)
	}
}
