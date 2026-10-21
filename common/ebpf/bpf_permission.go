//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"strings"

	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// Capability numbers from linux/capability.h. CAP_BPF exists since Linux 5.8;
// older kernels report it as absent and require CAP_SYS_ADMIN instead.
const (
	capabilitySysAdmin    = 21
	capabilitySysResource = 24
	capabilityBPF         = 39
)

// bpfPermissionState is the process context that decides why the kernel
// answered a BPF object creation with EPERM.
type bpfPermissionState struct {
	uid int
	// userNamespace is true when the process does not run in the initial user
	// namespace. Capabilities held there do not satisfy BPF permission checks.
	userNamespace  bool
	capsKnown      bool
	capBPF         bool
	capSysAdmin    bool
	capSysResource bool
	release        string
	// memlockAccounting is true on kernels before 5.11, which charge BPF
	// memory to the per-user RLIMIT_MEMLOCK budget instead of the memory
	// cgroup.
	memlockAccounting bool
	memlockKnown      bool
	memlockLimit      uint64
}

// readBPFPermissionState is replaced in tests.
var readBPFPermissionState = func() bpfPermissionState {
	state := bpfPermissionState{uid: os.Getuid()}
	state.userNamespace = runsInNonInitialUserNamespace()
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if unix.Capget(&header, &data[0]) == nil {
		state.capsKnown = true
		state.capBPF = effectiveCapability(data, capabilityBPF)
		state.capSysAdmin = effectiveCapability(data, capabilitySysAdmin)
		state.capSysResource = effectiveCapability(data, capabilitySysResource)
	}
	state.release = kernelProbeRelease()
	state.memlockAccounting = kernelChargesBPFToMemlock(state.release)
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit) == nil {
		state.memlockKnown = true
		state.memlockLimit = limit.Cur
	}
	return state
}

func effectiveCapability(data [2]unix.CapUserData, capability uint) bool {
	return data[capability/32].Effective&(1<<(capability%32)) != 0
}

// runsInNonInitialUserNamespace reports whether the uid map differs from the
// identity map of the initial user namespace ("0 0 4294967295").
func runsInNonInitialUserNamespace() bool {
	content, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	return !isInitialUIDMap(string(content))
}

func isInitialUIDMap(content string) bool {
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 1 {
		return false
	}
	fields := strings.Fields(lines[0])
	return len(fields) == 3 && fields[0] == "0" && fields[1] == "0" && fields[2] == "4294967295"
}

// kernelChargesBPFToMemlock reports whether the release predates the memory
// cgroup accounting for BPF objects introduced in Linux 5.11.
func kernelChargesBPFToMemlock(release string) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, majorLoaded := leadingVersionNumber(parts[0])
	minor, minorLoaded := leadingVersionNumber(parts[1])
	if !majorLoaded || !minorLoaded {
		return false
	}
	return major < 5 || major == 5 && minor < 11
}

// bpfPermissionError replaces the generic message of an EPERM from BPF object
// creation with its diagnosed cause while keeping the original error chain.
// cilium/ebpf appends "MEMLOCK may be too low" to every such EPERM, which is
// wrong whenever the real cause is a missing capability or a user namespace.
type bpfPermissionError struct {
	cause string
	err   error
}

// ciliumMemlockHint is the suffix cilium/ebpf appends to every EPERM from map
// creation and program loading, whatever the actual cause.
const ciliumMemlockHint = " (MEMLOCK may be too low, consider rlimit.RemoveMemlock)"

func (e *bpfPermissionError) Error() string {
	return e.cause + ": " + strings.ReplaceAll(e.err.Error(), ciliumMemlockHint, "")
}

func (e *bpfPermissionError) Unwrap() error {
	return e.err
}

// explainBPFPermissionError diagnoses an EPERM returned while creating BPF maps
// or programs. memlockErr is the result of raiseMemlockLimit for this attempt.
// Errors other than EPERM, and EPERM without an identifiable cause, are
// returned unchanged.
func explainBPFPermissionError(err error, memlockErr error) error {
	if err == nil || !errors.Is(err, unix.EPERM) {
		return err
	}
	var explained *bpfPermissionError
	if errors.As(err, &explained) {
		return err
	}
	state := readBPFPermissionState()
	switch {
	case state.userNamespace:
		return &bpfPermissionError{
			cause: "eBPF object creation was denied: the process runs in a non-initial user namespace " +
				"(for example an unprivileged container), where capabilities do not grant BPF access",
			err: err,
		}
	case state.capsKnown && !state.capBPF && !state.capSysAdmin:
		cause := fmt.Sprint("eBPF object creation was denied: the process (uid ", state.uid,
			") has neither CAP_BPF nor CAP_SYS_ADMIN; run it as root")
		if state.uid == 0 {
			cause = "eBPF object creation was denied: the process runs as root without CAP_BPF and " +
				"CAP_SYS_ADMIN; whatever launched it dropped them from its capability set"
		}
		return &bpfPermissionError{cause: cause, err: err}
	case state.memlockAccounting && state.memlockKnown && state.memlockLimit != unix.RLIM_INFINITY:
		cause := fmt.Sprint("eBPF object creation was denied: Linux ", state.release,
			" charges eBPF memory to RLIMIT_MEMLOCK, a budget shared by every process of uid ", state.uid,
			"; the finite limit of ", formatMemlockLimit(state.memlockLimit), " may be exhausted")
		if memlockErr != nil {
			cause += "; raising the limit failed (" + memlockErr.Error() + ")"
		}
		if state.capsKnown && !state.capSysResource {
			cause += "; the process lacks CAP_SYS_RESOURCE"
		}
		return &bpfPermissionError{cause: cause, err: err}
	}
	if memlockErr != nil && state.memlockAccounting {
		return E.Errors(err, E.Cause(memlockErr, "remove memlock limit"))
	}
	return err
}

func formatMemlockLimit(limit uint64) string {
	if limit >= 1<<20 && limit%(1<<20) == 0 {
		return fmt.Sprint(limit>>20, " MiB")
	}
	if limit >= 1<<10 && limit%(1<<10) == 0 {
		return fmt.Sprint(limit>>10, " KiB")
	}
	return fmt.Sprint(limit, " bytes")
}
