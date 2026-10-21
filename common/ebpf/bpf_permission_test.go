//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// ciliumMapCreateEPERM mirrors the error cilium/ebpf returns for any EPERM
// from BPF_MAP_CREATE, including its unconditional MEMLOCK hint.
var ciliumMapCreateEPERM = fmt.Errorf("creating map: %w", fmt.Errorf("map create: %w"+ciliumMemlockHint, unix.EPERM))

func withBPFPermissionState(t *testing.T, state bpfPermissionState) {
	t.Helper()
	original := readBPFPermissionState
	t.Cleanup(func() { readBPFPermissionState = original })
	readBPFPermissionState = func() bpfPermissionState { return state }
}

func privilegedModernState() bpfPermissionState {
	return bpfPermissionState{
		uid:            0,
		capsKnown:      true,
		capBPF:         true,
		capSysAdmin:    true,
		capSysResource: true,
		release:        "6.1.75-android14-11",
		memlockKnown:   true,
		memlockLimit:   unix.RLIM_INFINITY,
	}
}

func requireExplained(t *testing.T, err error, fragments ...string) {
	t.Helper()
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("explained error lost EPERM: %v", err)
	}
	var explained *bpfPermissionError
	if !errors.As(err, &explained) {
		t.Fatalf("error was not explained: %v", err)
	}
	message := err.Error()
	if strings.Contains(message, "MEMLOCK may be too low") {
		t.Fatalf("explained error kept the generic cilium hint: %q", message)
	}
	if !strings.Contains(message, "map create") {
		t.Fatalf("explained error lost the original operation: %q", message)
	}
	for _, fragment := range fragments {
		if !strings.Contains(message, fragment) {
			t.Fatalf("error %q does not contain %q", message, fragment)
		}
	}
}

func TestExplainBPFPermissionMissingCapabilities(t *testing.T) {
	state := privilegedModernState()
	state.uid = 2000
	state.capBPF = false
	state.capSysAdmin = false
	withBPFPermissionState(t, state)
	requireExplained(t, explainBPFPermissionError(ciliumMapCreateEPERM, nil),
		"uid 2000", "neither CAP_BPF nor CAP_SYS_ADMIN", "run it as root")
}

func TestExplainBPFPermissionRootWithoutCapabilities(t *testing.T) {
	state := privilegedModernState()
	state.capBPF = false
	state.capSysAdmin = false
	withBPFPermissionState(t, state)
	err := explainBPFPermissionError(ciliumMapCreateEPERM, nil)
	requireExplained(t, err, "runs as root without CAP_BPF and CAP_SYS_ADMIN", "dropped")
	if strings.Contains(err.Error(), "run it as root") {
		t.Fatalf("root process was told to run as root: %v", err)
	}
}

func TestExplainBPFPermissionUserNamespace(t *testing.T) {
	state := privilegedModernState()
	state.userNamespace = true
	withBPFPermissionState(t, state)
	requireExplained(t, explainBPFPermissionError(ciliumMapCreateEPERM, nil), "user namespace")
}

func TestExplainBPFPermissionMemlockOnOldKernel(t *testing.T) {
	state := privilegedModernState()
	state.release = "5.10.198-android12-9-g1234"
	state.memlockAccounting = true
	state.memlockLimit = 64 << 10
	state.capSysResource = false
	withBPFPermissionState(t, state)
	memlockErr := fmt.Errorf("setrlimit: %w", unix.EPERM)
	requireExplained(t, explainBPFPermissionError(ciliumMapCreateEPERM, memlockErr),
		"Linux 5.10.198", "RLIMIT_MEMLOCK", "uid 0", "64 KiB", "setrlimit", "CAP_SYS_RESOURCE")
}

func TestExplainBPFPermissionLeavesUnidentifiedCauses(t *testing.T) {
	withBPFPermissionState(t, privilegedModernState())
	if err := explainBPFPermissionError(ciliumMapCreateEPERM, nil); err != ciliumMapCreateEPERM {
		t.Fatalf("unidentified EPERM was rewritten: %v", err)
	}
	if err := explainBPFPermissionError(unix.EINVAL, nil); err != unix.EINVAL {
		t.Fatalf("non-EPERM error was rewritten: %v", err)
	}
	if err := explainBPFPermissionError(nil, nil); err != nil {
		t.Fatalf("nil error became %v", err)
	}
}

func TestExplainBPFPermissionIsIdempotent(t *testing.T) {
	state := privilegedModernState()
	state.capBPF = false
	state.capSysAdmin = false
	withBPFPermissionState(t, state)
	once := explainBPFPermissionError(ciliumMapCreateEPERM, nil)
	if twice := explainBPFPermissionError(once, nil); twice != once {
		t.Fatalf("second explanation wrapped again: %v", twice)
	}
}

func TestKernelChargesBPFToMemlock(t *testing.T) {
	for release, want := range map[string]bool{
		"4.14.186-perf+":             true,
		"4.19.157-android11":         true,
		"5.4.254-qgki":               true,
		"5.10.198-android12-9-g1234": true,
		"5.11.0":                     false,
		"5.15.148-android14-11":      false,
		"6.1.75-android14-11":        false,
		"6.18.44-fc-v64":             false,
		"unknown":                    false,
		"":                           false,
	} {
		if got := kernelChargesBPFToMemlock(release); got != want {
			t.Errorf("kernelChargesBPFToMemlock(%q) = %v, want %v", release, got, want)
		}
	}
}

func TestIsInitialUIDMap(t *testing.T) {
	for content, want := range map[string]bool{
		"         0          0 4294967295\n":                    true,
		"         0     100000      65536\n":                    false,
		"         0          0 4294967295\n      1000 1000 1\n": false,
		"": false,
	} {
		if got := isInitialUIDMap(content); got != want {
			t.Errorf("isInitialUIDMap(%q) = %v, want %v", content, got, want)
		}
	}
}

func TestFormatMemlockLimit(t *testing.T) {
	for limit, want := range map[uint64]string{
		64 << 10: "64 KiB",
		8 << 20:  "8 MiB",
		1000:     "1000 bytes",
	} {
		if got := formatMemlockLimit(limit); got != want {
			t.Errorf("formatMemlockLimit(%d) = %q, want %q", limit, got, want)
		}
	}
}
