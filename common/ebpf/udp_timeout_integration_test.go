//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net/netip"
	"testing"
	"time"
	"unsafe"
)

// The point of SetUDPTimeout is that the kernel reads the new value, so the
// assertion is against the control map the programs actually consult -- not
// against the backend's own copy of it, which would pass even if the write
// never left userspace.
func TestCgroupSetUDPTimeoutReachesTheControlMapIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test cgroup UDP timeout control")
	cgroupPath, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, _ := createIntegrationCgroup(t, cgroupPath, 0)
	backend, err := prepareCgroupIntegrationBackend(path, true, true, false)
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup eBPF is unavailable: %v", err)
		}
		t.Fatalf("prepare cgroup backend: %v", err)
	}
	defer backend.Close()

	if err = backend.LoadPrograms(1080); err != nil {
		t.Fatalf("load cgroup programs: %v", err)
	}
	readTimeout := func() uint32 {
		t.Helper()
		key := uint32(0)
		var control cgroupControl
		if err := lookupMap(backend.runtime.control_map_fd, unsafe.Pointer(&key), unsafe.Pointer(&control)); err != nil {
			t.Fatalf("read cgroup control: %v", err)
		}
		return control.UDPTimeoutSeconds
	}

	if got := readTimeout(); got == 0 {
		t.Fatal("the backend loaded with no UDP timeout at all")
	}
	if err = backend.SetUDPTimeout(600 * time.Second); err != nil {
		t.Fatalf("set UDP timeout: %v", err)
	}
	if got := readTimeout(); got != 600 {
		t.Fatalf("kernel UDP timeout = %d, want 600", got)
	}
	if got := backend.UDPTimeoutSeconds(); got != 600 {
		t.Fatalf("backend reports %d, kernel has 600", got)
	}

	// The rest of the control record has to survive: it is rewritten wholesale
	// from the backend's own state on every change, so a field this path forgets
	// would be silently zeroed rather than left alone.
	key := uint32(0)
	var control cgroupControl
	if err = lookupMap(backend.runtime.control_map_fd, unsafe.Pointer(&key), unsafe.Pointer(&control)); err != nil {
		t.Fatalf("read cgroup control: %v", err)
	}
	if control.ListenerPort != 1080 {
		t.Fatalf("listener port = %d after a timeout change, want 1080", control.ListenerPort)
	}
	if control.Flags == 0 {
		t.Fatal("policy flags were cleared by a timeout change")
	}
}

// The shared plane's half. It reaches the kernel through a different path --
// the backend keeps the whole control record in memory and rewrites it -- so
// the cgroup test above says nothing about it.
func TestSharedNetworkSetUDPTimeoutReachesTheControlMapIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test shared packet-rewrite UDP timeout control")
	policy, err := CompilePolicy(PolicyConfig{EnableTCP: true, EnableUDP: true, SharedDNSMode: DNSModeOff})
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	backend, err := PrepareSharedNetwork(nil, SharedNetworkConfig{
		ListenerPort: 65531, EnableTCP: true, EnableUDP: true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"),
		UDPTimeout:   time.Minute, Policy: policy,
		MapCapacity: SharedNetworkMapCapacities{Proxy: 64, Bypass: 64},
	})
	if err != nil {
		t.Skipf("shared packet-rewrite eBPF is unavailable: %v", err)
	}
	defer backend.Close()
	if err = backend.Enable(); err != nil {
		t.Fatalf("enable backend: %v", err)
	}

	readControl := func() sharedNetworkControl {
		t.Helper()
		key := uint32(0)
		var control sharedNetworkControl
		if err := lookupMap(backend.runtime.control_map_fd, unsafe.Pointer(&key), unsafe.Pointer(&control)); err != nil {
			t.Fatalf("read shared control: %v", err)
		}
		return control
	}

	before := readControl()
	if before.UDPTimeoutSeconds != 60 {
		t.Fatalf("kernel UDP timeout = %d, want the configured 60", before.UDPTimeoutSeconds)
	}
	if err = backend.SetUDPTimeout(600 * time.Second); err != nil {
		t.Fatalf("set UDP timeout: %v", err)
	}
	after := readControl()
	if after.UDPTimeoutSeconds != 600 {
		t.Fatalf("kernel UDP timeout = %d, want 600", after.UDPTimeoutSeconds)
	}
	if got := backend.UDPTimeoutSeconds(); got != 600 {
		t.Fatalf("backend reports %d, kernel has 600", got)
	}
	// The record is rewritten wholesale from b.control, so a field this path
	// forgets would be zeroed rather than left alone. Enabled is the one that
	// would silently switch the whole plane off.
	if after.Enabled != before.Enabled || after.Flags != before.Flags {
		t.Fatalf("a timeout change altered the rest of the control record: enabled %d->%d, flags %d->%d",
			before.Enabled, after.Enabled, before.Flags, after.Flags)
	}
}
