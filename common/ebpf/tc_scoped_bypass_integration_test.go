//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net/netip"
	"testing"
)

// One TC backend carries both the local and the shared path. While the two
// scopes bypass the same rule sets they read one table; once they differ the
// shared path is given its own, and from then on reads only that one.
func TestTCScopedBypassTablesIntegration(t *testing.T) {
	requireEBPFIntegration(t, "run the TC programs against per-scope bypass tables")
	requireTCSocketAssignment(t)
	policy, err := CompilePolicy(PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareTC(TCConfig{
		ListenerPort: 65529,
		EnableLocal:  true,
		EnableShared: true,
		EnableIPv4:   true,
		EnableTCP:    true,
		Policy:       policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	// The local path hands selected packets to the delivery interface and
	// passes everything else, so without one it would select nothing.
	if err = backend.SetDeliveryInterface(1, MACAddress{0x02, 0, 0, 0, 0, 9}); err != nil {
		t.Fatal(err)
	}
	localEgress := backend.runtime.programs[tcProgramLocalEgressEthernet]
	sharedIngress := backend.runtime.programs[tcProgramSharedIngressEthernet]

	localOnly := netip.MustParseAddr("198.51.100.10")
	sharedOnly := netip.MustParseAddr("203.0.113.20")
	source := netip.MustParseAddr("192.0.2.10")
	sourcePort := uint16(52000)
	selected := func(path string, destination netip.Addr) bool {
		t.Helper()
		program := localEgress
		if path == "shared" {
			program = sharedIngress
		}
		sourcePort++
		action, _ := runTCProgram(t, program, testIPv4TCPPacket(source, destination, sourcePort, 443))
		return action != testTCActUnspec
	}
	expect := func(stage string, want map[string]map[netip.Addr]bool) {
		t.Helper()
		for path, destinations := range want {
			for destination, wantSelected := range destinations {
				if got := selected(path, destination); got != wantSelected {
					t.Fatalf("%s: %s path selected %s = %v, want %v", stage, path, destination, got, wantSelected)
				}
			}
		}
	}
	compile := func(addresses ...netip.Addr) BypassCIDRPolicy {
		t.Helper()
		var prefixes []netip.Prefix
		for _, address := range addresses {
			prefixes = append(prefixes, netip.PrefixFrom(address, 32))
		}
		compiled, compileErr := CompileBypassCIDRPolicy(prefixes)
		if compileErr != nil {
			t.Fatal(compileErr)
		}
		return compiled
	}

	if _, err = backend.UpdateCompiledBypassCIDR(compile(localOnly)); err != nil {
		t.Fatal(err)
	}
	expect("one table", map[string]map[netip.Addr]bool{
		"local":  {localOnly: false, sharedOnly: true},
		"shared": {localOnly: false, sharedOnly: true},
	})

	if _, err = backend.UpdateCompiledSharedBypassCIDR(compile(sharedOnly)); err != nil {
		t.Fatal(err)
	}
	expect("a table per scope", map[string]map[netip.Addr]bool{
		"local":  {localOnly: false, sharedOnly: true},
		"shared": {localOnly: true, sharedOnly: false},
	})

	if _, err = backend.UpdateCompiledSharedBypassCIDR(compile()); err != nil {
		t.Fatal(err)
	}
	expect("an empty shared table", map[string]map[netip.Addr]bool{
		"local":  {localOnly: false, sharedOnly: true},
		"shared": {localOnly: true, sharedOnly: true},
	})
}
