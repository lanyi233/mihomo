//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net/netip"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

// Given a cgroup backend, the shared packet-rewrite plane borrows its bypass
// table, which keeps the two scopes in step while they bypass the same rule
// sets. OwnBypassCIDR gives it a table of its own for when they do not, and
// writing that one leaves the cgroup's alone.
func TestSharedNetworkOwnBypassTableIntegration(t *testing.T) {
	requireEBPFIntegration(t, "prepare a shared-network backend beside a cgroup one")
	root, err := DetectCgroup2Root()
	if err != nil {
		t.Skipf("cgroup v2 is unavailable: %v", err)
	}
	path, dedicated := createIntegrationCgroup(t, root, 940)
	if !dedicated {
		t.Skip("no dedicated cgroup to prepare against")
	}
	cgroupBackend, err := prepareCgroupIntegrationBackend(path, true, false, false)
	if err != nil {
		if cgroupIntegrationUnavailable(err) {
			t.Skipf("cgroup eBPF is unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cgroupBackend.Close() })
	cgroupTable := cgroupBackend.runtime.maps["cgroup_bypass_ipv4"]

	policy, err := CompilePolicy(PolicyConfig{EnableTCP: true})
	if err != nil {
		t.Fatal(err)
	}
	borrowing, err := PrepareSharedNetwork(cgroupBackend, newTestSharedNetworkConfig(policy, false))
	if err != nil {
		t.Skipf("cannot prepare a real shared-network eBPF backend in this environment: %v", err)
	}
	t.Cleanup(func() { _ = borrowing.Close() })
	if mapIDForTest(t, borrowing.bypassIPv4Map) != mapIDForTest(t, cgroupTable) {
		t.Fatal("without OwnBypassCIDR the shared plane did not borrow the cgroup's bypass table")
	}

	config := newTestSharedNetworkConfig(policy, false)
	config.OwnBypassCIDR = true
	owning, err := PrepareSharedNetwork(cgroupBackend, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owning.Close() })
	if mapIDForTest(t, owning.bypassIPv4Map) == mapIDForTest(t, cgroupTable) {
		t.Fatal("with OwnBypassCIDR the shared plane still borrowed the cgroup's bypass table")
	}

	sharedPolicy, err := CompileBypassCIDRPolicy([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owning.UpdateCompiledBypassCIDR(sharedPolicy); err != nil {
		t.Fatal(err)
	}
	if ipv4, _ := owning.BypassCIDRCount(); ipv4 != 1 {
		t.Fatalf("shared plane holds %d IPv4 bypass prefixes, want 1", ipv4)
	}
	if entries := mapEntriesForTest(t, cgroupTable); entries != 0 {
		t.Fatalf("writing the shared plane's own table put %d entries in the cgroup's", entries)
	}
}

func mapIDForTest(t *testing.T, m *CiliumEBPF.Map) CiliumEBPF.MapID {
	t.Helper()
	if m == nil {
		t.Fatal("map is missing")
	}
	info, err := m.Info()
	if err != nil {
		t.Fatal(err)
	}
	id, ok := info.ID()
	if !ok {
		t.Fatal("kernel did not report a map ID")
	}
	return id
}

func mapEntriesForTest(t *testing.T, m *CiliumEBPF.Map) int {
	t.Helper()
	var key, value []byte
	entries := 0
	iterator := m.Iterate()
	for iterator.Next(&key, &value) {
		entries++
	}
	if err := iterator.Err(); err != nil {
		t.Fatal(err)
	}
	return entries
}
