//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"net/netip"
	"testing"
	"time"
)

// The kernel repeats the classifier on the same bypassed packet, avoiding
// per-packet syscall and Go allocation noise in the reported kernel timing.
func BenchmarkSharedBypassPortIntegration(b *testing.B) {
	requireEBPFIntegration(b, "benchmark shared bypass-port in the kernel")
	policy, err := CompilePolicy(PolicyConfig{EnableTCP: true, SharedDNSMode: DNSModeOff,
		SharedBypassPort: []PortRange{{Start: 8443, End: 8443}}})
	if err != nil {
		b.Fatal(err)
	}
	backend, err := PrepareSharedNetwork(nil, SharedNetworkConfig{ListenerPort: 65531, EnableTCP: true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"), Policy: policy, UDPTimeout: time.Minute,
		MapCapacity: SharedNetworkMapCapacities{Proxy: 64, Bypass: 1}})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		b.Fatal(err)
	}
	packet := sharedRewriteTestPacket(ProtocolTCP, netip.MustParseAddrPort("192.0.2.10:53000"), netip.MustParseAddrPort("1.1.1.1:8443"), nil, false)
	b.ResetTimer()
	action, duration, err := backend.IngressProgram().Benchmark(packet, b.N, nil)
	b.StopTimer()
	if err != nil {
		b.Fatal(err)
	}
	if action != testTCActUnspec {
		b.Fatalf("unexpected action: %d", action)
	}
	b.ReportMetric(float64(duration.Nanoseconds()), "kernel-ns/op")
}
