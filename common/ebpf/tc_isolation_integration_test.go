//go:build with_ebpf && linux && ebpf_integration

package ebpf

import "testing"

func TestTCIsolatedVerifierIntegration(t *testing.T) {
	requireEBPFIntegration(t, "load tuple-preserving namespace TC programs")
	for _, legacy := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			for _, process := range []bool{false, true} {
				policy, err := CompilePolicy(PolicyConfig{EnableTCP: true, EnableUDP: true})
				if err != nil {
					t.Fatal(err)
				}
				backend, err := prepareTC(TCConfig{Isolated: true, ListenerPort: 65530, EnableLocal: true, EnableShared: true,
					EnableIPv4: true, EnableLocalIPv6: true, EnableSharedIPv6: true, EnableTCP: tcp, EnableUDP: true,
					Policy: policy, TrackProcess: process, AssignmentCapacity: 32}, legacy)
				if err != nil {
					t.Fatalf("legacy=%v tcp=%v process=%v: %+v", legacy, tcp, process, err)
				}
				if backend.DeliveryIngressProgramFD() < 0 || backend.IsolatedReturnProgramFD() < 0 {
					t.Fatal("missing isolation programs")
				}
				if err = backend.Close(); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
