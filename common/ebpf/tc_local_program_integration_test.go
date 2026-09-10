//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"errors"
	CiliumEBPF "github.com/cilium/ebpf"
	"strings"
	"testing"
)

// Load local classifiers independently of sk_assign, which requires Linux 5.9.
func TestTCLocalClassifierLoadIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify local TC classifiers on older kernels")
	spec, err := loadTC()
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range spec.Programs {
		if !strings.HasPrefix(p.SectionName, "classifier/local_egress_") {
			delete(spec.Programs, name)
		}
	}
	delete(spec.Maps, "tc_listener_sockets")
	for _, m := range spec.Maps {
		m.Extra = nil
		m.MaxEntries = 16
		if m.Type == CiliumEBPF.LPMTrie {
			m.Flags = 1
		}
	}
	collection, err := CiliumEBPF.NewCollection(spec)
	if err != nil {
		var verifier *CiliumEBPF.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("%+v", verifier)
		}
		t.Fatal(err)
	}
	collection.Close()
}
