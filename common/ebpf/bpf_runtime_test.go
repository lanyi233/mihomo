//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestOperationErrorPreservesVerifierDetails(t *testing.T) {
	for _, errno := range []error{unix.EINVAL, unix.EACCES, unix.EPERM, unix.EBUSY} {
		t.Run(errno.Error(), func(t *testing.T) {
			original := &CiliumEBPF.VerifierError{Cause: errno, Log: []string{"invalid access to packet"}}
			wrapped := eBPFOperationError("load programs", fmt.Errorf("program shared_ingress: %w", original))
			var verifier *CiliumEBPF.VerifierError
			if !errors.As(wrapped, &verifier) || verifier != original || !errors.Is(wrapped, errno) {
				t.Fatalf("lost verifier error chain: %v", wrapped)
			}
			if !strings.Contains(wrapped.Error(), "shared_ingress") {
				t.Fatalf("lost program context: %v", wrapped)
			}
		})
	}
}
