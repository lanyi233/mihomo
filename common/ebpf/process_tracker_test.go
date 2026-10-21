//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

type trackerTestLink struct {
	err    error
	closed bool
}

func (l *trackerTestLink) Close() error {
	if l.err == nil {
		l.closed = true
	}
	return l.err
}

func (l *trackerTestLink) IsClosed() bool { return l.closed }

func TestProcessTrackerKeepsCleanupUntilWritersDetach(t *testing.T) {
	cleanup := &trackerTestLink{}
	writer := &trackerTestLink{err: errors.New("detach failed")}
	tracker := &ProcessTracker{links: []cgroupProgramLink{cleanup, writer}, releaseCleanup: true}
	if err := tracker.Close(); !errors.Is(err, writer.err) {
		t.Fatalf("lost detach error: %v", err)
	}
	if cleanup.closed || !tracker.ReleaseCleanup() {
		t.Fatal("release hook detached while metadata writer was still attached")
	}
	writer.err = nil
	if err := tracker.Close(); err != nil {
		t.Fatal(err)
	}
	if !writer.closed || !cleanup.closed || tracker.ReleaseCleanup() {
		t.Fatal("retry did not finish cleanup")
	}
}

func TestProcessSocketOwnerABI(t *testing.T) {
	if size := unsafe.Sizeof(ProcessSocketOwner{}); size != 8 {
		t.Fatalf("unexpected process owner size: %d", size)
	}
}

func TestProcessTrackerHooks(t *testing.T) {
	if hooks := processTrackerHooks(ProcessTrackerConfig{}); len(hooks) != 0 {
		t.Fatalf("unexpected hooks for disabled protocols: %+v", hooks)
	}
	base := processTrackerHooks(ProcessTrackerConfig{EnableTCP: true})
	if len(base) != 1 || base[0].attachType != CiliumEBPF.AttachCGroupInet4Connect {
		t.Fatalf("unexpected base process tracker hooks: %+v", base)
	}
	dualStackUDP := processTrackerHooks(ProcessTrackerConfig{EnableTCP: true, EnableUDP: true, EnableIPv6: true})
	if len(dualStackUDP) != 4 ||
		dualStackUDP[1].attachType != CiliumEBPF.AttachCGroupInet6Connect ||
		dualStackUDP[2].attachType != CiliumEBPF.AttachCGroupUDP4Sendmsg ||
		dualStackUDP[3].attachType != CiliumEBPF.AttachCGroupUDP6Sendmsg {
		t.Fatalf("unexpected dual-stack UDP process tracker hooks: %+v", dualStackUDP)
	}
}

func TestProcessTrackerInstructions(t *testing.T) {
	instructions := processTrackerInstructions(1, -1, -1, false)
	if len(instructions) == 0 {
		t.Fatal("empty process tracker instructions")
	}
	if err := instructions.Marshal(new(bytes.Buffer), binary.LittleEndian); err != nil {
		t.Fatal(err)
	}
}

func TestProcessTrackerPolicyMetadata(t *testing.T) {
	tests := []struct {
		name          string
		defaultBypass bool
		matched       bool
		expected      int32
	}{
		{"include match", true, true, socketMetadataPolicyIntercept},
		{"include miss", true, false, socketMetadataPolicyBypass},
		{"exclude match", false, true, socketMetadataPolicyBypass},
		{"exclude miss", false, false, socketMetadataPolicyIntercept},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := processTrackerPolicyMetadata(test.defaultBypass, test.matched); actual != test.expected {
				t.Fatalf("unexpected metadata: got=%d expected=%d", actual, test.expected)
			}
		})
	}
}

func TestProcessTrackerUIDUsesClassicNetworkByteOrder(t *testing.T) {
	instructions := processTrackerInstructions(1, 2, 3, false)
	var conversions int
	for _, instruction := range instructions {
		if instruction.OpCode == asm.BSwap(asm.R0, asm.Word).OpCode {
			t.Fatal("UID policy requires an ISA v4 unconditional swap")
		}
		if instruction.OpCode == asm.HostTo(asm.BE, asm.R0, asm.Word).OpCode && instruction.Constant == 32 {
			conversions++
		}
	}
	if conversions != 1 {
		t.Fatalf("UID network-order conversions = %d, want 1", conversions)
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		if err := instructions.Marshal(new(bytes.Buffer), order); err != nil {
			t.Fatal(err)
		}
	}
}
