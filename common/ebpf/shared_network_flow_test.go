//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"
)

func TestSharedNetworkFlowReferences(t *testing.T) {
	backend := new(SharedNetworkBackend)
	flow := SharedNetworkFlowHandle{
		originalKey: sharedNetworkOriginalKey{InterfaceIndex: 7, Protocol: ProtocolTCP},
		listenerKey: sharedNetworkListenerKey{Protocol: ProtocolTCP, ListenerPort: 1234},
		generation:  11,
	}
	backend.retainFlowLocked(flow)
	backend.retainFlowLocked(flow)
	if backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("first release removed a multiply referenced flow")
	}
	if references := backend.flowReferences[flow]; references != 1 {
		t.Fatalf("unexpected remaining flow references: %d", references)
	}
	if !backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("last release did not select the flow for cleanup")
	}
	if _, loaded := backend.flowReferences[flow]; loaded {
		t.Fatal("released flow reference was retained")
	}
	if backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("duplicate release selected an already released flow for cleanup")
	}
}

func TestSharedNetworkTCPReleaseGrace(t *testing.T) {
	backend := new(SharedNetworkBackend)
	flow := SharedNetworkFlowHandle{
		originalKey: sharedNetworkOriginalKey{InterfaceIndex: 7, Protocol: ProtocolTCP},
		listenerKey: sharedNetworkListenerKey{Protocol: ProtocolTCP, ListenerPort: 1234},
		generation:  11,
	}
	backend.retainFlowLocked(flow)
	if !backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("last release did not select TCP flow for grace period")
	}
	now := time.Now()
	backend.deferTCPFlowReleaseLocked(flow, now)
	delay, available := backend.NextTCPFlowReleaseDelay(now)
	if !available || delay != sharedNetworkTCPReleaseGrace {
		t.Fatalf("unexpected cached release deadline: available=%v delay=%v", available, delay)
	}
	backend.retainFlowLocked(flow)
	if _, loaded := backend.flowReleases[flow]; loaded {
		t.Fatal("retained TCP flow remained pending for release")
	}
	// The cached deadline may be stale after a retain, but it never wakes later
	// than required and is recomputed by the resulting flush.
	if delay, available = backend.NextTCPFlowReleaseDelay(now); !available || delay != sharedNetworkTCPReleaseGrace {
		t.Fatalf("unexpected conservative release deadline: available=%v delay=%v", available, delay)
	}
}

func BenchmarkSharedNetworkTCPReleaseLaterDeadline(b *testing.B) {
	backend := &SharedNetworkBackend{flowWake: make(chan struct{}, 1)}
	now := time.Now()
	backend.deferTCPFlowReleaseLocked(SharedNetworkFlowHandle{}, now)
	<-backend.flowWake
	flows := make([]SharedNetworkFlowHandle, 1024)
	for index := range flows {
		flows[index].generation = uint64(index + 1)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := range b.N {
		backend.deferTCPFlowReleaseLocked(flows[index%len(flows)], now.Add(time.Second))
		select {
		case <-backend.flowWake:
		default:
		}
	}
}

func TestSharedNetworkFlowWakeOnlyForNewWorkOrEarlierDeadline(t *testing.T) {
	backend := &SharedNetworkBackend{flowWake: make(chan struct{}, 1)}
	expectWake := func(want bool) {
		t.Helper()
		select {
		case <-backend.TCPFlowWake():
			if !want {
				t.Fatal("unchanged maintenance deadline or occupancy woke the janitor")
			}
		default:
			if want {
				t.Fatal("new work did not wake the janitor")
			}
		}
	}
	flow := SharedNetworkFlowHandle{generation: 1}
	backend.retainFlowLocked(flow)
	expectWake(true)
	backend.retainFlowLocked(flow)
	expectWake(false)
	if backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("extra owner was lost")
	}
	if !backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("last owner did not release the flow")
	}
	now := time.Now()
	backend.deferTCPFlowReleaseLocked(flow, now)
	expectWake(true)
	backend.deferTCPFlowReleaseLocked(SharedNetworkFlowHandle{generation: 2}, now.Add(time.Second))
	expectWake(false)
	if len(backend.flowReleases) != 2 {
		t.Fatal("later release was not retained for the scheduled flush")
	}
	backend.deferTCPFlowReleaseLocked(SharedNetworkFlowHandle{generation: 3}, now.Add(-time.Second))
	expectWake(true)
	if delay, available := backend.NextTCPFlowReleaseDelay(now); !available || delay != sharedNetworkTCPReleaseGrace-time.Second {
		t.Fatalf("earlier release was not scheduled: delay=%s available=%v", delay, available)
	}
}
