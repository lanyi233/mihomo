//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testInstanceName keeps the abstract names of these tests apart from those of
// a running instance and of a concurrent test binary. Abstract socket names are
// limited to 107 bytes, so it stays short.
func testInstanceName(suffix string) string {
	return "@sing-ebpf-test-" + strconv.Itoa(os.Getpid()) + "-" + suffix
}

func TestAcquireInstanceSlotTakesTheFirstFreeSlot(t *testing.T) {
	base := testInstanceName("slot")
	name := func(slot int) string { return InstanceSlotName(base, slot) }
	held := make([]*InstanceSlot, 0, MaxInstanceSlots)
	t.Cleanup(func() {
		for _, slot := range held {
			_ = slot.Close()
		}
	})
	for want := range MaxInstanceSlots {
		slot, err := AcquireInstanceSlot(name)
		if err != nil {
			t.Fatalf("acquire slot %d: %v", want, err)
		}
		if slot.Index() != want {
			t.Fatalf("acquired slot %d, want %d", slot.Index(), want)
		}
		held = append(held, slot)
	}
	if _, err := AcquireInstanceSlot(name); !errors.Is(err, ErrInstanceSlotsExhausted) {
		t.Fatalf("acquire beyond the limit: %v, want ErrInstanceSlotsExhausted", err)
	}
	if err := held[0].Close(); err != nil {
		t.Fatal(err)
	}
	reused, err := AcquireInstanceSlot(name)
	if err != nil {
		t.Fatalf("the released slot 0 was not available again: %v", err)
	}
	held[0] = reused
	if reused.Index() != 0 {
		t.Fatalf("acquired slot %d, want the released slot 0", reused.Index())
	}
}

func TestInstanceSlotNameKeepsTheLegacyNameForSlotZero(t *testing.T) {
	if got := InstanceSlotName("@sing-ebpf-tc-7", 0); got != "@sing-ebpf-tc-7" {
		t.Fatalf("slot 0 name = %q, want the name single-instance builds lock", got)
	}
	if got := InstanceSlotName("@sing-ebpf-tc-7", 3); got != "@sing-ebpf-tc-7/3" {
		t.Fatalf("slot 3 name = %q", got)
	}
}

func TestAcquireInstanceMutexWaitsForTheHolder(t *testing.T) {
	name := strings.TrimPrefix(testInstanceName("mutex"), "@")
	held, err := AcquireInstanceMutex(name, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = AcquireInstanceMutex(name, 20*time.Millisecond); err == nil {
		t.Fatal("a held mutex was taken twice")
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = held.Close()
		close(released)
	}()
	waited, err := AcquireInstanceMutex(name, 5*time.Second)
	if err != nil {
		t.Fatalf("the mutex was not taken once its holder released it: %v", err)
	}
	<-released
	if err = waited.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInstanceLeaseValuesListsTheOtherLeases(t *testing.T) {
	key := strings.TrimPrefix(testInstanceName("lease"), "@")
	first, err := AcquireInstanceLease(key, "2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	if values, err := InstanceLeaseValues(key, first); err != nil || len(values) != 0 {
		t.Fatalf("values besides the only lease = %v, %v; want none", values, err)
	}
	second, err := AcquireInstanceLease(key, "1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	values, err := InstanceLeaseValues(key, first)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(values, []string{"1"}) {
		t.Fatalf("values besides the first lease = %v, want [1]", values)
	}
	values, err = InstanceLeaseValues(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(values)
	if !slices.Equal(values, []string{"1", "2"}) {
		t.Fatalf("all values = %v, want [1 2]", values)
	}
	if err = second.Close(); err != nil {
		t.Fatal(err)
	}
	if values, err = InstanceLeaseValues(key, first); err != nil || len(values) != 0 {
		t.Fatalf("a closed lease is still listed: %v, %v", values, err)
	}
	if _, err = AcquireInstanceLease(key, "a/b"); err == nil {
		t.Fatal("a lease value containing the separator was accepted")
	}
}

func TestParseAbstractSocketNames(t *testing.T) {
	const listing = `Num       RefCount Protocol Flags    Type St Inode Path
0000000000000000: 00000002 00000000 00000000 0002 01 1001 @sing-ebpf-lease/k/2/10.1
0000000000000000: 00000002 00000000 00010000 0001 01 1002 /run/systemd/notify
0000000000000000: 00000003 00000000 00000000 0001 03 1003
0000000000000000: 00000002 00000000 00000000 0002 01 1004 @sing-ebpf-lease/k/0/11.4
0000000000000000: 00000002 00000000 00000000 0002 01 1005 @sing-ebpf-lease/other/1/12.1
`
	names, err := parseAbstractSocketNames(strings.NewReader(listing), "@sing-ebpf-lease/k/")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names, []string{"@sing-ebpf-lease/k/2/10.1", "@sing-ebpf-lease/k/0/11.4"}) {
		t.Fatalf("names = %v", names)
	}
}
