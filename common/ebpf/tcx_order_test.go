//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestTCXPriorityAnchor(t *testing.T) {
	priorities := map[CiliumEBPF.ProgramID]uint16{1: 1, 2: 5, 4: 3}
	previous := tcxProgramOrder
	tcxProgramOrder = func(id CiliumEBPF.ProgramID) (uint16, bool, error) {
		if id == 99 {
			return 0, false, unix.EPERM
		}
		priority, marked := priorities[id]
		return priority, marked, nil
	}
	t.Cleanup(func() { tcxProgramOrder = previous })
	// 3 is a foreign program without a marker, between the priorities 5 and 3.
	hook := []link.AttachedProgram{{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4}}
	for _, testCase := range []struct {
		priority uint16
		want     link.Anchor
		scenario string
	}{
		{0, link.BeforeProgramByID(1), "lowest priority goes before every marked program"},
		{1, link.BeforeProgramByID(2), "equal priority keeps attach order"},
		{2, link.BeforeProgramByID(2), "before the first larger priority, not the smallest larger one"},
		{5, link.Tail(), "nothing larger: append"},
		{9, link.Tail(), "largest priority: append"},
	} {
		if got, err := tcxPriorityAnchor(hook, testCase.priority); err != nil || got != testCase.want {
			t.Errorf("%s: anchor for priority %d = %#v, %v; want %#v", testCase.scenario, testCase.priority, got, err, testCase.want)
		}
	}
	if got, err := tcxPriorityAnchor(nil, 1); err != nil || got != link.Tail() {
		t.Errorf("anchor on an empty hook = %#v, %v; want the tail", got, err)
	}
	// A program whose priority cannot be read makes the position unknown.
	if _, err := tcxPriorityAnchor(append(hook, link.AttachedProgram{ID: 99}), 9); !errors.Is(err, unix.EPERM) {
		t.Errorf("an unreadable program gave %v, want its error", err)
	}
}

func TestAttachTCXOrderedQueryErrors(t *testing.T) {
	originalQuery := queryTCXPrograms
	t.Cleanup(func() { queryTCXPrograms = originalQuery })

	for _, testCase := range []struct {
		name            string
		queryErr        error
		wantUnsupported bool
	}{
		{name: "unsupported", queryErr: CiliumEBPF.ErrNotSupported, wantUnsupported: true},
		{name: "eopnotsupp", queryErr: unix.EOPNOTSUPP, wantUnsupported: true},
		{name: "enosys", queryErr: unix.ENOSYS, wantUnsupported: true},
		{name: "einval", queryErr: unix.EINVAL, wantUnsupported: true},
		{name: "permission", queryErr: unix.EPERM},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			queryTCXPrograms = func(link.QueryOptions) (*link.QueryResult, error) {
				return nil, testCase.queryErr
			}
			_, err := AttachTCXOrdered(1, CiliumEBPF.AttachTCXEgress, &CiliumEBPF.Program{}, 100)
			if err == nil {
				t.Fatal("AttachTCXOrdered unexpectedly succeeded")
			}
			if testCase.wantUnsupported {
				if !errors.Is(err, CiliumEBPF.ErrNotSupported) {
					t.Fatalf("unsupported query did not update capability classification: %v", err)
				}
				if errors.Is(err, ErrTCXOrderUnavailable) {
					t.Fatalf("unsupported query error was classified as ordered TCX unavailable: %v", err)
				}
			} else if !errors.Is(err, ErrTCXOrderUnavailable) {
				t.Fatalf("query error = %v, want ErrTCXOrderUnavailable", err)
			}
		})
	}
}
