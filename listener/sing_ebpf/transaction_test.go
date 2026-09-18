//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"strings"
	"testing"
)

func recordingStep(name string, order *[]string, applyErr error) reversibleStep {
	return reversibleStep{
		name: name,
		apply: func() error {
			*order = append(*order, "apply:"+name)
			return applyErr
		},
		revert: func() error {
			*order = append(*order, "revert:"+name)
			return nil
		},
	}
}

func TestApplyReversibleStepsAppliesEveryStepInOrder(t *testing.T) {
	var order []string
	steps := []reversibleStep{
		recordingStep("TC", &order, nil),
		recordingStep("cgroup", &order, nil),
		recordingStep("shared", &order, nil),
	}

	if err := applyReversibleSteps(steps); err != nil {
		t.Fatalf("all-succeeding transaction failed: %v", err)
	}
	want := []string{"apply:TC", "apply:cgroup", "apply:shared"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

// The point of the transaction: a plane that fails must not leave the ones
// before it carrying a policy the others never got.
func TestApplyReversibleStepsUndoesWhatItAlreadyApplied(t *testing.T) {
	var order []string
	failure := errors.New("map is full")
	steps := []reversibleStep{
		recordingStep("TC", &order, nil),
		recordingStep("cgroup", &order, failure),
		recordingStep("shared", &order, nil),
	}

	err := applyReversibleSteps(steps)
	if err == nil {
		t.Fatal("a failing transaction reported success")
	}
	if !errors.Is(err, failure) {
		t.Fatalf("error lost the cause: %v", err)
	}
	// TC applied then reverted; cgroup failed so has nothing to undo; shared
	// never ran at all.
	want := []string{"apply:TC", "apply:cgroup", "revert:TC"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

func TestApplyReversibleStepsUndoesNewestFirst(t *testing.T) {
	var order []string
	steps := []reversibleStep{
		recordingStep("TC", &order, nil),
		recordingStep("cgroup", &order, nil),
		recordingStep("shared", &order, errors.New("closed")),
	}

	if err := applyReversibleSteps(steps); err == nil {
		t.Fatal("a failing transaction reported success")
	}
	want := []string{"apply:TC", "apply:cgroup", "apply:shared", "revert:cgroup", "revert:TC"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v", order, want)
	}
}

// A revert that fails must not swallow the failure that caused it: the first
// error is what explains the outage.
func TestApplyReversibleStepsKeepsTheCauseWhenRevertFails(t *testing.T) {
	cause := errors.New("map is full")
	revertFailure := errors.New("backend closed")
	steps := []reversibleStep{
		{
			name:   "TC",
			apply:  func() error { return nil },
			revert: func() error { return revertFailure },
		},
		{
			name:   "cgroup",
			apply:  func() error { return cause },
			revert: func() error { return nil },
		},
	}

	err := applyReversibleSteps(steps)
	if !errors.Is(err, cause) {
		t.Fatalf("original cause was lost: %v", err)
	}
	if !errors.Is(err, revertFailure) {
		t.Fatalf("failed revert was not reported: %v", err)
	}
}
