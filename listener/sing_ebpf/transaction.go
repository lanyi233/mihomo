//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"slices"

	E "github.com/metacubex/sing/common/exceptions"
)

// reversibleStep is one write in a change that has to land everywhere or
// nowhere, paired with how to put back what it replaced.
type reversibleStep struct {
	// name completes the phrases "apply <name>" and "restore <name>". Where a
	// step corresponds to one config key, that key is the clearest thing to
	// name -- "apply bypass_rule_set" points the reader at what they edited.
	// Otherwise a noun naming the plane and the decision: "TC bypass policy".
	name   string
	apply  func() error
	revert func() error
}

// applyReversibleSteps performs every step, or none of them.
//
// The data planes hold separate copies of the same decisions -- what to
// bypass, how long a UDP session lives -- and nothing reconciles them
// afterwards. Applying in sequence and returning at the first error is what
// leaves them disagreeing: TC proxying a CIDR cgroup lets past, or one plane
// expiring sessions on a timeout the others never got. Silently, and for good,
// since a rule set that does not change again is never revisited.
//
// Not every multi-plane write belongs here. Rolling back is right when the
// planes must agree and nothing will ever ask again -- a rule set that does not
// change again is the case this was written for. Where the desired end state is
// every plane on the NEW value and a driver exists that can keep asking, the
// answer is to converge instead: rolling back moves away from the goal. The
// fake-ip range push is that case, and fakeip.go says so at the point it
// diverges.
//
// A revert that itself fails is reported alongside the original error rather
// than replacing it: the cause of the outage is the first failure. Where the
// step writes a multi-entry policy map, the backend also marks itself as
// needing a rebuild, which the retry scheduler reads to stop retrying it; a
// step that writes a single control record has no partial state to leave
// behind, so restoring its own field is all the rollback there is.
func applyReversibleSteps(steps []reversibleStep) error {
	var applied []reversibleStep
	for _, step := range steps {
		if err := step.apply(); err != nil {
			err = E.Cause(err, "apply ", step.name)
			for _, undo := range slices.Backward(applied) {
				if undoErr := undo.revert(); undoErr != nil {
					err = E.Errors(err, E.Cause(undoErr, "restore ", undo.name))
				}
			}
			return err
		}
		applied = append(applied, step)
	}
	return nil
}
