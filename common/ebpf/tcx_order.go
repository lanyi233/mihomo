//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"os"
	"slices"
	"strings"

	E "github.com/metacubex/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// A TCX hook runs its programs in the order of one kernel list, which several
// sing-ebpf instances and foreign programs share. Every sing-ebpf program put
// on such a list carries its runtime's TC priority in a one-entry array map
// bound to it with BPF_PROG_BIND_MAP, which every kernel with TCX supports. A
// later instance reads those markers back through the program's map IDs and
// inserts itself before the first sing-ebpf program with a larger priority, so
// lower priorities run first, as tc filter priorities do, and equal priorities
// keep their attach order. Programs without a marker, foreign ones or those of
// older builds, do not constrain the position.
//
// The marker is bound before the attach, so a sing-ebpf program is never on a
// hook without one, and the attach names the hook revision it was computed
// from: a concurrent change makes it fail with ESTALE and the position is
// computed again.
const tcxPriorityMarkerName = "sb_tcx_prio"

// tcxOrderAttempts bounds the retries of a hook that keeps changing between
// the query and the attach.
const tcxOrderAttempts = 16

// kernelProgramPrefix is shared by every program name in program_name.go.
const kernelProgramPrefix = "sb_"

// ErrTCXOrderUnavailable reports that the priority order of a TCX hook could
// not be read or recorded, typically because opening programs and maps by ID
// needs CAP_SYS_ADMIN. Callers fall back to clsact, whose filter priority the
// kernel orders itself.
var ErrTCXOrderUnavailable = errors.New("TCX program order is unavailable")

// Seams for tests that exercise ordering without a TCX kernel.
var (
	queryTCXPrograms = link.QueryPrograms
	attachTCX        = link.AttachTCX
	tcxProgramOrder  = tcxProgramPriority
)

// AttachTCXOrdered attaches program to the interface's TCX hook in priority
// order. On a kernel without TCX it returns the same unsupported error as
// link.AttachTCX, which callers use to select the clsact fallback.
func AttachTCXOrdered(interfaceIndex int, attachType CiliumEBPF.AttachType, program *CiliumEBPF.Program, priority uint16) (link.Link, error) {
	if program == nil {
		return nil, E.New("TCX program is unavailable")
	}
	markerReady := false
	for attempt := 1; ; attempt++ {
		result, queryErr := queryTCXPrograms(link.QueryOptions{Target: interfaceIndex, Attach: attachType})
		if queryErr != nil {
			// Querying the existing hook is required only for ordered TCX
			// insertion.  A permission failure while reading program IDs must
			// not turn a usable TCX kernel into a startup failure: callers can
			// preserve the priority contract through clsact instead.  Keep
			// explicit unsupported errors recognizable so they can update the
			// process-wide TCX capability cache.
			if errors.Is(queryErr, CiliumEBPF.ErrNotSupported) ||
				errors.Is(queryErr, unix.EOPNOTSUPP) || errors.Is(queryErr, unix.ENOSYS) ||
				errors.Is(queryErr, unix.EINVAL) {
				return nil, E.Errors(CiliumEBPF.ErrNotSupported, queryErr)
			}
			return nil, E.Errors(ErrTCXOrderUnavailable, E.Cause(queryErr, "query TCX programs"))
		}
		if !markerReady {
			if err := ensureTCXPriorityMarker(program, priority); err != nil {
				return nil, E.Errors(ErrTCXOrderUnavailable, E.Cause(err, "record TCX priority"))
			}
			markerReady = true
		}
		anchor, err := tcxPriorityAnchor(result.Programs, priority)
		if err != nil {
			return nil, E.Errors(ErrTCXOrderUnavailable, E.Cause(err, "read TCX priorities"))
		}
		attached, err := attachTCX(link.TCXOptions{
			Interface:        interfaceIndex,
			Program:          program,
			Attach:           attachType,
			Anchor:           anchor,
			ExpectedRevision: result.Revision,
		})
		if err == nil {
			return attached, nil
		}
		// ESTALE: the hook changed after the query. ENOENT: the anchor was
		// detached in the meantime.
		if attempt < tcxOrderAttempts && (errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOENT)) {
			continue
		}
		return nil, err
	}
}

func tcxPriorityAnchor(programs []link.AttachedProgram, priority uint16) (link.Anchor, error) {
	for _, attached := range programs {
		other, marked, err := tcxProgramOrder(attached.ID)
		if err != nil {
			return nil, err
		}
		if !marked || other <= priority {
			continue
		}
		if linkID, linked := attached.LinkID(); linked {
			return link.BeforeLinkByID(linkID), nil
		}
		return link.BeforeProgramByID(attached.ID), nil
	}
	return link.Tail(), nil
}

// tcxObjectGone reports an object that was freed after its ID was listed.
func tcxObjectGone(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist)
}

// tcxProgramPriority reads the priority marker of an attached program. A
// program that went away reads as unmarked: the result only positions the
// next attach, and the revision check catches the change. A program or map
// that cannot be opened is an error, since its position is then unknown.
func tcxProgramPriority(id CiliumEBPF.ProgramID) (uint16, bool, error) {
	program, err := CiliumEBPF.NewProgramFromID(id)
	if err != nil {
		if tcxObjectGone(err) {
			return 0, false, nil
		}
		return 0, false, err
	}
	defer program.Close()
	info, err := program.Info()
	if err != nil {
		return 0, false, err
	}
	if !strings.HasPrefix(info.Name, kernelProgramPrefix) {
		return 0, false, nil
	}
	marker, err := findTCXPriorityMarker(info)
	if err != nil || marker == nil {
		return 0, false, err
	}
	defer marker.Close()
	var value uint32
	if err = marker.Lookup(uint32(0), &value); err != nil {
		return 0, false, err
	}
	if value > 0xffff {
		return 0, false, nil
	}
	return uint16(value), true, nil
}

// findTCXPriorityMarker returns the program's bound priority marker, or nil.
// A map that cannot be opened is an error rather than "no marker": binding a
// second marker would be permanent.
func findTCXPriorityMarker(info *CiliumEBPF.ProgramInfo) (*CiliumEBPF.Map, error) {
	ids, available := info.MapIDs()
	if !available {
		return nil, CiliumEBPF.ErrNotSupported
	}
	// BPF_PROG_BIND_MAP appends to the program's map list, so the marker is
	// normally the last entry.
	for _, id := range slices.Backward(ids) {
		candidate, err := CiliumEBPF.NewMapFromID(id)
		if err != nil {
			if tcxObjectGone(err) {
				continue
			}
			return nil, err
		}
		candidateInfo, err := candidate.Info()
		if err == nil && candidateInfo.Name == tcxPriorityMarkerName && candidateInfo.Type == CiliumEBPF.Array &&
			candidateInfo.KeySize == 4 && candidateInfo.ValueSize == 4 {
			return candidate, nil
		}
		_ = candidate.Close()
	}
	return nil, nil
}

// ensureTCXPriorityMarker binds a priority marker to program, or updates the
// one it already carries. A program belongs to one runtime, so the value only
// changes if that runtime is rebuilt with a different priority.
func ensureTCXPriorityMarker(program *CiliumEBPF.Program, priority uint16) error {
	info, err := program.Info()
	if err != nil {
		return err
	}
	marker, err := findTCXPriorityMarker(info)
	if err != nil {
		return err
	}
	if marker != nil {
		defer marker.Close()
		return marker.Put(uint32(0), uint32(priority))
	}
	marker, err = CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Name:       tcxPriorityMarkerName,
		Type:       CiliumEBPF.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		return err
	}
	// The binding keeps the map alive as long as the program; this descriptor
	// is only needed to fill and bind it.
	defer marker.Close()
	if err = marker.Put(uint32(0), uint32(priority)); err != nil {
		return err
	}
	return program.BindMap(marker)
}
