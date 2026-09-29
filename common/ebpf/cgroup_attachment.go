//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"os"
	"strings"

	E "github.com/metacubex/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// lockCgroupFile takes the exclusive lock that marks this cgroup as managed
// here.
//
// A lock that is already held is still reported as EBUSY, so callers matching
// on it keep working, but it is described for what is known rather than what is
// likely. The holder may be another running instance, and it may equally be a
// handle this process itself has not let go of, because a close that could not
// detach every program keeps the cgroup open. Naming only the first would send
// the reader looking for a second process that need not exist.
func lockCgroupFile(cgroupFile *os.File) error {
	err := unix.Flock(int(cgroupFile.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) {
		return E.Cause(unix.EBUSY,
			"the exclusive lock on this cgroup is already held, "+
				"either by another active instance or by an earlier close that did not finish: ",
			"lock cgroup")
	}
	return eBPFOperationError("lock cgroup", err)
}

func detachOwnedCgroupPrograms(cgroupFD int) error {
	for _, definition := range cgroupProgramDefinitions {
		first, err := queryCgroupProgramIDs(cgroupFD, definition.attachType)
		if err != nil {
			if definition.attachType == CiliumEBPF.AttachCgroupInetSockRelease && socketReleaseUnavailable(err) {
				continue
			}
			return err
		}
		second, err := queryCgroupProgramIDs(cgroupFD, definition.attachType)
		if err != nil {
			return err
		}
		if !sameProgramIDs(first, second) {
			return unix.ESTALE
		}
		for _, programID := range first {
			program, openErr := CiliumEBPF.NewProgramFromID(programID)
			if openErr != nil {
				return openErr
			}
			info, infoErr := program.Info()
			if infoErr != nil {
				_ = program.Close()
				return infoErr
			}
			if strings.HasPrefix(info.Name, "sb_ebpf_") {
				if detachErr := rawDetachProgram(cgroupFD, program, definition.attachType); detachErr != nil {
					_ = program.Close()
					return detachErr
				}
			}
			if closeErr := program.Close(); closeErr != nil {
				return closeErr
			}
		}
	}
	return nil
}

func queryCgroupProgramIDs(cgroupFD int, attachType CiliumEBPF.AttachType) ([]CiliumEBPF.ProgramID, error) {
	result, err := link.QueryPrograms(link.QueryOptions{Target: cgroupFD, Attach: attachType})
	if err != nil {
		return nil, err
	}
	ids := make([]CiliumEBPF.ProgramID, len(result.Programs))
	for index := range result.Programs {
		ids[index] = result.Programs[index].ID
	}
	return ids, nil
}

func (b *CgroupBackend) Attach() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	attachOrder := make([]int, 0, cgroupProgramCount)
	if b.runtime.programs[cgroupProgramSocketRelease] != nil {
		attachOrder = append(attachOrder, cgroupProgramSocketRelease)
	}
	for slot := range b.runtime.programs {
		if slot != cgroupProgramSocketRelease {
			attachOrder = append(attachOrder, slot)
		}
	}
	for _, slot := range attachOrder {
		program := b.runtime.programs[slot]
		if program == nil {
			continue
		}
		programLink, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  cgroupFD,
			Program: program,
			Attach:  cgroupProgramDefinitions[slot].attachType,
		})
		if err == nil {
			b.runtime.links[slot] = programLink
		} else if cgroupLinkUnavailable(err) {
			b.runtime.displaced[slot], err = attachCgroupProgramRaw(cgroupFD, program, cgroupProgramDefinitions[slot].attachType)
		}
		if err != nil {
			_ = b.detachProgramsLocked()
			return eBPFBackendOperationError("attach eBPF inbound", cgroupProgramDefinitions[slot].name, err)
		}
		b.runtime.attached[slot] = true
	}
	if b.runtime.enable_udp && b.runtime.socket_release_supported &&
		!b.runtime.attached[cgroupProgramSocketRelease] {
		_ = b.detachProgramsLocked()
		return eBPFOperationError("attach eBPF inbound UDP cleanup", unix.EINVAL)
	}
	return nil
}

func cgroupLinkUnavailable(err error) bool {
	return errors.Is(err, link.ErrNotSupported) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, linuxErrnoNotSupported)
}

func (b *CgroupBackend) detachProgramsLocked() error {
	if b.runtime == nil || b.runtime.cgroupFile == nil {
		return nil
	}
	cgroupFD := int(b.runtime.cgroupFile.Fd())
	var detachErr error
	for slot := cgroupProgramCount - 1; slot >= 0; slot-- {
		if !b.runtime.attached[slot] {
			continue
		}
		programLink := b.runtime.links[slot]
		var err error
		if programLink != nil {
			err = programLink.Close()
			b.runtime.links[slot] = nil
			b.runtime.attached[slot] = false
			if err != nil {
				detachErr = E.Errors(detachErr, err)
			}
			continue
		} else if displaced := b.runtime.displaced[slot]; displaced != nil {
			err = restoreDisplacedCgroupProgram(cgroupFD, b.runtime.programs[slot], displaced, cgroupProgramDefinitions[slot].attachType)
		} else {
			err = rawDetachProgram(cgroupFD, b.runtime.programs[slot], cgroupProgramDefinitions[slot].attachType)
		}
		if err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			b.runtime.attached[slot] = false
			if displaced := b.runtime.displaced[slot]; displaced != nil {
				_ = displaced.Close()
				b.runtime.displaced[slot] = nil
			}
			continue
		}
		detachErr = E.Errors(detachErr, err)
	}
	return detachErr
}

// attachCgroupProgramRaw attaches program next to whatever holds the hook and,
// failing that, in its place. It is the fallback for kernels that refuse
// BPF_LINK_CREATE, and the in-place attach replaces a program another owner
// attached exclusively: on Android 15 and later netd holds connect, sendmsg and
// recvmsg on the cgroup v2 root that way, and nothing else can attach there
// alongside it. Detaching ours afterwards used to leave that hook empty until
// its owner attached again, typically at the next boot. So before replacing,
// this takes a reference to the program being displaced and returns it, and
// detach puts it back. If the reference cannot be taken, the attach goes ahead
// as it did before, only without the restore.
func attachCgroupProgramRaw(cgroupFD int, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) (*CiliumEBPF.Program, error) {
	err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  cgroupFD,
		Program: program,
		Attach:  attachType,
		Flags:   unix.BPF_F_ALLOW_MULTI,
	})
	if err == nil {
		return nil, nil
	}
	var displaced *CiliumEBPF.Program
	// An exclusive attachment is the only kind the in-place attach can replace,
	// and it holds exactly one program.
	if ids, queryErr := queryCgroupProgramIDs(cgroupFD, attachType); queryErr == nil && len(ids) == 1 {
		displaced, _ = CiliumEBPF.NewProgramFromID(ids[0])
	}
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  cgroupFD,
		Program: program,
		Attach:  attachType,
	})
	if err != nil {
		if displaced != nil {
			_ = displaced.Close()
		}
		return nil, err
	}
	return displaced, nil
}

// restoreDisplacedCgroupProgram hands the hook back to the program ours
// displaced. Attaching it exclusively replaces ours in one step, so the hook is
// never left empty in between. If the kernel refuses, ours is detached anyway:
// the hook ends up empty, which is what detaching did before the restore
// existed.
func restoreDisplacedCgroupProgram(cgroupFD int, program, displaced *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) error {
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  cgroupFD,
		Program: displaced,
		Attach:  attachType,
	}); err == nil {
		return nil
	}
	return rawDetachProgram(cgroupFD, program, attachType)
}

// DisplacedHooks names the hooks where attaching replaced a program another
// owner had attached exclusively, with that program's name. Each is put back
// when the backend detaches.
func (b *CgroupBackend) DisplacedHooks() []string {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return nil
	}
	var hooks []string
	for slot, displaced := range b.runtime.displaced {
		if displaced == nil {
			continue
		}
		name := "unnamed"
		if info, err := displaced.Info(); err == nil && info.Name != "" {
			name = info.Name
		}
		hooks = append(hooks, cgroupProgramDefinitions[slot].attachType.String()+" ("+name+")")
	}
	return hooks
}
