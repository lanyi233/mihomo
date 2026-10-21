//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"cmp"
	"slices"
	"sync"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
)

var ebpfDiagnostics = struct {
	sync.RWMutex
	next     uint64
	inbounds map[*Inbound]uint64
}{inbounds: make(map[*Inbound]uint64)}

type InboundDiagnostics struct {
	ID              uint64                   `json:"id"`
	Mode            string                   `json:"mode"`
	LocalDataPlane  string                   `json:"local_data_plane"`
	SharedDataPlane string                   `json:"shared_data_plane"`
	SelfBypass      string                   `json:"self_bypass"`
	Maintenance     []ECommon.MapMaintenance `json:"maintenance"`
	Resources       ECommon.RuntimeState     `json:"resources"`
	ResourceError   string                   `json:"resource_error,omitempty"`
}

func (i *Inbound) registerDiagnostics() {
	ebpfDiagnostics.Lock()
	defer ebpfDiagnostics.Unlock()
	ebpfDiagnostics.next++
	ebpfDiagnostics.inbounds[i] = ebpfDiagnostics.next
}

func (i *Inbound) unregisterDiagnostics() {
	ebpfDiagnostics.Lock()
	defer ebpfDiagnostics.Unlock()
	delete(ebpfDiagnostics.inbounds, i)
}

// Diagnostics inspects only resources held by this process's active inbounds.
// It is explicitly requested by the controller; no worker counts map keys.
func Diagnostics() []InboundDiagnostics {
	ebpfDiagnostics.RLock()
	defer ebpfDiagnostics.RUnlock()
	result := make([]InboundDiagnostics, 0, len(ebpfDiagnostics.inbounds))
	for i, id := range ebpfDiagnostics.inbounds {
		d := InboundDiagnostics{ID: id, Mode: i.mode, LocalDataPlane: i.localDataPlane, SharedDataPlane: i.sharedDataPlane, SelfBypass: i.selfBypassMode()}
		owners := []ECommon.RuntimeResources{i.selfBypass.RuntimeResources(), i.processTracker.RuntimeResources()}
		if b := i.cgroupBackendInstance(); b != nil {
			owners = append(owners, b.RuntimeResources())
			d.Maintenance = append(d.Maintenance, b.MapMaintenance()...)
		}
		if b := i.tcBackend(); b != nil {
			owners = append(owners, b.RuntimeResources())
			d.Maintenance = append(d.Maintenance, b.MapMaintenance()...)
		}
		if i.sharedRewrite != nil {
			if b := i.sharedRewrite.sharedBackendInstance(); b != nil {
				owners = append(owners, b.RuntimeResources())
				d.Maintenance = append(d.Maintenance, b.MapMaintenance()...)
			}
		}
		d.Resources = ECommon.InspectRuntimeResources(owners...)
		if d.Resources.ProgramsError != nil {
			d.ResourceError = d.Resources.ProgramsError.Error()
		}
		result = append(result, d)
	}
	slices.SortFunc(result, func(a, b InboundDiagnostics) int { return cmp.Compare(a.ID, b.ID) })
	return result
}
