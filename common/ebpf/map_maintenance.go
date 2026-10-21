//go:build with_ebpf && (linux || android)

package ebpf

import (
	"cmp"
	"slices"
	"sync"
	"time"
)

// MapMaintenance reports work already performed by bounded maintenance.
// Reading it never starts a map traversal or holds a data-plane lock.
type MapMaintenance struct {
	Name       string    `json:"name"`
	Capacity   uint32    `json:"capacity"`
	Entries    uint32    `json:"entries"`
	UsageKnown bool      `json:"usage_known"`
	Complete   bool      `json:"complete"`
	Passes     uint64    `json:"passes"`
	Scanned    uint64    `json:"scanned"`
	Retired    uint64    `json:"retired"`
	Removed    uint64    `json:"removed"`
	Failures   uint64    `json:"failures"`
	LastError  string    `json:"last_error,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type mapMaintenanceState struct {
	access sync.Mutex
	maps   map[string]MapMaintenance
}

func (s *mapMaintenanceState) record(name string, capacity uint32, scan mapScanResult, removed uint32, entries uint32, known bool, err error) {
	s.access.Lock()
	defer s.access.Unlock()
	if s.maps == nil {
		s.maps = make(map[string]MapMaintenance)
	}
	m := s.maps[name]
	m.Name, m.Capacity = name, capacity
	m.Passes++
	m.Scanned += uint64(scan.Scanned)
	m.Removed += uint64(removed)
	m.Complete = scan.Complete && err == nil
	m.UsageKnown = known && err == nil
	if m.UsageKnown {
		m.Entries = entries
	}
	m.LastError = ""
	if err != nil {
		m.Failures++
		m.LastError = err.Error()
	}
	m.UpdatedAt = time.Now()
	s.maps[name] = m
}

func (s *mapMaintenanceState) snapshot() []MapMaintenance {
	s.access.Lock()
	defer s.access.Unlock()
	result := make([]MapMaintenance, 0, len(s.maps))
	for _, m := range s.maps {
		result = append(result, m)
	}
	slices.SortFunc(result, func(a, b MapMaintenance) int { return cmp.Compare(a.Name, b.Name) })
	return result
}

func (b *TCBackend) MapMaintenance() []MapMaintenance {
	if b == nil {
		return nil
	}
	return b.maintenance.snapshot()
}
func (b *CgroupBackend) MapMaintenance() []MapMaintenance {
	if b == nil {
		return nil
	}
	return b.maintenance.snapshot()
}
func (b *SharedNetworkBackend) MapMaintenance() []MapMaintenance {
	if b == nil {
		return nil
	}
	return b.maintenance.snapshot()
}

func (s *mapMaintenanceState) recordRetired(name string, count uint32) {
	if count == 0 {
		return
	}
	s.access.Lock()
	defer s.access.Unlock()
	m := s.maps[name]
	m.Retired += uint64(count)
	s.maps[name] = m
}
