//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

func TestMapOccupancyPolicyClassification(t *testing.T) {
	for _, name := range []string{"sb_cg_lforce4", "sb_sh_sforce6", "sb_sh_inc4", "sb_sh_exc6", "sb_cg_bypass_po", "sb_tc_lport"} {
		category := metadataForMapName(name).category
		if category != MapCategoryConfiguredPolicy {
			t.Errorf("%s category = %s", name, category)
		}
		if pressure := mapPressure(category, 1, 1, false); pressure != "configured" {
			t.Errorf("full policy %s pressure = %s", name, pressure)
		}
	}
	if pressure := mapPressure(MapCategoryRuntime, 95, 100, false); pressure != "degraded" {
		t.Fatalf("runtime pressure = %s", pressure)
	}
	if pressure := mapPressure(MapCategoryRuntime, 0, 100, true); pressure != "unavailable" {
		t.Fatalf("failed inspection pressure = %s", pressure)
	}
	for _, pressures := range [][]string{{"warning", "unavailable"}, {"unavailable", "warning"}, {"unavailable", "degraded"}} {
		maps := make([]MapOccupancy, len(pressures))
		for i, pressure := range pressures {
			maps[i].Pressure = pressure
		}
		want := "unknown"
		if pressures[len(pressures)-1] == "degraded" {
			want = "degraded"
		}
		if got := mapOccupancyStatus(maps); got != want {
			t.Errorf("%v status = %s, want %s", pressures, got, want)
		}
	}
}
