//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"testing"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
)

func TestFormatUIDRanges(t *testing.T) {
	for _, test := range []struct {
		name   string
		ranges []ECommon.UIDRange
		want   string
	}{
		{name: "empty", want: "[]"},
		{name: "single", ranges: []ECommon.UIDRange{{Start: 10335, End: 10335}}, want: "[10335]"},
		{name: "ranges", ranges: []ECommon.UIDRange{{Start: 1000, End: 1002}, {Start: 10335, End: 10335}}, want: "[1000-1002,10335]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := formatUIDRanges(test.ranges); got != test.want {
				t.Fatalf("formatUIDRanges() = %q, want %q", got, test.want)
			}
		})
	}
}
