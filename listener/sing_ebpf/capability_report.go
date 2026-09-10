//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"strings"

	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/log"
)

// reportKernelCapabilities logs the eBPF features this kernel cannot provide.
//
// Every one of these degradations is already handled -- the inbound falls back
// and keeps working -- which is exactly the problem: nothing said so. A kernel
// older than 5.5 has no cgroup/sock_release, so the self-bypass and connected-UDP
// entries are never deleted on close and only the LRU reclaims them; a kernel
// older than 5.14 cannot lookup-and-delete a hash map, so the redirect sweeper
// declines to run at all; a kernel without TCX falls back to clsact filters.
// Both look identical to a healthy setup from the outside until state pressure
// starts costing flows. ProbeKernel already knew all of this and had no callers.
//
// Runs on its own goroutine: the probe loads and unloads throwaway programs,
// and startup should not wait on that.
func (i *Inbound) reportKernelCapabilities() {
	options := ECommon.KernelProbeOptions{
		Mode:                i.kernelProbeMode(),
		Network:             i.networkNames(),
		InterfaceNames:      append([]string(nil), i.sharedOptions.Interface...),
		EnableIPv6:          i.localIPv6 || i.sharedIPv6,
		NeedLPMPolicy:       i.needsLPMPolicy(),
		NeedProcessTracking: i.processTracker != nil,
	}
	if i.localEnabled {
		options.LocalDataPlane = ECommon.KernelProbeDataPlane(i.localDataPlane)
	}
	if i.sharedEnabled {
		options.SharedDataPlane = ECommon.KernelProbeDataPlane(i.sharedDataPlane)
	}
	go func() {
		report, err := ECommon.ProbeKernel(options)
		if err != nil {
			log.Debugln("[EBPF] kernel capability probe skipped: %s", err)
			return
		}
		var degraded []string
		for _, finding := range report.Findings {
			if finding.Status == ECommon.KernelProbePass {
				continue
			}
			// A required failure would already have stopped the inbound from
			// starting, so anything left here is a working-but-reduced path.
			degraded = append(degraded, finding.Scope+"/"+finding.Feature+": "+finding.Detail)
		}
		if len(degraded) == 0 {
			log.Debugln("[EBPF] kernel %s provides every probed capability", report.KernelRelease)
			return
		}
		// Do not summarise what the shortfall costs: the findings differ in kind.
		// A missing inet_sock_release slows reclamation, while a missing TCX
		// attach type changes how filters are installed. Each finding carries
		// its own consequence; print those.
		log.Warnln("[EBPF] kernel %s lacks %d optional capability(ies); the inbound is running on the fallback path for each:\n  - %s",
			report.KernelRelease, len(degraded), strings.Join(degraded, "\n  - "))
	}()
}

func (i *Inbound) kernelProbeMode() ECommon.KernelProbeMode {
	switch {
	case i.localEnabled && i.sharedEnabled:
		return ECommon.KernelProbeModeAll
	case i.sharedEnabled:
		return ECommon.KernelProbeModeShared
	default:
		return ECommon.KernelProbeModeLocal
	}
}

func (i *Inbound) networkNames() []string {
	var networks []string
	if i.enableTCP {
		networks = append(networks, "tcp")
	}
	if i.enableUDP {
		networks = append(networks, "udp")
	}
	return networks
}

// needsLPMPolicy reports whether any configured policy is backed by an LPM
// trie: bypass_rule_set, UID ranges, and shared source CIDRs. The probe uses
// it to decide whether the 6.6.0-6.6.46 LPM update defect matters here.
func (i *Inbound) needsLPMPolicy() bool {
	return len(i.bypassRuleSet) > 0 ||
		len(i.localPolicy.IncludeUID) > 0 || len(i.localPolicy.ExcludeUID) > 0 ||
		len(i.sharedOptions.IncludeSourceCIDR) > 0 || len(i.sharedOptions.ExcludeSourceCIDR) > 0
}
