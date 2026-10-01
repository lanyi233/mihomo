//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"slices"

	LC "github.com/metacubex/mihomo/listener/config"

	E "github.com/metacubex/sing/common/exceptions"
)

// resolveEnableAliases folds local.enable / shared.enable, the spelling
// sing-box and the upstream eBPF listener use, into local.enabled /
// shared.enabled, which the rest of the option handling reads. Setting both
// spellings for one scope is allowed as long as they agree.
func resolveEnableAliases(options LC.EBPF) (LC.EBPF, error) {
	local, err := mergeEnableAlias("local", options.Local.Enable, options.Local.Enabled)
	if err != nil {
		return options, err
	}
	shared, err := mergeEnableAlias("shared", options.Shared.Enable, options.Shared.Enabled)
	if err != nil {
		return options, err
	}
	options.Local.Enable, options.Local.Enabled = nil, local
	options.Shared.Enable, options.Shared.Enabled = nil, shared
	return options, nil
}

func mergeEnableAlias(scope string, enable, enabled *bool) (*bool, error) {
	switch {
	case enable == nil:
		return enabled, nil
	case enabled == nil:
		return enable, nil
	case *enable != *enabled:
		return nil, E.New(scope, ".enable and ", scope, ".enabled disagree")
	default:
		return enabled, nil
	}
}

// effectiveBypassRuleSets resolves the rule sets each scope bypasses. The
// top-level bypass-rule-set applies to every data plane, as it always has;
// local.bypass-rule-set and shared.bypass-rule-set add to it for their own
// scope. A scope that is not enabled bypasses nothing.
func effectiveBypassRuleSets(options LC.EBPF, localEnabled, sharedEnabled bool) (local, shared []string) {
	if localEnabled {
		local = mergeRuleSetTags(options.BypassRuleSet, options.Local.BypassRuleSet)
	}
	if sharedEnabled {
		shared = mergeRuleSetTags(options.BypassRuleSet, options.Shared.BypassRuleSet)
	}
	return local, shared
}

// mergeRuleSetTags concatenates tag lists in order and drops repeats, so a tag
// listed both at the top level and for a scope counts once.
func mergeRuleSetTags(lists ...[]string) []string {
	var merged []string
	for _, list := range lists {
		for _, tag := range list {
			if !slices.Contains(merged, tag) {
				merged = append(merged, tag)
			}
		}
	}
	return merged
}

// bypassScopesSplit reports whether the two scopes need bypass tables of their
// own. That is only the case with both enabled and bypassing different rule
// sets; otherwise one policy serves every running data plane, exactly as it did
// before the scopes could differ.
func bypassScopesSplit(localEnabled, sharedEnabled bool, local, shared []string) bool {
	return localEnabled && sharedEnabled && !sameRuleSetTags(local, shared)
}

// sameRuleSetTags compares tag lists as sets: the order rule sets are listed
// in does not change what they bypass.
func sameRuleSetTags(left, right []string) bool {
	left, right = slices.Clone(left), slices.Clone(right)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}
