package outboundgroup

import (
	"testing"

	"github.com/metacubex/mihomo/component/smart"

	"github.com/stretchr/testify/require"
)

// Claims are rebuilt from evidence that ages out, so a rebuild that finds none
// has to clear what the last one left, not keep it.
func TestClaimsWithNoEvidenceLeftAreCleared(t *testing.T) {
	smart.InitCache()
	smart.InitQueue()
	s := sweepGroup("claims-group")
	s.configName = "config"
	s.store = &smart.Store{}
	s.preferASN = true
	s.asnRule.Store("64512", "RuleSet [stale]")
	_, seeded := s.asnRule.Load("64512")
	require.True(t, seeded, "fixture did not seed the claim")

	s.claimASNEvidence()

	_, ok := s.asnRule.Load("64512")
	require.False(t, ok, "a claim outlived its evidence")
}

// Diversity only decides a provider-defined rule name, so it must not be
// tracked for anything else: a set per domain would grow for as long as the
// group lives.
func TestASNDiversityIsOnlyTrackedForRuleNames(t *testing.T) {
	s := sweepGroup("diversity-group")

	s.needsASNKey("www.example.com", "64512")
	require.Zero(t, s.asnDiversity.Size(), "a domain target was tracked")

	const ruleName = "RuleSet [example-video]"
	require.Equal(t, smart.TargetKindRuleName, smart.ClassifyTargetName(ruleName))
	s.needsASNKey(ruleName, "64512")
	require.Equal(t, 1, s.asnDiversity.Size())
}
