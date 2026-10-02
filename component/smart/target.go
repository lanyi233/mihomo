package smart

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Thresholds for a rule set whose name follows no convention, which is what a user
// defined provider name looks like. Calibrated on a real setup: collections at
// 111030 / 27055 / 4367 entries, the largest service catalog at 1792. The ASN limit
// stays above what a real service spans once shared networks are excluded (github 1,
// apple and netflix around 2), a promoted service would be split into several exits.
const (
	BroadRuleCount    = 10000
	BroadASNDiversity = 6

	// asnEvidencePrefix marks the per target network counters kept in StatsRecord.Weights,
	// they carry no weight and are claim evidence only

	ASNClaimMinKinds  = 2   // networks a service must span to claim without repeats
	ASNClaimMinHits   = 4   // successes a single network service needs before it claims
	ASNClaimAmbiguous = "-" // network two services were seen on, never used as key
)

// SharedASNs are networks that rent addresses to unrelated parties, so the ASN does
// not identify a single service and must not be used as a service key.
var SharedASNs = map[string]bool{
	"13335":  true,
	"12222":  true,
	"16625":  true,
	"20940":  true,
	"31110":  true,
	"35994":  true,
	"54113":  true,
	"22822":  true,
	"15133":  true,
	"19551":  true,
	"20446":  true,
	"5065":   true,
	"60068":  true,
	"16509":  true,
	"36408":  true,
	"4809":   true,
	"4847":   true,
	"199524": true,
	"212238": true,
	"55933":  true,
	"43260":  true,
	"43317":  true,
	"43996":  true,
	"33438":  true,
	"396982": true,
	"16276":  true,
	"30081":  true,
	"12389":  true,
	"37888":  true,
	"45090":  true,
	"207143": true,
	"14061":  true,
	"24940":  true,
	"31898":  true,
	"36351":  true,
	"14618":  true,
	"45102":  true,
	"132203": true,
	"55990":  true,
	"12876":  true,
	"51167":  true,
	"197540": true,
	"20473":  true,
	"63949":  true,
	"9009":   true,
	"60781":  true,
	"36236":  true,
	"39572":  true,
	"400618": true,
	"4134":   true,
	"4808":   true,
	"4837":   true,
}

// broadSetNames are meta-rules-dat entries that collect unrelated services; an
// "@<scope>" suffix only marks the scope of the same entry.
var broadSetNames = map[string]bool{
	"cn":           true,
	"private":      true,
	"gfw":          true,
	"greatfire":    true,
	"ads-all":      true,
	"oc-cn-domain": true,
	"china-domain": true,
	"china-ip":     true,
	"tor":          true,
}

var broadNamePrefixes = []string{"category-", "geolocation-", "tld-"}

// sharedGeoIPPayloads are geoip entries of shared or non routable address space.
var sharedGeoIPPayloads = map[string]bool{
	"cloudflare": true,
	"cloudfront": true,
	"fastly":     true,
	"private":    true,
}

// TargetKind classifies a target string: a collection of unrelated services, a
// single service, or a rule entry name that only the counts can tell apart.
type TargetKind int

const (
	TargetKindNoRule   TargetKind = iota // no rule identity, the fallback target
	TargetKindRuleName                   // rule set / geosite / geoip name, which may be provider defined
	TargetKindService                    // the rule type itself is narrow
	TargetKindBroad                      // collection of unrelated services, e.g. a region
)

// ClassifyTargetName classifies a target by naming conventions. A name that matches
// no convention is a rule name, NeedsASNKey decides it from counts and diversity.
func ClassifyTargetName(target string) TargetKind {
	kind, payload, ok := splitTarget(target)
	if !ok {
		return TargetKindNoRule
	}

	name, _, _ := strings.Cut(strings.ToLower(payload), "@")

	switch kind {
	case "GeoIP", "SrcGeoIP":
		if isCountryCode(name) || sharedGeoIPPayloads[name] || broadSetNames[name] {
			return TargetKindBroad
		}
		return TargetKindRuleName
	case "RuleSet", "GeoSite":
		if broadSetNames[name] {
			return TargetKindBroad
		}
		for _, prefix := range broadNamePrefixes {
			if strings.HasPrefix(name, prefix) {
				return TargetKindBroad
			}
		}
		if asn, ok := asnRuleSetName(name); ok && SharedASNs[asn] {
			return TargetKindBroad
		}
		return TargetKindRuleName
	default:
		return TargetKindService
	}
}

// NeedsASNKey reports whether the ASN has to replace the target as key: always for a
// collection or a target without rule identity, and for a provider defined name only
// once its entry count or its number of unrelated networks proves it is a collection.
func NeedsASNKey(target string, ruleCount, asnDiversity int) bool {
	switch ClassifyTargetName(target) {
	case TargetKindBroad, TargetKindNoRule:
		return true
	case TargetKindService:
		return false
	}
	if ruleCount >= BroadRuleCount {
		return true
	}
	return asnDiversity >= BroadASNDiversity
}

// RuleSetPayload returns the provider payload of a rule set target, the name its
// entry count is looked up with.
func RuleSetPayload(target string) (string, bool) {
	kind, payload, ok := splitTarget(target)
	if !ok {
		return "", false
	}
	switch kind {
	case "RuleSet", "GeoSite":
		return payload, true
	}
	return "", false
}

func splitTarget(target string) (kind, payload string, ok bool) {
	if target == "" {
		return "", "", false
	}
	open := strings.LastIndex(target, " [")
	if open <= 0 || !strings.HasSuffix(target, "]") {
		return "", "", false
	}
	payload = target[open+2 : len(target)-1]
	if payload == "" {
		return "", "", false
	}
	return target[:open], payload, true
}

// IsRuleTarget reports whether a target carries rule identity (rule name or rule set).
func IsRuleTarget(target string) bool {
	_, _, ok := splitTarget(target)
	return ok
}

func asnRuleSetName(name string) (string, bool) {
	if len(name) < 3 || name[0] != 'a' || name[1] != 's' {
		return "", false
	}
	digits := name[2:]
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return "", false
		}
	}
	return digits, true
}

// SmartTargetKey folds a target into a service key when the group runs with prefer-asn. A
// service rule keeps its rule string and a rule set covers every ASN it is served from,
// otherwise the key is the ASN, or the site for a shared or unknown network.
func SmartTargetKey(preferASN bool, asn, target, wildcardTarget, site string, needsASNKey bool) string {
	if target == "" {
		target = wildcardTarget
	}
	if target == "" {
		return ""
	}
	if !preferASN {
		return target
	}
	if !needsASNKey {
		return target
	}
	if site != "" {
		return site
	}
	if asn != "" && !SharedASNs[asn] {
		return asn
	}
	if wildcardTarget != "" {
		return wildcardTarget
	}
	return target
}

func isCountryCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// ClaimedASNRules maps every network to the service rule that owns it, from the
// evidence collected per target. A network that two services were seen on is
// reported as ambiguous, so it is never keyed to either of them.
func ClaimedASNRules(evidence map[string]map[string]int) map[string]string {
	type claim struct {
		rule string
		hits int
	}

	claims := make(map[string]claim)

	for target, asns := range evidence {
		if ClassifyTargetName(target) != TargetKindRuleName {
			continue
		}
		singleNetwork := len(asns) < ASNClaimMinKinds
		for asn, hits := range asns {
			if singleNetwork && hits < ASNClaimMinHits {
				continue
			}
			switch existing, ok := claims[asn]; {
			case !ok:
				claims[asn] = claim{rule: target, hits: hits}
			case existing.rule == ASNClaimAmbiguous:
			case existing.rule != target:
				claims[asn] = claim{rule: ASNClaimAmbiguous, hits: existing.hits}
			case hits > existing.hits:
				claims[asn] = claim{rule: target, hits: hits}
			}
		}
	}

	result := make(map[string]string, len(claims))
	for asn, c := range claims {
		result[asn] = c.rule
	}
	return result
}

func isHexRandom(s string) bool {
	if len(s) < 8 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isValidLabel(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

// GetEffectiveTarget folds a host into the wildcard key its records are kept under.
func GetEffectiveTarget(host string, dstIP string) string {
	if host == "" {
		return dstIP
	}

	h := strings.ToLower(host)

	// the wildcard of a host never changes, a cached one needs no rewrite
	if targetCache != nil {
		if cached, _, ok := targetCache.GetWithExpire(h); ok && (strings.HasPrefix(cached, "*.") || cached == h) {
			return cached
		}
	}

	compute := func() string {
		reg := ""
		if !strings.HasPrefix(h, ".") && !strings.HasSuffix(h, ".") && !strings.Contains(h, "..") {
			suffix, _ := publicsuffix.PublicSuffix(h)
			if len(h) > len(suffix) {
				if cut := len(h) - len(suffix) - 1; h[cut] == '.' {
					reg = h[1+strings.LastIndexByte(h[:cut], '.'):]
				}
			}
		}
		if reg == "" || reg == h || !(h == reg || strings.HasSuffix(h, "."+reg)) {
			lastDot := strings.LastIndexByte(h, '.')
			if lastDot < 0 {
				return h
			}
			reg = h[strings.LastIndexByte(h[:lastDot], '.')+1:]
		}

		var sub string
		if h == reg {
			sub = ""
		} else {
			sub = strings.TrimSuffix(h, "."+reg)
		}

		if sub == "" {
			return reg
		}

		last := sub
		if dot := strings.LastIndexByte(sub, '.'); dot >= 0 {
			last = sub[dot+1:]
		}

		if strings.Contains(last, "-") {
			last = "*"
		} else if isHexRandom(last) {
			last = "*"
		} else {
			letters := 0
			digits := 0
			for _, r := range last {
				if r >= 'a' && r <= 'z' {
					letters++
				} else if r >= '0' && r <= '9' {
					digits++
				}
			}
			if letters > 0 && digits > 0 {
				if len(last) > 10 || (digits > 0 && float64(digits)/float64(len(last)) > 0.6) {
					last = "*"
				}
			}
		}

		if !isValidLabel(last) || strings.HasPrefix(last, "-") || strings.HasSuffix(last, "-") {
			last = "*"
		}

		if strings.IndexByte(sub, '.') < 0 || last == "*" {
			return "*." + reg
		}

		return "*." + last + "." + reg
	}

	result := compute()
	if targetCache == nil || result == "" {
		return result
	}

	if strings.HasPrefix(result, "*.") {
		targetCache.Set(h, result)
		return result
	}

	if result == h && strings.Count(h, ".") == 1 {
		wildcard := "*." + h
		targetCache.Set(h, wildcard)
		return wildcard
	}

	targetCache.Set(h, result)
	return result
}
