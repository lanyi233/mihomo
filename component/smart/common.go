package smart

import (
	"errors"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/bbolt"
	"github.com/metacubex/mihomo/log"

	"golang.org/x/net/publicsuffix"
)

const (
	OpSaveNodeState = iota
	OpSaveStats
	OpSavePrefetch
	OpSaveRanking
	OpSaveHostFailures
	OpDeleteData
)

const (
	KeyTypePrefetch     = "prefetch"
	KeyTypeNode         = "node"
	KeyTypeStats        = "stats"
	KeyTypeRanking      = "ranking"
	KeyTypeHostFailures = "failures"

	WeightTypeTCP = "tcp"
	WeightTypeUDP = "udp"
)

const (
	DefaultMinSampleCount = 2

	MaxTargetsLimit     = 5000
	MinTargetsLimit     = 500
	MaxBatchThreshLimit = 300
	MinBatchThreshLimit = 50
	maxScanPrealloc     = 4096

	RecordExpiredTime = 7 * 24 * time.Hour

	HostFailureNodeTTL       = 24 * time.Hour
	hostStatusRetryAfter     = 4 * time.Hour
	hostStatusViewTTLSeconds = 30

	probeMaxBlockTTL = 30 * time.Minute

	AllowedWeight = 0.4

	RankMostUsed   = "MostUsed"
	RankOccasional = "OccasionalUsed"
	RankRarelyUsed = "RarelyUsed"
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
	asnEvidencePrefix = "asn:"

	ASNClaimMinKinds  = 2   // networks a service must span to claim without repeats
	ASNClaimMinHits   = 4   // successes a single network service needs before it claims
	ASNClaimAmbiguous = "-" // network two services were seen on, never used as key
)

const (
	TargetKindNoRule   TargetKind = iota // no rule identity, the fallback target
	TargetKindRuleName                   // rule set / geosite / geoip name, which may be provider defined
	TargetKindService                    // the rule type itself is narrow
	TargetKindBroad                      // collection of unrelated services, e.g. a region
)

var (
	db               *bbolt.DB
	bucketSmartStats = []byte("smart_stats")

	globalOperationQueue operationQueue

	globalCacheParams struct {
		BatchSaveThreshold int
		MaxTargets         int
		LastMemoryUsage    float64
		mutex              sync.RWMutex
	}
)

// SharedASNs are networks that rent addresses to unrelated parties, so the ASN does
// not identify a single service and must not be used as a service key.
var SharedASNs = map[string]bool{
	"13335":  true, // Cloudflare
	"12222":  true, // Akamai
	"16625":  true, // Akamai
	"20940":  true, // Akamai
	"31110":  true, // Akamai
	"35994":  true, // Akamai
	"54113":  true, // Fastly
	"22822":  true, // Limelight Networks
	"15133":  true, // EdgeCast (Verizon)
	"19551":  true, // Incapsula (Imperva)
	"20446":  true, // StackPath
	"5065":   true, // BunnyCDN
	"60068":  true, // CDN77
	"16509":  true, // Amazon CloudFront
	"36408":  true, // CDNetworks
	"4809":   true, // ChinaCache
	"4847":   true, // ChinaNetCenter
	"199524": true, // Gcore
	"212238": true, // BelugaCDN
	"55933":  true, // QUANTIL
	"43260":  true, // Medianova
	"43317":  true, // CDNvideo
	"43996":  true, // CDNsun
	"33438":  true, // Edgio (Highwinds)
	"396982": true, // Google Cloud Platform
	"16276":  true, // OVH
	"30081":  true, // CacheFly
	"12389":  true, // Zenlayer
	"37888":  true, // Alibaba CDN
	"45090":  true, // Tencent CDN
	"207143": true, // KeyCDN
	"14061":  true, // DigitalOcean
	"24940":  true, // Hetzner
	"31898":  true, // Oracle Cloud
	"36351":  true, // IBM Cloud (SoftLayer)
	"14618":  true, // Amazon AES (AWS)
	"45102":  true, // Alibaba Cloud
	"132203": true, // Tencent Cloud
	"55990":  true, // Huawei Cloud
	"12876":  true, // Scaleway
	"51167":  true, // Contabo
	"197540": true, // Netcup
	"20473":  true, // Vultr (Choopa)
	"63949":  true, // Linode
	"9009":   true, // Leaseweb
	"60781":  true, // Leaseweb NL
	"36236":  true, // NetActuate (anycast hosting)
	"39572":  true, // DataWeb Global Group (hosting)
	"400618": true, // Prime Security (JP IDC)
	"4134":   true, // China Telecom
	"4808":   true, // China Unicom
	"4837":   true, // China Unicom (China169)
}

// broadSetNames are meta-rules-dat entries that collect unrelated services; an
// "@<scope>" suffix only marks the scope of the same entry.
var broadSetNames = map[string]bool{
	"cn":           true,
	"private":      true,
	"gfw":          true,
	"greatfire":    true,
	"ads-all":      true,
	"oc-cn-domain": true, // OpenClash generated CN domain collection
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

type (
	Store struct{}

	StoreOperation struct {
		Type    int
		KeyType string // used by OpDeleteData to identify the target key type
		Group   string
		Config  string
		Target  string
		Node    string
		Data    []byte
	}
)

// TargetKind classifies a target string: a collection of unrelated services, a
// single service, or a rule entry name that only the counts can tell apart.
type TargetKind int

func NewStore(newdb *bbolt.DB) *Store {
	db = newdb
	InitCache()
	InitQueue()
	return &Store{}
}

// 格式化数据库键
func FormatDBKey(parts ...string) string {
	size := 5
	for _, part := range parts {
		if part != "" {
			size += 1 + len(part)
		}
	}
	var b strings.Builder
	b.Grow(size)
	b.WriteString("smart")
	for _, part := range parts {
		if part != "" {
			b.WriteByte('/')
			b.WriteString(part)
		}
	}
	return b.String()
}

func formatOperationKey(op *StoreOperation) string {
	switch op.Type {
	case OpSaveNodeState:
		return FormatDBKey(KeyTypeNode, op.Config, op.Group, op.Node)
	case OpSaveStats:
		return FormatDBKey(KeyTypeStats, op.Config, op.Group, op.Target, op.Node)
	case OpSavePrefetch:
		return FormatDBKey(KeyTypePrefetch, op.Config, op.Group, op.Target)
	case OpSaveRanking:
		return FormatDBKey(KeyTypeRanking, op.Config, op.Group)
	case OpSaveHostFailures:
		return FormatDBKey(KeyTypeHostFailures, op.Config, op.Group, op.Target)
	case OpDeleteData:
		kt := op.KeyType
		if kt == "" {
			if op.Target != "" {
				kt = KeyTypeHostFailures
			} else if op.Node != "" {
				kt = KeyTypeNode
			} else {
				kt = KeyTypeRanking
			}
		}
		switch kt {
		case KeyTypeNode:
			return FormatDBKey(KeyTypeNode, op.Config, op.Group, op.Node)
		case KeyTypeStats:
			return FormatDBKey(KeyTypeStats, op.Config, op.Group, op.Target, op.Node)
		case KeyTypePrefetch:
			return FormatDBKey(KeyTypePrefetch, op.Config, op.Group, op.Target)
		case KeyTypeRanking:
			return FormatDBKey(KeyTypeRanking, op.Config, op.Group)
		default:
			return FormatDBKey(KeyTypeHostFailures, op.Config, op.Group, op.Target)
		}
	default:
		return ""
	}
}

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

// 获取有效顶级域名加一二级域名并使用通配符处理
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

// 时间衰减
func GetTimeDecayWithCache(lastUsedTime int64, now int64, minDecay float64) float64 {
	fuzzyLastUsedTime := (lastUsedTime / 3600) * 3600

	hoursSinceLastConn := float64(now-fuzzyLastUsedTime) / 3600.0
	var decay float64

	switch {
	case hoursSinceLastConn <= 24:
		// 0-24小时：保持高权重
		decay = 1.0
	case hoursSinceLastConn <= 72:
		// 24-72小时：线性衰减到0.8
		decay = 1.0 - (hoursSinceLastConn-24.0)/48.0*0.2
	case hoursSinceLastConn <= 168: // 7天
		// 72-168小时：线性衰减到0.5
		decay = 0.8 - (hoursSinceLastConn-72.0)/96.0*0.3
	case hoursSinceLastConn <= 720: // 30天
		// 168-720小时：线性衰减到0.3
		decay = 0.5 - (hoursSinceLastConn-168.0)/552.0*0.2
	default:
		decay = 0.1
	}

	decay = math.Max(minDecay, decay)
	return decay
}

// 获取批量保存阈值
func GetBatchSaveThreshold() int {
	globalCacheParams.mutex.RLock()
	defer globalCacheParams.mutex.RUnlock()

	if globalCacheParams.BatchSaveThreshold <= 0 {
		return MinBatchThreshLimit
	}

	return globalCacheParams.BatchSaveThreshold
}

// 获取系统内存使用情况
//
// systemMemoryUsage is provided per platform; when it cannot read the system
// figures we fall back to a neutral 0.5 so cache sizing stays in its mid range.
func GetSystemMemoryUsage() float64 {
	if usage, ok := systemMemoryUsage(); ok {
		return usage
	}
	return 0.5
}

func readProcMemoryUsage(readFile func(string) ([]byte, error)) (float64, bool) {
	data, err := readFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}

	var totalKB, availableKB uint64
	var foundTotal, foundAvailable bool
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || (name != "MemTotal" && name != "MemAvailable") {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		memoryKB, parseErr := strconv.ParseUint(fields[0], 10, 64)
		if parseErr != nil {
			continue
		}
		if name == "MemTotal" {
			totalKB = memoryKB
			foundTotal = true
		} else {
			availableKB = memoryKB
			foundAvailable = true
		}
	}

	if !foundTotal || !foundAvailable || totalKB == 0 {
		return 0, false
	}
	if availableKB >= totalKB {
		return 0, true
	}
	return float64(totalKB-availableKB) / float64(totalKB), true
}

// operationQueue is the set of writes waiting to be flushed: a map for
// deduplication and a slice for order, so an append costs O(1).
//
// It was a slice inside an atomic value, rebuilt in full on every append -- a
// fresh map over every pending entry, a formatOperationKey (with its string
// build) for each, then a fresh slice. Filling the queue to its flush threshold
// therefore cost O(threshold^2) key formats and allocations, and
// AdjustCacheParameters raises that threshold when memory is free, so a machine
// with more RAM paid quadratically more for it. Under a burst of closes the CAS
// loop degenerated into a spin lock around an O(n) critical section.
//
// Deduplication stays. BatchSave would dedupe again at flush time, but dropping
// it here would make the threshold count raw appends instead of distinct keys,
// so the queue would flush more often -- and every flush is a bbolt commit with
// an fsync, which on the flash storage these run on is the expensive part.
type operationQueue struct {
	access   sync.Mutex
	position map[string]int
	ops      []StoreOperation
}

// add records the operations and returns a batch to flush when the queue has
// reached the threshold, or nil.
func (q *operationQueue) add(operations []StoreOperation) []StoreOperation {
	q.access.Lock()
	defer q.access.Unlock()
	for i := range operations {
		key := formatOperationKey(&operations[i])
		if key == "" {
			continue
		}
		if at, seen := q.position[key]; seen {
			// Last write wins, in the place the key already holds: there is
			// only ever one entry per key, so position carries no meaning
			// beyond keeping the flush order stable.
			q.ops[at] = operations[i]
			continue
		}
		if q.position == nil {
			q.position = make(map[string]int)
		}
		q.position[key] = len(q.ops)
		q.ops = append(q.ops, operations[i])
	}
	if len(q.ops) < GetBatchSaveThreshold() {
		return nil
	}
	return q.takeLocked()
}

// drain returns the pending batch, emptying the queue, when it has reached the
// threshold or the caller insists.
func (q *operationQueue) drain(force bool) []StoreOperation {
	q.access.Lock()
	defer q.access.Unlock()
	if len(q.ops) == 0 || (!force && len(q.ops) < GetBatchSaveThreshold()) {
		return nil
	}
	return q.takeLocked()
}

func (q *operationQueue) takeLocked() []StoreOperation {
	ops := q.ops
	q.ops = make([]StoreOperation, 0, GetBatchSaveThreshold())
	q.position = make(map[string]int, GetBatchSaveThreshold())
	return ops
}

// snapshot copies the pending operations, for readers that answer a query from
// the queue before it reaches the store.
func (q *operationQueue) snapshot() []StoreOperation {
	q.access.Lock()
	defer q.access.Unlock()
	return slices.Clone(q.ops)
}

// retain drops every operation the predicate rejects, rebuilding the index.
// Only the flood suppressor and config teardown do this, so the O(n) rebuild
// is not on any hot path.
func (q *operationQueue) retain(keep func(StoreOperation) bool) {
	q.access.Lock()
	defer q.access.Unlock()
	kept := make([]StoreOperation, 0, len(q.ops))
	position := make(map[string]int, len(q.ops))
	for _, op := range q.ops {
		if !keep(op) {
			continue
		}
		if key := formatOperationKey(&op); key != "" {
			position[key] = len(kept)
		}
		kept = append(kept, op)
	}
	q.ops = kept
	q.position = position
}

func (q *operationQueue) reset() {
	q.access.Lock()
	defer q.access.Unlock()
	q.takeLocked()
}

func (q *operationQueue) length() int {
	q.access.Lock()
	defer q.access.Unlock()
	return len(q.ops)
}

func InitQueue() {
	globalOperationQueue.reset()
}

func (s *Store) AppendToGlobalQueue(operations ...StoreOperation) {
	if len(operations) == 0 {
		return
	}
	snapshot := globalOperationQueue.add(operations)
	if len(snapshot) == 0 {
		return
	}
	go func() {
		if err := s.BatchSave(snapshot); err == nil {
			log.Debugln("[SmartStore] Queue datas saved, operations: [%d]", len(snapshot))
		}
	}()
}

func (s *Store) ClearFloodRecordsByGroup(group, config string) {
	globalOperationQueue.retain(func(op StoreOperation) bool {
		if op.Group == group && op.Config == config {
			switch op.Type {
			case OpSaveStats, OpSaveHostFailures, OpSaveNodeState:
				return false
			}
		}
		return true
	})

	blockedNodesCache.Delete(FormatDBKey(config, group))
	hostStatusCache.RemoveByKeyPrefix(FormatDBKey(KeyTypeHostFailures, config, group) + "/")
}

func removeNodesFromQueue(group, config string, nodes []string) {
	nodeSet := make(map[string]struct{}, len(nodes))
	for _, n := range nodes {
		nodeSet[n] = struct{}{}
	}
	globalOperationQueue.retain(func(op StoreOperation) bool {
		if op.Group == group && op.Config == config {
			_, dropped := nodeSet[op.Node]
			return !dropped
		}
		return true
	})
}

// 按级别刷新缓存
func (s *Store) FlushByLevel(level string, config string, group string) error {
	if level == "" {
		return errors.New("flush level cannot be empty")
	}

	if level == "all" {
		InitQueue()
	} else if level == "config" {
		globalOperationQueue.retain(func(op StoreOperation) bool { return op.Config != config })
	} else if level == "group" {
		globalOperationQueue.retain(func(op StoreOperation) bool {
			return op.Group != group || op.Config != config
		})
	}

	s.clearCache(level, config, group)

	if level == "all" {
		s.DBBatchDeletePrefix([]string{"smart"}, false)
	} else if level == "config" {
		s.DBBatchDeletePrefix([]string{
			FormatDBKey(KeyTypeStats, config),
			FormatDBKey(KeyTypeNode, config),
			FormatDBKey(KeyTypeRanking, config),
			FormatDBKey(KeyTypePrefetch, config),
			FormatDBKey(KeyTypeHostFailures, config),
		}, false)
	} else if level == "group" {
		s.DBBatchDeletePrefix([]string{
			FormatDBKey(KeyTypeStats, config, group),
			FormatDBKey(KeyTypeNode, config, group),
			FormatDBKey(KeyTypeRanking, config, group),
			FormatDBKey(KeyTypePrefetch, config, group),
			FormatDBKey(KeyTypeHostFailures, config, group),
		}, false)
	}

	return nil
}

// 清空所有缓存
func (s *Store) FlushAll() error {
	log.Debugln("[SmartStore] Starting FlushAll, current queue length: %d", globalOperationQueue.length())
	err := s.FlushByLevel("all", "", "")
	if err == nil {
		log.Debugln("[SmartStore] All Smart data cleared")
	}
	return err
}

// 按配置清空缓存
func (s *Store) FlushByConfig(config string) error {
	err := s.FlushByLevel("config", config, "")
	if err == nil {
		log.Debugln("[SmartStore] All data for config [%s] cleared", config)
	}
	return err
}

func (s *Store) FlushByGroup(group, config string) error {
	err := s.FlushByLevel("group", config, group)
	if err == nil {
		log.Debugln("[SmartStore] All data for group [%s] config [%s] cleared", group, config)
	}
	return err
}
