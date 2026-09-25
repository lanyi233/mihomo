package outboundgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/callback"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/singleflight"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/mmdb"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/smart"
	"github.com/metacubex/mihomo/component/smart/lightgbm"
	"github.com/metacubex/mihomo/component/smart/tcpstats"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
)

const (
	cleanupInterval          = 120 * time.Minute
	cacheParamAdjustInterval = 5 * time.Minute
	recoveryCheckInterval    = 10 * time.Minute
	hostStatusCheckInterval  = 30 * time.Minute
	checkInterval            = 10 * time.Minute
	prefetchInterval         = 15 * time.Minute
	flushQueueInterval       = 5 * time.Minute
	rankingInterval          = 5 * time.Minute

	maxRetries  = 5
	maxSelected = 10

	deterministicDialPrefix = 3
	parallelDials           = 5
	connectThreshold        = 5.0

	floodWindow    = 2 * time.Second
	floodThreshold = 50

	// How long a connection on a degraded node may wait for an answer to what
	// it sent before closeStalledConnections treats it as stuck.
	stalledReplyAfter = 10 * time.Second
	// How often the global sweep looks for connections stuck on a member that
	// new dials already avoid. One task for every group, so the cadence costs
	// one wake-up rather than one per group.
	stalledSweepInterval = 15 * time.Second

	// Blocking a (host, node) pair is a hard exclusion at dial time, not a
	// ranking penalty, and the store drops the pair on its own only after
	// HostFailureNodeTTL (24h). Recovery probing therefore has to get all the
	// way round the blocked set well inside that window: at 64 per tick a group
	// with 400 blocked pairs is fully swept in ~3h.
	hostRecoveryProbeBudget = 64
	// Must be at least one tick, otherwise a group used in short regular bursts
	// can land in the "wrong" half of every cycle and deterministically never
	// probe - the scheduler's jitter is computed once at start, so its phase is
	// fixed for the process lifetime.
	hostRecoveryActiveWindow = 2 * hostStatusCheckInterval
	hostRecoveryBackoffBase  = 2 * hostStatusCheckInterval
	// This is now the only thing spacing repeat probes of the same pair. The
	// store's own gate only withholds a pair for the first hostStatusRetryAfter
	// of its block: it was implemented by a failed probe resetting the deadline
	// to now+TTL, and a re-block no longer moves the deadline, precisely so a
	// host that fails every probe cannot stay blocked for good. Backing off
	// past a few hours only delays recovery, and this map is lost on restart --
	// after which the 64-per-tick budget is what bounds the catch-up.
	hostRecoveryBackoffMax = 4 * time.Hour
)

// A failed attempt downloads ASN.mmdb with a 90s timeout, and InitSmart runs
// inline on the config-parse path, so retries have to be spaced out: without
// this every smart group in the config would pay that timeout again on every
// reload.
const asnInitRetryAfter = 5 * time.Minute

var (
	asnInitAccess    sync.Mutex
	asnInitDone      bool
	asnInitLastTried time.Time
)

// initASNDatabase loads the ASN database once, but only latches on success. The
// usual failure is that the download could not run yet - no connectivity at
// boot is routine on mobile - and a later config reload has to be able to retry
// it. Latching on failure left prefer-asn silently degraded, with getASNCode
// returning "" for the rest of the process lifetime.
func initASNDatabase() {
	asnInitAccess.Lock()
	defer asnInitAccess.Unlock()
	if asnInitDone {
		return
	}
	if now := time.Now(); asnInitLastTried.IsZero() || now.Sub(asnInitLastTried) >= asnInitRetryAfter {
		asnInitLastTried = now
	} else {
		return
	}
	if err := geodata.InitASN(); err != nil {
		log.Warnln("[Smart] Failed to load ASN database: %v", err)
		return
	}
	asnInitDone = true
}

type SmartOption struct {
	PolicyPriority string  `group:"policy-priority,omitempty"`
	UseLightGBM    bool    `group:"uselightgbm,omitempty"`
	CollectData    bool    `group:"collectdata,omitempty"`
	SampleRate     float64 `group:"sample-rate,omitempty"`
	PreferASN      bool    `group:"prefer-asn,omitempty"`
	Tolerance      uint16  `group:"tolerance,omitempty"`
}

type Smart struct {
	*GroupBase
	store *smart.Store

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
	close  sync.Once
	global *smartGlobalTaskRun

	configName     string
	selected       string
	testUrl        string
	expectedStatus string
	disableUDP     bool

	weightModel    *lightgbm.WeightModel
	policyPriority []priorityRule
	priorityCache  xsync.Map[string, float64]
	sampleRate     float64
	useLightGBM    bool
	collectData    bool
	preferASN      bool
	hostFailLimit  atomic.Int32
	tolerance      uint16

	freshNodesGroup singleflight.Group[nodeResult]

	suppressStats atomic.Bool
	suppressCount atomic.Int64
	suppressLast  atomic.Int64

	workMu      sync.Mutex
	workWG      sync.WaitGroup
	workClosing bool

	lastTrafficActivity atomic.Int64
	recoveryCursor      atomic.Uint64
	recoveryMu          sync.Mutex
	recoveryBackoff     map[string]hostRecoveryState
}

type dialResult struct {
	proxyIndex  int
	conn        C.Conn
	connectTime int64
	error       error
}

type priorityRule struct {
	pattern string
	regex   *regexp2.Regexp
	factor  float64
	isRegex bool
}

type nodeWithWeight struct {
	node   string
	weight float64
}

type nodeResult struct {
	names   []string
	weights []float64
}

type hostRecoveryState struct {
	failures uint8
	next     time.Time
}

type hostRecoveryItem struct {
	wildcardTarget string
	nodeName       string
	host           string
	key            string
}

func getConfigFilename() string {
	configFile := C.Path.Config()
	baseName := filepath.Base(configFile)
	filename := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	return filename
}

func NewSmart(option GroupCommonOption, smartOption SmartOption, emptyFallback C.Proxy, providers []provider.ProxyProvider) (*Smart, error) {
	if option.URL == "" {
		option.URL = C.DefaultTestURL
	}

	configName := getConfigFilename()

	s := &Smart{
		GroupBase: NewGroupBase(GroupBaseOption{
			Name:             option.Name,
			Type:             C.Smart,
			Hidden:           option.Hidden,
			Icon:             option.Icon,
			Filter:           option.Filter,
			ExcludeFilter:    option.ExcludeFilter,
			ExcludeType:      option.ExcludeType,
			TestTimeout:      option.TestTimeout,
			MaxFailedTimes:   option.MaxFailedTimes,
			EmptyFallback:    emptyFallback,
			PreferUDP:        option.PreferUDP,
			PenalizeUnstable: option.PenalizeUnstable,
			PreferIPv6:       option.PreferIPv6,
			Providers:        providers,
		}),
		testUrl:        option.URL,
		expectedStatus: option.ExpectedStatus,
		configName:     configName,
		disableUDP:     option.DisableUDP,
		policyPriority: make([]priorityRule, 0),
		sampleRate:     1,
		useLightGBM:    smartOption.UseLightGBM,
		collectData:    smartOption.CollectData,
		preferASN:      smartOption.PreferASN,
		tolerance:      smartOption.Tolerance,
	}

	s.hostFailLimit.Store(int32(s.maxFailedTimes))

	if smartOption.SampleRate > 0 && smartOption.SampleRate <= 1 {
		s.sampleRate = smartOption.SampleRate
	}

	if smartOption.PolicyPriority != "" {
		applyPolicyPriority(s, smartOption.PolicyPriority)
	}

	s.InitSmart()

	return s, nil
}

func (s *Smart) GetConfigFilename() string {
	return s.configName
}

// ref: component/dialer/dialer.go:314
func (s *Smart) ParallelDialContext(ctx context.Context, proxies []C.Proxy, metadata *C.Metadata, start time.Time, singleDialFunc func(context.Context, C.Proxy, *C.Metadata, time.Time) (C.Conn, int64, error)) (C.Proxy, C.Conn, int64, error) {
	if len(proxies) == 1 {
		conn, connectTime, err := singleDialFunc(ctx, proxies[0], metadata, start)
		return proxies[0], conn, connectTime, err
	}

	n := len(proxies)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dialResult, n)

	for i := 0; i < n; i++ {
		go func(proxyIndex int) {
			conn, connectTime, err := singleDialFunc(childCtx, proxies[proxyIndex], metadata, start)
			results <- dialResult{
				proxyIndex:  proxyIndex,
				conn:        conn,
				connectTime: connectTime,
				error:       err,
			}
		}(i)
	}

	drainRemaining := func(pending int) {
		go func() {
			for i := 0; i < pending; i++ {
				if r := <-results; r.conn != nil && r.error == nil {
					_ = r.conn.Close()
				}
			}
		}()
	}

	errs := make([]error, 0, n)
	for received := 0; received < n; received++ {
		select {
		case res := <-results:
			if res.error == nil {
				cancel()
				drainRemaining(n - received - 1)
				return proxies[res.proxyIndex], res.conn, res.connectTime, nil
			}
			errs = append(errs, res.error)

		case <-ctx.Done():
			drainRemaining(n - received)
			return nil, nil, 0, ctx.Err()
		}
	}

	if len(errs) > 0 {
		return nil, nil, 0, errors.Join(errs...)
	}
	return nil, nil, 0, os.ErrDeadlineExceeded
}

func (s *Smart) singleDialContext(ctx context.Context, proxy C.Proxy, metadata *C.Metadata, start time.Time) (c C.Conn, connectTime int64, err error) {
	c, err = proxy.DialContext(ctx, metadata)
	connectTime = time.Since(start).Milliseconds()

	if err != nil {
		// err if ShouldStopRetry should not record as failed in node stats and stop retry
		if tunnel.ShouldStopRetry(err) {
			return nil, connectTime, err
		}
		if !errors.Is(err, context.Canceled) && ctx.Err() == nil {
			// metadata may be re-written by a later retry's selectProxies.
			s.submitConnectionStats(metadata.Clone(), proxy, connectTime, 0, 0, 0, 0, 0, 0, nil, err, false)
		}
		return nil, connectTime, err
	}

	return c, connectTime, nil
}

func (s *Smart) groupDialFailed(proxies []C.Proxy, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	for _, p := range proxies {
		t := p.Type()
		if t == C.Direct || t == C.Compatible || t == C.Reject || t == C.Pass || t == C.RejectDrop {
			continue
		}
		s.onDialFailed(t, err, s.healthCheck)
		return
	}
}

func smartDialBatchBounds(total, iteration int) (begin, end int) {
	if total <= 0 {
		return 0, 0
	}
	if total == 1 {
		return 0, 1
	}
	if iteration < deterministicDialPrefix {
		if iteration >= total {
			return 0, 0
		}
		return iteration, iteration + 1
	}
	begin = deterministicDialPrefix + (iteration-deterministicDialPrefix)*parallelDials
	if begin >= total {
		return 0, 0
	}
	end = begin + parallelDials
	if end > total {
		end = total
	}
	return begin, end
}

func (s *Smart) adoptUnwrapWinner(metadata *C.Metadata, asnNumber string, p C.Proxy) {
	target := metadata.SmartTarget
	wildcard := metadata.WildcardTarget
	existing, _ := s.store.GetUnwrapResult(s.Name(), s.configName, target, asnNumber, wildcard)

	// A new winner steers the dials that come after it, and nothing else. This
	// used to also close every connection in the bucket that was not on the
	// winner, and the bucket is keyed by the matched rule while the node a dial
	// lands on depends on per-destination blocks. Two destinations in one rule
	// that each exclude the other's node therefore closed each other's working
	// connections on every dial, for as long as the client kept reconnecting --
	// a Telegram DC set split across two nodes looped every few seconds
	// (liuran001/mihomo#2). A winner change says nothing against the node the
	// existing connections are on; the degrade path is what handles a node
	// that has actually stopped carrying traffic.
	switch {
	case len(existing) == 0:
		s.store.StoreUnwrapResult(s.Name(), s.configName, target, asnNumber, wildcard, []C.Proxy{p})
	case existing[0] == p.Name():
		// Unchanged: nothing to record.
	default:
		s.store.DeleteUnwrapResult(s.Name(), s.configName, target, asnNumber, wildcard)
		s.store.StoreUnwrapResult(s.Name(), s.configName, target, asnNumber, wildcard, []C.Proxy{p})
	}
}

func (s *Smart) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	s.markTrafficActivity()

	getBatch := func(proxies []C.Proxy, i int) ([]C.Proxy, time.Duration) {
		begin, end := smartDialBatchBounds(len(proxies), i)
		if begin == end {
			return nil, 0
		}

		batch := proxies[begin:end]
		var historyConnectTime int64
		var timeout time.Duration

		for _, p := range batch {
			hct := s.getHistoryConnectStats(metadata, p)
			if hct > historyConnectTime {
				historyConnectTime = hct
			}
		}

		if historyConnectTime > 0 {
			timeout = time.Duration(float64(historyConnectTime)*connectThreshold) * time.Millisecond
		}

		if timeout > C.DefaultTCPTimeout || timeout <= 0 {
			timeout = C.DefaultTCPTimeout
		}

		return batch, timeout
	}

	tryDial := func(proxies []C.Proxy, asnNumber string) (C.Conn, error) {
		var finalErr error
		for i := 0; i < maxRetries; i++ {
			batch, timeout := getBatch(proxies, i)
			if len(batch) == 0 {
				break
			}

			ctxDial, cancel := context.WithTimeout(ctx, timeout)
			start := time.Now()
			p, c, connectTime, err := s.ParallelDialContext(ctxDial, batch, metadata, start, s.singleDialContext)
			cancel()

			if err != nil {
				if tunnel.ShouldStopRetry(err) {
					return nil, err
				}
				finalErr = err
			} else {
				s.adoptUnwrapWinner(metadata, asnNumber, p)
				s.onDialSuccess()
				return s.WrapConnWithMetric(c, p, metadata, connectTime), nil
			}
		}

		s.store.DeleteUnwrapResult(s.Name(), s.configName, metadata.SmartTarget, asnNumber, metadata.WildcardTarget)

		s.groupDialFailed(proxies, finalErr)

		return nil, finalErr
	}

	proxies, asnNumber := s.selectProxies(metadata, s.GetProxies(true))

	return tryDial(proxies, asnNumber)
}

func (s *Smart) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (pc C.PacketConn, err error) {
	s.markTrafficActivity()

	var finalErr error

	proxies, asnNumber := s.selectProxies(metadata, s.GetProxies(true))

	limit := len(proxies)
	if limit > maxSelected {
		limit = maxSelected
	}

	singleProxyRetry := (len(proxies) == 1)

	for i := 0; i < limit; i++ {
		proxy := proxies[i]
		attempts := 1
		if singleProxyRetry {
			attempts = maxRetries
		}

		for a := 0; a < attempts; a++ {
			historyConnectTime := s.getHistoryConnectStats(metadata, proxy)
			var timeout time.Duration
			if historyConnectTime > 0 {
				timeout = time.Duration(float64(historyConnectTime)*connectThreshold) * time.Millisecond
			}
			if timeout > C.DefaultUDPTimeout || timeout <= 0 {
				timeout = C.DefaultUDPTimeout
			}
			ctxDial, cancel := context.WithTimeout(ctx, timeout)
			start := time.Now()
			pc, err = proxy.ListenPacketContext(ctxDial, metadata)
			cancel()
			connectTime := time.Since(start).Milliseconds()

			if err != nil {
				if tunnel.ShouldStopRetry(err) {
					return nil, err
				}
				finalErr = err
				s.submitConnectionStats(metadata.Clone(), proxy, connectTime, 0, 0, 0, 0, 0, 0, nil, err, false)
				continue
			}

			s.adoptUnwrapWinner(metadata, asnNumber, proxy)
			s.onDialSuccess()
			return s.WrapPacketConnWithMetric(pc, proxy, metadata, connectTime), nil
		}

		if singleProxyRetry {
			break
		}
	}

	s.store.DeleteUnwrapResult(s.Name(), s.configName, metadata.SmartTarget, asnNumber, metadata.WildcardTarget)

	s.groupDialFailed(proxies, finalErr)

	return nil, finalErr
}

func (s *Smart) Unwrap(metadata *C.Metadata, touch bool) C.Proxy {
	proxies := s.GetProxies(touch)

	if metadata == nil {
		return proxies[0]
	}

	if s.selected != "" {
		for _, p := range proxies {
			if p.Name() == s.selected {
				return p
			}
		}
	}

	proxies, _ = s.selectProxies(metadata, proxies)

	return proxies[0]
}

func (s *Smart) IsL3Protocol(metadata *C.Metadata) bool {
	return s.Unwrap(metadata, false).IsL3Protocol(metadata)
}

func (s *Smart) SupportUDP() bool {
	return !s.disableUDP
}

func (s *Smart) WrapConnWithMetric(c C.Conn, proxy C.Proxy, metadata *C.Metadata, connectTime int64) C.Conn {
	c.AppendToChains(s)

	start := time.Now()

	var firstWriteErr atomic.TypedValue[error]
	var firstReadErr atomic.TypedValue[error]
	var firstReadLatency atomic.Int64

	if N.NeedHandshake(c) {
		c = callback.NewFirstWriteCallBackConn(c, func(err error) {
			if err != nil {
				firstWriteErr.Store(err)
			}
		})
	}

	c = callback.NewFirstReadCallBackConn(c, func(err error) {
		firstReadLatency.Store(time.Since(start).Milliseconds())
		if err != nil {
			firstReadErr.Store(err)
		}
	})

	return s.registerClosureMetricsCallback(
		c, proxy, metadata, connectTime,
		&firstReadLatency, &firstReadErr, &firstWriteErr,
	)
}

func (s *Smart) WrapPacketConnWithMetric(pc C.PacketConn, proxy C.Proxy, metadata *C.Metadata, connectTime int64) C.PacketConn {
	pc.AppendToChains(s)

	var udpLatency atomic.Int64

	pc = callback.NewFirstReadCallBackPacketConn(pc, func(latency int64) {
		udpLatency.Store(latency)
	})

	return s.registerPacketClosureMetricsCallback(pc, proxy, metadata, connectTime, &udpLatency)
}

func (s *Smart) Set(name string) error {
	var p C.Proxy
	for _, proxy := range s.GetProxies(false) {
		if proxy.Name() == name {
			p = proxy
			break
		}
	}

	if p == nil {
		return errors.New("proxy not exist")
	}

	s.ForceSet(name)

	return nil
}

func (s *Smart) ForceSet(name string) {
	s.selected = name
}

func (s *Smart) Now() string {
	if s.selected != "" {
		for _, p := range s.GetProxies(false) {
			if p.Name() == s.selected {
				return p.Name()
			}
		}
		s.selected = ""
	}

	return "Smart - Select"
}

func (s *Smart) MarshalJSON() ([]byte, error) {
	proxies := s.GetProxies(false)
	all := make([]string, len(proxies))
	for i, proxy := range proxies {
		all[i] = proxy.Name()
	}

	var policyPriorityBuf strings.Builder
	for i, rule := range s.policyPriority {
		if i > 0 {
			policyPriorityBuf.WriteByte(';')
		}
		fmt.Fprintf(&policyPriorityBuf, "%s:%.2f", rule.pattern, rule.factor)
	}

	return json.Marshal(map[string]any{
		"type":            s.Type().String(),
		"now":             s.Now(),
		"all":             all,
		"testUrl":         s.testUrl,
		"expectedStatus":  s.expectedStatus,
		"fixed":           s.selected,
		"hidden":          s.Hidden(),
		"icon":            s.Icon(),
		"emptyFallback":   s.EmptyFallback().Name(),
		"policy-priority": policyPriorityBuf.String(),
		"useLightGBM":     s.useLightGBM,
		"collectData":     s.collectData,
		"sampleRate":      s.sampleRate,
		"preferASN":       s.preferASN,
		"tolerance":       s.tolerance,
	})
}

func (s *Smart) Providers() []provider.ProxyProvider {
	return s.providers
}

func (s *Smart) Proxies() []C.Proxy {
	return s.GetProxies(false)
}

// uniqueProxiesByName returns only names that identify one current proxy.
// Smart's persistent store predates provider-aware identities and stores names
// for compatibility, so an ambiguous cached name must be ignored rather than
// silently mapped to whichever provider happened to be iterated last.
func uniqueProxiesByName(proxies []C.Proxy) map[string]C.Proxy {
	byName := make(map[string]C.Proxy, len(proxies))
	ambiguous := make(map[string]struct{})
	for _, proxy := range proxies {
		if proxy == nil {
			continue
		}
		name := proxy.Name()
		if _, duplicate := ambiguous[name]; duplicate {
			continue
		}
		if _, exists := byName[name]; exists {
			delete(byName, name)
			ambiguous[name] = struct{}{}
			continue
		}
		byName[name] = proxy
	}
	return byName
}

// proxyIndexFor returns the cached name index when all is the group's own
// current proxy list, which is what every caller on the connection path passes.
// A caller holding some other slice gets a freshly derived index.
func (s *Smart) proxyIndexFor(all []C.Proxy) map[string]C.Proxy {
	s.getProxiesMutex.Lock()
	cached := len(all) == len(s.providerProxies) &&
		(len(all) == 0 || &all[0] == &s.providerProxies[0])
	if cached && s.proxiesByName == nil {
		s.proxiesByName = uniqueProxiesByName(all)
	}
	byName := s.proxiesByName
	s.getProxiesMutex.Unlock()
	if !cached {
		return uniqueProxiesByName(all)
	}
	return byName
}

func (s *Smart) filterProxies(metadata *C.Metadata, wildcardTarget string, names []string, weights []float64, all []C.Proxy, minCount int, isUDP bool) []C.Proxy {
	blockedNodes := s.store.GetBlockedNodes(s.Name(), s.configName)
	wtFailNodes, _, _, wtBlocked := s.store.GetHostStatus(s.Name(), s.configName, wildcardTarget, int(s.hostFailLimit.Load()), metadata.SmartTarget)

	var proxyByName map[string]C.Proxy
	if len(names) > 0 {
		proxyByName = s.proxyIndexFor(all)
	}

	checkNodeUsed := make(map[string]bool, len(names))

	selected := make([]C.Proxy, 0, minCount+1)

	for i, name := range names {
		proxy := proxyByName[name]
		if proxy == nil || blockedNodes[name] || !proxy.AliveForTestUrl(s.testUrl) || (isUDP && !proxy.SupportUDP()) {
			continue
		}
		checkNodeUsed[adapter.ProxyIdentity(proxy)] = true
		w := 0.0
		if weights != nil && i < len(weights) {
			w = weights[i]
		}
		if weights != nil && w < smart.AllowedWeight {
			continue
		}
		if excludedForHost(wtFailNodes, wtBlocked, name) {
			continue
		}
		selected = append(selected, proxy)
	}

	// Unwrap result should not filled
	if weights == nil && len(selected) > 0 {
		return selected
	}

	if len(selected) >= len(all) {
		return selected
	}

	if len(selected) >= minCount {
		return selected[:minCount]
	}

	hasPriority := len(s.policyPriority) > 0

	type sortKey struct {
		delay  uint16
		factor float64
		index  int
	}
	allKeys := make(map[string]sortKey, len(all))
	for i, p := range all {
		name := p.Name()
		// Capability preferences demote a node here rather than removing it
		// from the pool, so a failed UDP / IPv6 probe costs a node its rank
		// but never its availability.
		k := sortKey{
			delay: adapter.AddCapabilityPenalty(
				p.LastDelayForTestUrl(s.testUrl), p, s.preferUDP, s.preferIPv6),
			index: i,
		}
		if hasPriority {
			k.factor = s.getPriorityFactor(name)
		}
		allKeys[adapter.ProxyIdentity(p)] = k
	}

	defaultSort := func(proxies []C.Proxy) []C.Proxy {
		sort.SliceStable(proxies, func(i, j int) bool {
			ni, nj := adapter.ProxyIdentity(proxies[i]), adapter.ProxyIdentity(proxies[j])
			ki, kj := allKeys[ni], allKeys[nj]
			if hasPriority && ki.factor != kj.factor {
				return ki.factor > kj.factor
			}
			// Tolerance: delays within tolerance are treated as equal, preventing jitter
			if s.tolerance > 0 {
				var diff uint16
				if ki.delay > kj.delay {
					diff = ki.delay - kj.delay
				} else {
					diff = kj.delay - ki.delay
				}
				if diff <= s.tolerance {
					return ki.index < kj.index
				}
			}
			if ki.delay != kj.delay {
				return ki.delay < kj.delay
			}
			return ki.index < kj.index
		})
		return proxies
	}

	filteredAll := make([]C.Proxy, 0, len(all))

	for _, p := range all {
		name := p.Name()
		if checkNodeUsed[adapter.ProxyIdentity(p)] {
			continue
		}
		if excludedForHost(wtFailNodes, wtBlocked, name) {
			continue
		}
		if blockedNodes[name] {
			continue
		}
		if !p.AliveForTestUrl(s.testUrl) || (isUDP && !p.SupportUDP()) {
			continue
		}
		filteredAll = append(filteredAll, p)
	}

	filteredAll = defaultSort(filteredAll)

	for _, p := range filteredAll {
		selected = append(selected, p)
		if len(selected) >= minCount {
			break
		}
	}

	if len(selected) == 0 {
		fallbackAll := defaultSort(slices.Clone(all))
		for _, p := range fallbackAll {
			if (wtFailNodes[p.Name()] == 0 || (wtBlocked && wtFailNodes[p.Name()] != 1)) && p.AliveForTestUrl(s.testUrl) && (!isUDP || p.SupportUDP()) {
				selected = append(selected, p)
			}
			if len(selected) >= minCount {
				break
			}
		}

		if len(selected) == 0 {
			for _, p := range fallbackAll {
				if p.AliveForTestUrl(s.testUrl) {
					selected = append(selected, p)
				}
				if len(selected) >= minCount {
					break
				}
			}
		}

		if len(selected) == 0 {
			for _, p := range fallbackAll {
				if wtFailNodes[p.Name()] == smart.BlockManual {
					continue
				}
				selected = append(selected, p)
				if len(selected) >= minCount {
					break
				}
			}

			if len(selected) == 0 {
				for _, p := range fallbackAll {
					selected = append(selected, p)
					if len(selected) >= minCount {
						break
					}
				}
			}
		}
	}

	return selected
}

// node selection
func (s *Smart) selectProxies(metadata *C.Metadata, proxies []C.Proxy) ([]C.Proxy, string) {
	// attach ASN info
	asnNumber := s.getASNCode(metadata)
	wildcardTarget := smart.GetEffectiveTarget(metadata.Host, metadata.DstIP.String())
	metadata.WildcardTarget = wildcardTarget
	if metadata.SmartTarget == "" {
		metadata.SmartTarget = wildcardTarget
	}

	if s.selected != "" {
		for _, p := range proxies {
			if p.Name() == s.selected {
				return []C.Proxy{p}, asnNumber
			}
		}
	}

	// use prefetch cache or compute in real time
	computeFreshNodes := func(isUDP bool) ([]string, []float64) {
		if proxiesName, weights := s.store.GetPrefetchResult(s.Name(), s.configName, metadata.SmartTarget, asnNumber, isUDP); len(proxiesName) > 0 {
			return proxiesName, weights
		}
		if proxiesName, weights, err := s.store.GetBestProxyForTarget(s.Name(), s.configName, metadata.SmartTarget, asnNumber, isUDP); err == nil && len(proxiesName) > 0 {
			return proxiesName, weights
		}
		return nil, nil
	}

	computeFreshSingleFlight := func(isUDP bool) ([]string, []float64) {
		sfKey := fmt.Sprintf("%s|%s|%v", metadata.SmartTarget, asnNumber, isUDP)
		res, _, _ := s.freshNodesGroup.Do(sfKey, func() (nodeResult, error) {
			names, weights := computeFreshNodes(isUDP)
			return nodeResult{names: names, weights: weights}, nil
		})
		return res.names, res.weights
	}

	// asynchronously update expired cache (stale-while-revalidate)
	refreshUnwrapCache := func(isUDP bool) {
		names, _ := computeFreshSingleFlight(isUDP)
		if len(names) == 0 {
			return
		}
		_, proxyByName := s.GetProxiesByName(true)
		resultProxies := make([]C.Proxy, 0, len(names))
		for _, name := range names {
			if p, ok := proxyByName[name]; ok {
				resultProxies = append(resultProxies, p)
			}
		}
		if len(resultProxies) > 0 {
			s.store.StoreUnwrapResult(s.Name(), s.configName, metadata.SmartTarget, asnNumber, metadata.WildcardTarget, resultProxies)
		}
	}

	trySelector := func(isUDP bool) ([]string, []float64) {
		// check the unwrap cache
		if proxiesName, expired := s.store.GetUnwrapResult(s.Name(), s.configName, metadata.SmartTarget, asnNumber, metadata.WildcardTarget); len(proxiesName) > 0 {
			if expired && s.beginBackgroundWork() {
				go func() {
					defer s.finishBackgroundWork()
					refreshUnwrapCache(isUDP)
				}()
			}
			return proxiesName, nil
		}
		return computeFreshSingleFlight(isUDP)
	}

	isUDP := metadata.NetWork == C.UDP
	resultNames, resultWeights := trySelector(isUDP)
	result := s.filterProxies(metadata, wildcardTarget, resultNames, resultWeights, proxies, maxSelected, isUDP)

	return result, asnNumber
}

func (s *Smart) InitSmart() {
	s.store = cachefile.GetSmartStore()

	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.lastTrafficActivity.Store(time.Now().UnixNano())
	s.recoveryBackoff = make(map[string]hostRecoveryState)

	if s.preferASN {
		initASNDatabase()
	}

	s.global = globalSmartTasks.acquire(s)
	s.startGroupTasks()
	if s.useLightGBM {
		s.weightModel = lightgbm.GetModel()
	}
}

func (s *Smart) runPrefetch() {
	proxies := s.GetProxies(true)
	proxyMap := make(map[string]bool, len(proxies))
	for _, proxy := range proxies {
		proxyMap[proxy.Name()] = true
	}
	s.store.RunPrefetch(s.Name(), s.configName, proxyMap)
}

func (s *Smart) updateNodeRanking() {
	proxies := s.GetProxies(true)
	rankingWrapper, _ := s.store.GetNodeWeightRankingCache(s.Name(), s.configName)

	if len(rankingWrapper.Result) > 0 {
		now := time.Now().Unix()
		lastUpdated := rankingWrapper.LastUpdated
		cacheAge := time.Duration(now-lastUpdated) * time.Second

		if cacheAge < 30*time.Minute {
			rankedNodes := make(map[string]bool, len(rankingWrapper.Result))
			for _, r := range rankingWrapper.Result {
				rankedNodes[r.Name] = true
			}
			hasUnrankedProxy := false
			for _, p := range proxies {
				if !rankedNodes[p.Name()] {
					hasUnrankedProxy = true
					break
				}
			}

			if !hasUnrankedProxy {
				if cacheAge <= 10*time.Minute {
					return
				}
				proxyMap := make(map[string]C.Proxy, len(proxies))
				for _, p := range proxies {
					proxyMap[p.Name()] = p
				}
				hasDeadRankedNode := false
				for _, r := range rankingWrapper.Result {
					if r.Rank != smart.RankRarelyUsed {
						if p, exists := proxyMap[r.Name]; exists {
							if !p.AliveForTestUrl(s.testUrl) {
								hasDeadRankedNode = true
								break
							}
						}
					}
				}
				if !hasDeadRankedNode {
					return
				}
			}
		}
	}

	log.Debugln("[Smart] Starting node ranking update for policy group [%s]", s.Name())

	rankingWrapper, err := s.store.GetNodeWeightRanking(s.Name(), s.configName, s.testUrl, proxies)
	if err != nil {
		log.Warnln("[Smart] Failed to update node ranking: %v", err)
		return
	}
	if len(rankingWrapper.Result) == 0 {
		log.Debugln("[Smart] Policy group [%s] doesn't have enough data to generate node ranking", s.Name())
		return
	}
	categoryCounts := make(map[string]int)
	for _, rank := range rankingWrapper.Result {
		categoryCounts[rank.Rank]++
	}

	log.Debugln("[Smart] Policy group [%s] node ranking update completed: %d nodes total (%s: %d, %s: %d, %s: %d)",
		s.Name(), len(rankingWrapper.Result),
		smart.RankMostUsed, categoryCounts[smart.RankMostUsed],
		smart.RankOccasional, categoryCounts[smart.RankOccasional],
		smart.RankRarelyUsed, categoryCounts[smart.RankRarelyUsed])
}

func (s *Smart) cleanupOrphanedGroups() {
	allProxies := tunnel.Proxies()
	existingSmartGroups := make(map[string]bool)

	for name, proxy := range allProxies {
		if proxy.Type() == C.Smart {
			existingSmartGroups[name] = true
		}
	}

	cachedGroups, err := s.store.GetAllGroupsForConfig(s.configName)
	if err != nil {
		return
	}

	var orphanedGroups []string
	for _, groupName := range cachedGroups {
		if !existingSmartGroups[groupName] {
			orphanedGroups = append(orphanedGroups, groupName)
		}
	}

	if len(orphanedGroups) > 0 {
		for _, group := range orphanedGroups {
			log.Debugln("[Smart] Cleaning up cache data for non-existent policy group [%s]", group)
			err := s.store.FlushByGroup(group, s.configName)
			if err != nil {
				log.Warnln("[Smart] Failed to clean up policy group [%s] cache: %v", group, err)
			}
		}
	}
}

func (s *Smart) cleanupOrphanedNodeCache() {
	proxies := s.GetProxies(true)
	proxyMap := make(map[string]bool, len(proxies))
	for _, proxy := range proxies {
		proxyMap[proxy.Name()] = true
	}

	cachedNodes, err := s.store.GetAllNodesForGroup(s.Name(), s.configName)
	if err != nil {
		return
	}

	var orphanedNodes []string
	for _, nodeName := range cachedNodes {
		if !proxyMap[nodeName] {
			orphanedNodes = append(orphanedNodes, nodeName)
		}
	}

	if len(orphanedNodes) > 0 {
		for _, node := range orphanedNodes {
			log.Debugln("[Smart] Cleaning up cache data for non-existent node [%s]", node)
		}

		err := s.store.RemoveNodesData(s.Name(), s.configName, int(s.hostFailLimit.Load()), orphanedNodes)
		if err != nil {
			log.Warnln("[Smart] Failed to clean up non-existent node caches: %v", err)
		}
	}
}

// get historical connectTime
func (s *Smart) getHistoryConnectStats(metadata *C.Metadata, proxy C.Proxy) int64 {
	target := metadata.SmartTarget
	proxyName := proxy.Name()
	cacheKey := smart.FormatDBKey(smart.KeyTypeStats, s.configName, s.Name(), target, proxyName)
	atomicRecord := s.store.GetOrCreateAtomicRecord(cacheKey, s.Name(), s.configName, target, proxyName)
	return atomicRecord.Get("connectTime").(int64)
}

// connection duration update
func (s *Smart) updateConnectionDuration(record *smart.AtomicStatsRecord, connectionDuration int64) {
	durationMinutes := float64(connectionDuration) / 60000.0
	currentDuration := record.Get("duration").(float64)

	if currentDuration > 0 {
		record.Set("duration", (currentDuration+durationMinutes)/2.0)
	} else {
		record.Set("duration", durationMinutes)
	}
}

// save record
func (s *Smart) saveStatsRecord(target string, proxy C.Proxy, record *smart.StatsRecord) {
	if data, err := json.Marshal(record); err == nil {
		s.store.AppendToGlobalQueue(smart.StoreOperation{
			Type:   smart.OpSaveStats,
			Group:  s.Name(),
			Config: s.configName,
			Target: target,
			Node:   proxy.Name(),
			Data:   data,
		})
	}
}

func (s *Smart) calcMADMetrics(delays []float64) (currentAnomaly bool, unstable bool, threshold float64, grade int) {
	calcGrade := func(t float64) int {
		if t <= 500 {
			return 1
		} else if t <= 1000 {
			return 2
		} else if t <= 2000 {
			return 3
		}
		return 4
	}

	n := len(delays)
	if n == 0 {
		return false, false, 0, 0
	}

	var median float64
	var mad float64
	var robustCV float64

	const scale = 1.4826
	const defaultK = 2.5
	const smallK = 3.5
	const cvThreshold = 0.6
	const minSamples = 3
	const SentinelThreshold = 0.5
	const sentinel = float64(0xffff)

	recentCount := minSamples
	if n < recentCount {
		recentCount = n
	}
	recentStart := n - recentCount
	recentSentinels := 0

	filtered := make([]float64, 0, n)
	for i, v := range delays {
		if v >= sentinel {
			if i >= recentStart {
				recentSentinels++
			}
			continue
		}
		filtered = append(filtered, v)
	}

	m := len(filtered)
	if m == 0 {
		return true, true, 0, 0
	}

	if float64(recentSentinels)/float64(recentCount) > SentinelThreshold {
		unstable = true
	}

	if m < minSamples {
		last := delays[n-1]
		currentAnomaly = last >= sentinel
		return currentAnomaly, unstable, 0, 0
	}

	sort.Float64s(filtered)

	if m%2 == 1 {
		median = filtered[m/2]
	} else {
		median = (filtered[m/2-1] + filtered[m/2]) / 2
	}

	devs := make([]float64, 0, m)
	for _, v := range filtered {
		devs = append(devs, math.Abs(v-median))
	}
	sort.Float64s(devs)

	if m%2 == 1 {
		mad = devs[m/2]
	} else {
		mad = (devs[m/2-1] + devs[m/2]) / 2
	}

	if mad == 0 {
		mean := 0.0
		for _, v := range filtered {
			mean += v
		}
		mean /= float64(m)
		varSum := 0.0
		for _, v := range filtered {
			d := v - mean
			varSum += d * d
		}
		std := math.Sqrt(varSum / float64(m))
		threshold = mean + 2*std
		last := delays[n-1]
		if last >= sentinel {
			currentAnomaly = true
		} else {
			currentAnomaly = last > threshold && delays[n-2] > threshold
		}

		return currentAnomaly, unstable, threshold, calcGrade(threshold)
	}

	k := defaultK
	if m < maxSelected {
		k = smallK
	}

	threshold = median + k*scale*mad

	if median > 0 {
		robustCV = scale * mad / median
	} else {
		robustCV = 0
	}

	last := delays[n-1]
	if last >= sentinel {
		currentAnomaly = true
	} else {
		currentAnomaly = last > threshold && delays[n-2] > threshold
	}

	if !unstable {
		unstable = robustCV >= cvThreshold
	}

	return currentAnomaly, unstable, threshold, calcGrade(threshold)
}

func (s *Smart) checkNodesStable() {
	if s.suppressStats.Load() {
		return
	}

	proxies := s.GetProxies(true)
	operations := make([]smart.StoreOperation, 0, len(proxies))
	nodesToBlock := make(map[string]*smart.NodeState, len(proxies))
	now := time.Now().Unix()
	blockedUntil := time.Now().Add(checkInterval + 2*time.Minute).Unix()

	nodeStateData, _ := s.store.GetNodeStates(s.Name(), s.configName)

	for _, p := range proxies {
		if !p.AliveForTestUrl(s.testUrl) {
			continue
		}

		histories := p.DelayHistoryForTestUrl(s.testUrl)
		if len(histories) == 0 {
			continue
		}

		delays := make([]float64, 0, len(histories))
		for _, h := range histories {
			if h.Delay == 0 {
				h.Delay = 0xffff
			}
			delays = append(delays, float64(h.Delay))
		}

		currentAnomaly, unstable, _, newGrade := s.calcMADMetrics(delays)

		proxyName := p.Name()
		var state smart.NodeState
		if data, exists := nodeStateData[proxyName]; exists {
			json.Unmarshal(data, &state)
		}
		prevGrade := state.ThresholdGrade
		state.Name = proxyName
		state.LastChecked = now
		if newGrade > 0 {
			state.ThresholdGrade = newGrade
		}

		gradeWorsened := (prevGrade > 0 && newGrade > prevGrade) || (prevGrade <= 2 && newGrade > 2)
		if currentAnomaly || unstable || gradeWorsened {
			state.BlockedUntil = blockedUntil
			blockCopy := state
			nodesToBlock[proxyName] = &blockCopy
		}

		data, err := json.Marshal(&state)
		if err != nil {
			continue
		}
		operations = append(operations, smart.StoreOperation{
			Type:   smart.OpSaveNodeState,
			Group:  s.Name(),
			Config: s.configName,
			Node:   proxyName,
			Data:   data,
		})
	}

	if len(operations) > 0 {
		s.store.AppendToGlobalQueue(operations...)
	}
	if len(nodesToBlock) > 0 {
		s.store.UpdateBlockedNodesCache(s.Name(), s.configName, nodesToBlock)
	}
}

// check node block status
func (s *Smart) checkBlockedNodes() {
	stateData, err := s.store.GetNodeStates(s.Name(), s.configName)
	if err != nil {
		return
	}

	nodesToUpdate := make(map[string]*smart.NodeState)

	for nodeName, data := range stateData {
		var state smart.NodeState
		err := json.Unmarshal(data, &state)
		if err != nil {
			continue
		}

		if state.BlockedUntil > 0 && state.BlockedUntil <= time.Now().Unix() {
			state.BlockedUntil = 0
			nodesToUpdate[nodeName] = &state
			log.Debugln("[Smart] Node [%s] block period expired, unblocking", nodeName)
		}
	}

	if len(nodesToUpdate) > 0 {
		operations := make([]smart.StoreOperation, 0, len(nodesToUpdate))
		for nodeName, state := range nodesToUpdate {
			data, err := json.Marshal(state)
			if err != nil {
				continue
			}
			operations = append(operations, smart.StoreOperation{
				Type:   smart.OpSaveNodeState,
				Group:  s.Name(),
				Config: s.configName,
				Node:   nodeName,
				Data:   data,
			})
		}
		s.store.AppendToGlobalQueue(operations...)
		s.store.UpdateBlockedNodesCache(s.Name(), s.configName, nodesToUpdate)
	}
}

// unit conversion
func formatTrafficUnit(val float64, isSpeed bool) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	base := 1024.0
	i := 0
	for val >= base && i < len(units)-1 {
		val /= base
		i++
	}
	if isSpeed {
		return fmt.Sprintf("%.2f %s/s", val, units[i])
	}
	return fmt.Sprintf("%.2f %s", val, units[i])
}

func formatTimeUnit(val float64) string {
	units := []string{"ms", "s", "min", "h"}
	thresholds := []float64{1000.0, 60.0, 60.0}
	i := 0
	for i < len(units)-1 && val >= thresholds[i] {
		val /= thresholds[i]
		i++
	}
	return fmt.Sprintf("%.2f %s", val, units[i])
}

// log record
func (s *Smart) logConnectionStats(err error, record *smart.StatsRecord, metadata *C.Metadata, baseWeight, priorityFactor float64,
	addressDisplay, proxyName string, connectTime int64, latency int64, uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate float64,
	connectionDuration int64, asnNumber string, ModelPredicted bool, lossRate, cumulLossRate float64) {

	var tcpAsnWeight, udpAsnWeight float64

	if asnNumber != "" {
		tcpAsnWeightKey := smart.WeightTypeTCPASN + ":" + asnNumber
		udpAsnWeightKey := smart.WeightTypeUDPASN + ":" + asnNumber
		if record.Weights != nil {
			if w, ok := record.Weights[tcpAsnWeightKey]; ok {
				tcpAsnWeight = w
			}
			if w, ok := record.Weights[udpAsnWeightKey]; ok {
				udpAsnWeight = w
			}
		}
	}

	weightSource := "Traditional"
	if ModelPredicted {
		weightSource = "LightGBM"
	}

	statusStr := "closed"
	if err != nil {
		statusStr = "failed"
	}

	log.Debugln("[Smart] Connection status: [%s], Updated weights: (Model: [%s], TCP: [%.4f], UDP: [%.4f], TCP ASN: [%.4f], UDP ASN: [%.4f], Base: [%.4f], Priority: [%.2f]) "+
		"For (Group: [%s] - Node: [%s] - Network: [%s] - Address: [%s]) "+
		"- Current: (Connect: [%s], Latency: [%s], LossRate: [%.2f%%], Up: [%s], Down: [%s], Max Up Speed: [%s], Max Down Speed: [%s], Duration: [%s]) "+
		"- History: (Success: [%d], Failure: [%d], EMA Connect: [%s], EMA Latency: [%s], Cumul LossRate: [%.2f%%], Total Up: [%s], Total Down: [%s], Max Up Speed: [%s], Max Down Speed: [%s], Avg Duration: [%s])",
		statusStr, weightSource, record.Weights[smart.WeightTypeTCP], record.Weights[smart.WeightTypeUDP], tcpAsnWeight, udpAsnWeight, baseWeight, priorityFactor,
		s.Name(), proxyName, metadata.NetWork.String(), addressDisplay,
		formatTimeUnit(float64(connectTime)),
		formatTimeUnit(float64(latency)),
		lossRate*100,
		formatTrafficUnit(uploadTotal*1024*1024, false),
		formatTrafficUnit(downloadTotal*1024*1024, false),
		formatTrafficUnit(maxUploadRate*1024, true),
		formatTrafficUnit(maxDownloadRate*1024, true),
		formatTimeUnit(float64(connectionDuration)),
		record.Success, record.Failure,
		formatTimeUnit(float64(record.ConnectTime)),
		formatTimeUnit(float64(record.Latency)),
		cumulLossRate*100,
		formatTrafficUnit(record.UploadTotal*1024*1024, false),
		formatTrafficUnit(record.DownloadTotal*1024*1024, false),
		formatTrafficUnit(record.MaxUploadRate*1024, true),
		formatTrafficUnit(record.MaxDownloadRate*1024, true),
		formatTimeUnit(record.ConnectionDuration*60000),
	)
}

// data collection
func (s *Smart) collectConnectionData(input *smart.ModelInput, metadata *C.Metadata,
	baseWeight float64, proxyName string, ModelPredicted bool) {

	// sample rate control
	if s.sampleRate < 1.0 && rand.Float64() > s.sampleRate {
		return
	}

	input.GroupName = s.Name()
	input.NodeName = proxyName
	weightSource := "Traditional"

	if ModelPredicted {
		weightSource = "LightGBM"
	}

	lightgbm.GetCollector().AddSample(input, metadata, baseWeight, weightSource)
}

func updateEMAInt(oldValue int64, newValue int64) int64 {
	if oldValue > 0 {
		return (oldValue*2 + newValue*4) / 6
	}
	return newValue
}

func updateEMAFloat(oldValue, newValue float64) float64 {
	if oldValue > 0 {
		return (oldValue*2 + newValue*4) / 6
	}
	return newValue
}

// admitConnectionStats is failure-flood suppression: once recent failures reach
// the threshold, the heavy per-connection work is skipped so a burst of dead
// connections cannot turn into a disconnect storm of its own. It reports
// whether to go on, and whether this call is the one that armed the suppressor
// (the caller owns the store write that follows).
//
// A connection the group closed itself is evidence of nothing and must not
// clear the suppressor. It reports no read or write error -- closeErr is
// derived from those alone -- so it used to arrive indistinguishable from a
// healthy close and reset the counter to zero. Every victim of a sweep did
// that, which meant the one mechanism written to stop a disconnect storm was
// held open by the storm it was meant to stop.
func (s *Smart) admitConnectionStats(metadata *C.Metadata, err error, now int64) (proceed bool, tripped bool) {
	// Neither direction: a connection this group closed says nothing about the
	// network, so it must not clear the suppressor and must not count toward
	// arming it either. A victim usually reports no error, but one whose first
	// read had already failed before the sweep reached it arrives here with
	// both an error and the marker -- and arming is not the safe direction it
	// looks like, because tripping runs ClearFloodRecordsByGroup, which
	// discards the group's queued stat and host-status writes.
	if metadata.SmartBlock == "degraded" {
		return true, false
	}
	if err == nil {
		s.suppressStats.Store(false)
		s.suppressCount.Store(0)
		return true, false
	}
	if now-s.suppressLast.Load() > int64(floodWindow.Seconds()) {
		s.suppressCount.Store(0)
	}
	s.suppressLast.Store(now)
	if s.suppressCount.Add(1) >= floodThreshold {
		tripped = s.suppressStats.CompareAndSwap(false, true)
	}
	return !s.suppressStats.Load(), tripped
}

func (s *Smart) recordConnectionStats(metadata *C.Metadata, proxy C.Proxy,
	connectTime, latency, uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate,
	connectionDuration int64, tcpStats *tcpstats.Stats, err error) {

	if proxy.Type() == C.Compatible || proxy.Type() == C.Reject || proxy.Type() == C.Pass || proxy.Type() == C.RejectDrop {
		return
	}

	now := time.Now().Unix()
	proceed, tripped := s.admitConnectionStats(metadata, err, now)
	if tripped {
		s.store.ClearFloodRecordsByGroup(s.Name(), s.configName)
	}
	if !proceed {
		return
	}

	var lossRate float64
	var cumulLossRate float64
	var calculatedWeight float64
	var ModelPredicted bool

	proxyName := proxy.Name()
	isUDP := metadata.NetWork == C.UDP
	networkStr := metadata.NetWork.String()

	target := metadata.SmartTarget
	wildcardTarget := metadata.WildcardTarget
	cacheKey := smart.FormatDBKey(smart.KeyTypeStats, s.configName, s.Name(), target, proxyName)
	asnNumber := s.getASNCode(metadata)
	priorityFactor := s.getPriorityFactor(proxyName)

	var addressDisplay string
	debugEnabled := log.DebugEnabled()
	if debugEnabled {
		asnDisplay := "unknown"
		if asnNumber != "" {
			asnDisplay = asnNumber
		}
		if metadata.Host != "" {
			addressDisplay = fmt.Sprintf("Host: [%s] - Target: [%s] - WildcardTarget: [%s] - ASN: [%s]", metadata.Host, target, wildcardTarget, asnDisplay)
		} else {
			addressDisplay = fmt.Sprintf("IP: [%s] - Target: [%s] - ASN: [%s]", metadata.DstIP.String(), target, asnDisplay)
		}
	}

	weightType := smart.WeightTypeTCP
	if asnNumber != "" {
		if isUDP {
			weightType = smart.WeightTypeUDPASN + ":" + asnNumber
		} else {
			weightType = smart.WeightTypeTCPASN + ":" + asnNumber
		}
	} else if isUDP {
		weightType = smart.WeightTypeUDP
	}

	lock := smart.GetTargetNodeLock(target, s.Name(), proxyName)
	lock.Lock()
	locked := true
	defer func() {
		if locked {
			lock.Unlock()
		}
	}()

	atomicRecord := s.store.GetOrCreateAtomicRecord(cacheKey, s.Name(), s.configName, target, proxyName)

	switch {
	case err != nil:
		atomicRecord.Add("failure", int64(1))
	default:
		atomicRecord.Add("success", int64(1))
	}

	if connectTime > 0 {
		oldConnectTime := atomicRecord.Get("connectTime").(int64)
		newConnectTime := updateEMAInt(oldConnectTime, connectTime)
		atomicRecord.Set("connectTime", newConnectTime)
	}

	if latency > 0 {
		oldLatency := atomicRecord.Get("latency").(int64)
		newLatency := updateEMAInt(oldLatency, latency)
		atomicRecord.Set("latency", newLatency)
	}

	if connectionDuration > 0 {
		s.updateConnectionDuration(atomicRecord, connectionDuration)
	}

	if tcpStats != nil {
		atomicRecord.Add("cumulSent", int64(tcpStats.TotalSent()))
		atomicRecord.Add("cumulRetrans", int64(tcpStats.TotalRetrans()))
		lossRate = tcpStats.LossRate()
	}

	if sent := atomicRecord.Get("cumulSent").(int64); sent > 0 {
		cumulLossRate = float64(atomicRecord.Get("cumulRetrans").(int64)) / float64(sent)
		if cumulLossRate > 1 {
			cumulLossRate = 1
		}
	}

	emaLossRate := atomicRecord.Get("lossRate").(float64)
	emaLossRate = updateEMAFloat(emaLossRate, lossRate)
	atomicRecord.Set("lossRate", emaLossRate)

	oldWeight := atomicRecord.GetWeight(weightType)
	uploadTotalMB := float64(uploadTotal) / (1024.0 * 1024.0)
	downloadTotalMB := float64(downloadTotal) / (1024.0 * 1024.0)
	maxUploadRateKB := float64(maxUploadRate) / 1024.0
	maxDownloadRateKB := float64(maxDownloadRate) / 1024.0

	atomicRecord.Add("uploadTotal", uploadTotalMB)
	atomicRecord.Add("downloadTotal", downloadTotalMB)

	oldMaxUploadRate := atomicRecord.Get("maxUploadRate").(float64)
	if maxUploadRateKB > oldMaxUploadRate {
		atomicRecord.Set("maxUploadRate", maxUploadRateKB)
	}

	oldMaxDownloadRate := atomicRecord.Get("maxDownloadRate").(float64)
	if maxDownloadRateKB > oldMaxDownloadRate {
		atomicRecord.Set("maxDownloadRate", maxDownloadRateKB)
	}

	input := lightgbm.CreateModelInputFromStatsRecord(
		atomicRecord, metadata,
		uploadTotalMB, downloadTotalMB, maxUploadRateKB, maxDownloadRateKB, float64(connectionDuration)/60000.0, wildcardTarget,
		lossRate, cumulLossRate,
	)
	input.ConnectionFailed = err != nil

	if s.useLightGBM && s.weightModel != nil {
		calculatedWeight, ModelPredicted = s.weightModel.PredictWeight(input, priorityFactor)
	} else {
		calculatedWeight, ModelPredicted = smart.CalculateWeight(input, priorityFactor)
	}

	// extra checks and weight adjustment
	// no more forced weight adjustment; only block nodes for specific domains on anomalies, to avoid good nodes being fully blocked for the whole target
	adjWeight, isDegraded, checked, blockCode := s.checkNodeQuality(
		err, metadata, proxy, wildcardTarget,
		addressDisplay, proxyName, calculatedWeight, oldWeight,
		connectionDuration, uploadTotalMB, downloadTotalMB,
		networkStr, asnNumber, isUDP, lossRate, emaLossRate)

	// block node for the specific domain/IP (wildcardTarget + SmartTarget two-level records)
	failedBlock := s.markNodeFailure(metadata, proxyName, isDegraded, checked, blockCode)

	// average weight (adapted for target adjusting to rule-based and ASN-based cases)
	newWeight := updateEMAFloat(oldWeight, adjWeight)
	atomicRecord.Set("lastUsed", time.Now().Unix())
	atomicRecord.SetWeight(weightType, newWeight, isUDP)
	statsSnapshot := atomicRecord.CreateStatsSnapshot(cacheKey)
	// Queued under the lock: the queue keeps the last write per key, so two
	// closes on this node racing to append would otherwise let the older
	// snapshot overwrite the newer one.
	s.saveStatsRecord(target, proxy, statsSnapshot)

	// Closing stalled connections can block on I/O, so it runs without the
	// lock; the stats goroutines those closes spawn take it.
	lock.Unlock()
	locked = false

	if isDegraded || failedBlock {
		s.closeStalledConnections(metadata, proxyName, target, asnNumber)
		s.store.DeleteUnwrapResult(s.Name(), s.configName, target, asnNumber, metadata.WildcardTarget)
	}

	if s.collectData {
		collectedWeight := adjWeight / priorityFactor
		if isDegraded || failedBlock {
			// forcefully adjust for abnormal connections so the model can recognize them during training
			if collectedWeight >= smart.AllowedWeight {
				collectedWeight = collectedWeight * 0.1
			} else {
				if collectedWeight == 0 {
					collectedWeight = smart.AllowedWeight * rand.Float64()
				}
			}
		}
		s.collectConnectionData(input, metadata, collectedWeight, proxyName, ModelPredicted)
	}

	if debugEnabled {
		s.logConnectionStats(err, statsSnapshot, metadata, calculatedWeight/priorityFactor, priorityFactor, addressDisplay, proxyName,
			connectTime, latency, uploadTotalMB, downloadTotalMB, maxUploadRateKB, maxDownloadRateKB, connectionDuration, asnNumber, ModelPredicted, lossRate, cumulLossRate)
	}
}

func (s *Smart) submitConnectionStats(metadata *C.Metadata, proxy C.Proxy,
	connectTime, latency, uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate,
	connectionDuration int64, tcpStats *tcpstats.Stats, err error, markCloseFailure bool,
) bool {
	if !s.beginBackgroundWork() {
		return false
	}

	go func() {
		defer s.finishBackgroundWork()
		// The degraded marker means this group closed the connection itself, so
		// nothing about the close is the node's doing. checkNodeQuality honours
		// it; this path did not, and a connection whose first read had already
		// failed before the sweep reached it was blamed with code 3 anyway.
		if markCloseFailure && err != nil && metadata.SmartBlock != "degraded" {
			s.markNodeFailure(metadata, proxy.Name(), true, true, smart.BlockDialFailure)
		}
		s.recordConnectionStats(metadata, proxy, connectTime, latency, uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate, connectionDuration, tcpStats, err)
	}()
	return true
}

func (s *Smart) beginBackgroundWork() bool {
	s.workMu.Lock()
	defer s.workMu.Unlock()
	if s.workClosing {
		return false
	}
	s.workWG.Add(1)
	return true
}

func (s *Smart) finishBackgroundWork() {
	s.workWG.Done()
}

func (s *Smart) disableBackgroundWork() {
	s.workMu.Lock()
	s.workClosing = true
	s.workMu.Unlock()
}

func (s *Smart) waitBackgroundWork() {
	s.workWG.Wait()
}

func (s *Smart) registerClosureMetricsCallback(c C.Conn, proxy C.Proxy, metadata *C.Metadata, connectTime int64, firstReadLatency *atomic.Int64, firstReadErr *atomic.TypedValue[error], firstWriteErr *atomic.TypedValue[error]) C.Conn {
	return callback.NewCloseCallbackConn(c, func() {
		tracker := statistic.DefaultManager.Get(metadata.UUID)
		if tracker != nil {
			info := tracker.Info()
			uploadTotal := info.UploadTotal.Load()
			downloadTotal := info.DownloadTotal.Load()
			connectionDuration := time.Since(info.Start).Milliseconds()
			maxUploadRate := info.MaxUploadRate.Load()
			maxDownloadRate := info.MaxDownloadRate.Load()

			latency := firstReadLatency.Load()
			readErr := firstReadErr.Load()
			writeErr := firstWriteErr.Load()

			var tcpStats *tcpstats.Stats
			if trackerConn, ok := tracker.(net.Conn); ok {
				tcpStats = tcpstats.GetTCPStats(trackerConn)
			}

			var closeErr error
			if readErr != nil {
				if readErr == io.EOF {
					if writeErr != nil && writeErr != io.EOF {
						closeErr = writeErr
					}
				} else {
					closeErr = readErr
				}
			}

			s.submitConnectionStats(metadata, proxy, connectTime, latency, uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate, connectionDuration, tcpStats, closeErr, true)
			return
		}
	})
}

func (s *Smart) registerPacketClosureMetricsCallback(pc C.PacketConn, proxy C.Proxy, metadata *C.Metadata, connectTime int64, udpLatency *atomic.Int64) C.PacketConn {
	return callback.NewCloseCallbackPacketConn(pc, func() {
		tracker := statistic.DefaultManager.Get(metadata.UUID)
		if tracker != nil {
			info := tracker.Info()
			uploadTotal := info.UploadTotal.Load()
			downloadTotal := info.DownloadTotal.Load()
			connectionDuration := time.Since(info.Start).Milliseconds()
			maxUploadRate := info.MaxUploadRate.Load()
			maxDownloadRate := info.MaxDownloadRate.Load()

			s.submitConnectionStats(metadata, proxy, connectTime, udpLatency.Load(),
				uploadTotal, downloadTotal, maxUploadRate, maxDownloadRate, connectionDuration, nil, nil, false)
			return
		}
	})
}

func (s *Smart) checkNodeQuality(
	err error, metadata *C.Metadata, proxy C.Proxy, wildcardTarget string,
	addressDisplay, proxyName string,
	newWeight, oldWeight float64,
	connectionDuration int64, uploadTotal, downloadTotal float64,
	networkType string, asnNumber string, isUDP bool, lossRate, emaLossRate float64) (float64, bool, bool, smart.BlockCode) {

	if s.selected != "" {
		return newWeight, false, false, smart.BlockNone
	}

	now := time.Now().Unix()

	// user manual block
	if metadata.SmartBlock == "blocked" {
		log.Debugln("[Smart] Connection Group: [%s] - Node: [%s] - Network: [%s] - Address: [%s] detected manual block...",
			s.Name(), proxyName, networkType, addressDisplay)
		return newWeight, true, true, smart.BlockManual
	}

	// force-closed connection, skip quality check to avoid erroneous downgrade
	if metadata.SmartBlock == "degraded" {
		return oldWeight, false, false, smart.BlockNone
	}

	wtFailNodes, wtLastCheck, wtLastFailure, wtBlocked := s.store.GetHostStatus(s.Name(), s.configName, wildcardTarget, int(s.hostFailLimit.Load()), metadata.SmartTarget)

	// The safety valve: so many nodes are blocked for this target that
	// filterProxies has started letting blocked ones back into the pool, and no
	// further blocking verdict should be recorded while that lasts. A clean
	// close over a node that is itself blocked still has to be reported, and
	// for the same reason as below -- draining the blocks is the only way the
	// valve ever closes, and reporting it unchecked left the recovery probe as
	// the only route out of a state the probe could not even see, since it
	// swept code 2 alone.
	if wtBlocked {
		return newWeight, false, err == nil && wtFailNodes[proxyName] != smart.BlockNone, smart.BlockNone
	}

	if newWeight > 0 && newWeight < smart.AllowedWeight {
		return newWeight, true, true, smart.BlockLowWeight
	}

	if err != nil {
		return newWeight, false, true, smart.BlockDialFailure
	}

	// The node is already blocked for this target and still carried this
	// connection through -- the hostFailLimit safety valve lets blocked nodes
	// back into the pool once too many of them are out, and a recovery probe
	// clears the way for the rest. Skipping the quality checks for it is right;
	// reporting it unchecked was not, because UpdateHostStatus returns at once
	// on !checked and its clearing branch is the only thing that lifts a block.
	// Success could therefore never undo one: a blocked node waited out the
	// full 24-hour TTL or a recovery probe, however well it was working.
	if wtFailNodes[proxyName] != smart.BlockNone {
		return newWeight, false, true, smart.BlockNone
	}

	// A connection that carried a request and got nothing back. The node
	// accepted the flow and then swallowed it, which is a failure no dial error
	// reports.
	//
	// It used to require uploadTotal == 0 as well, which inverted the
	// attribution: the client had not sent a byte, so the node never had a
	// chance to answer and could not be at fault. That fires on every
	// speculative TLS connection a browser opens and closes unused, and on
	// every idle HTTP/2 spare -- each one costing the node that happened to
	// carry it a 24-hour block for the target. The fork's own stall detector
	// already draws the line here: tunnel/statistic/tracker.go refuses to
	// record a stall unless the upload counter moved.
	if connectionDuration > 100 && downloadTotal == 0 && uploadTotal > 0 && metadata.DstPort == 443 && !isUDP {
		log.Debugln("[Smart] Connection Group: [%s] - Node: [%s] - Network: [%s] - Address: [%s] detected no response to a sent request...",
			s.Name(), proxyName, networkType, addressDisplay)
		return newWeight, true, true, smart.BlockNoResponse
	}

	// abnormal status code detection
	if downloadTotal < 0.03 && metadata.Host != "" && metadata.DstPort == 443 && !isUDP && metadata.Type != C.INNER {
		var failure bool
		var checked bool
		// A probe is a live HTTPS request through the proxy -- a fresh
		// transport, a TLS handshake, up to three redirects, a 10s client
		// timeout -- and it runs with this connection's shard lock held. The
		// rate limit is what keeps that bounded.
		//
		// The second clause used to remove the limit outright for 300s after
		// any failure on this target, so during exactly the churn that produces
		// failures, every qualifying close launched its own probe: unbounded,
		// while the scheduled path doing the same work budgets itself to 64
		// probes per half hour. Recent trouble now shortens the interval rather
		// than removing it, so the eagerness survives and the storm does not.
		probeInterval := int64(300)
		if now-wtLastFailure < 300 {
			probeInterval = 30
		}
		if now-wtLastCheck > probeInterval {
			checked = true
			status, ok, err := s.StatusTest(proxy, metadata.Host)
			if err == nil {
				failure = !ok
				if failure {
					log.Debugln("[Smart] Connection Group: [%s] - Node: [%s] - Network: [%s] - Address: [%s] detected abnormal response [%d]...",
						s.Name(), proxyName, networkType, addressDisplay, status)
				}
			}
		}
		if failure {
			return newWeight, true, checked, smart.BlockAbnormalStatus
		}
		return newWeight, false, checked, smart.BlockNone
	}

	// high packet loss detection
	if lossRate >= 0.1 || emaLossRate >= 0.05 {
		log.Debugln("[Smart] Connection Group: [%s] - Node: [%s] - Network: [%s] - Address: [%s] detected high packet loss [current: %.2f%%, history EMA: %.2f%%]...",
			s.Name(), proxyName, networkType, addressDisplay, lossRate*100, emaLossRate*100)
		return newWeight, true, true, smart.BlockPacketLoss
	}

	return newWeight, false, false, smart.BlockNone
}

func (s *Smart) markNodeFailure(metadata *C.Metadata, proxyName string, isDegraded bool, checked bool, blockCode smart.BlockCode) bool {
	wildcardTarget := metadata.WildcardTarget
	target := metadata.SmartTarget

	failedBlock := s.store.UpdateHostStatus(s.Name(), s.configName, wildcardTarget, metadata, proxyName, s.maxFailedTimes, int(s.hostFailLimit.Load()), isDegraded, checked, blockCode)

	if hostStatusAppliesToEveryScope(isDegraded, failedBlock, checked, blockCode) {
		if target != "" && target != wildcardTarget {
			s.store.UpdateHostStatus(s.Name(), s.configName, target, metadata, proxyName, s.maxFailedTimes, int(s.hostFailLimit.Load()), isDegraded, checked, blockCode)
		}
	}

	return failedBlock
}

// hostStatusAppliesToEveryScope reports whether a host-status update changes a
// block, and so has to reach the SmartTarget records as well as the wildcard
// ones. GetHostStatus unions the two scopes, so a block written to both and
// lifted from one still excludes the node at dial time -- which is what used to
// happen, because only the blocking verdicts propagated.
func hostStatusAppliesToEveryScope(isDegraded, failedBlock, checked bool, blockCode smart.BlockCode) bool {
	if isDegraded || failedBlock {
		return true
	}
	// A clear. UpdateHostStatus drops the node from every code set but the
	// manual one when it is told the connection succeeded, and does nothing at
	// all when the verdict was never checked.
	return checked && blockCode == smart.BlockNone
}

// closeStalledConnections answers a degrade of proxyName on target by closing
// the connections it left stuck: those in the bucket on that node that sent
// something and have heard nothing back for stalledReplyAfter. Through a dead
// relay they would otherwise hang until the client or a keep-alive gave up, and
// closing them is what lets the client redial onto another node now.
//
// Anything else is left alone. This used to close every connection in the
// bucket on every node, so one degraded connection to one destination killed
// all the rule's working traffic and the reconnect storm fed the next degrade.
// A connection that is on another node, idle, or still getting answers is not
// stuck, whatever happened to its neighbour.
func (s *Smart) closeStalledConnections(metadata *C.Metadata, proxyName, target, asnNumber string) {
	if proxyName == "" {
		return
	}
	now := time.Now()
	// Loop-invariant: depends only on asnNumber.
	cdnASN := asnNumber != "" && smart.CdnASNs[asnNumber]
	statistic.DefaultManager.RangeSmartTarget(target, func(id string) bool {
		if id == metadata.UUID {
			return true
		}
		tracker := statistic.DefaultManager.Get(id)
		if tracker == nil {
			return true
		}
		// Cheapest rejections first: the ASN comparison below can memoise an
		// ASN lookup into the tracker's metadata, which is wasted on a tracker
		// that is not a candidate for closing in the first place.
		chains := tracker.Chains()
		if !lo.Contains(chains, s.Name()) || !lo.Contains(chains, proxyName) {
			return true
		}
		if !tracker.Info().AwaitingReply(now, stalledReplyAfter) {
			return true
		}
		if asnNumber != "" {
			if !cdnASN && s.getASNCode(tracker.Info().Metadata) != asnNumber {
				return true
			}
		} else if s.getASNCode(tracker.Info().Metadata) != "" {
			return true
		}
		closeStalled(tracker)
		return true
	})
}

// closeStalled closes a connection this group judged stuck, marked as the
// group's own doing. checkNodeQuality reads the marker to skip a connection the
// group killed itself: a connection it closed says nothing about the node that
// carried it, and without the marker its close was read as the node's own
// failure and answered with a block, which fed the next degrade.
//
// The write reaches the reader that matters without synchronisation:
// closeCallbackConn.Close runs its callback synchronously in this goroutine, so
// the stats goroutine it spawns is created after this write. It does race with
// GET /connections marshalling the same field for display, which predates this
// and costs at most a garbled string in one dashboard row -- torn reads here
// can only produce a value matching none of the three constants, which every
// comparison treats as "not ours". Closing it properly means making Metadata
// non-copyable, and it is copied by value in three places including TUIC's UoT
// path.
func closeStalled(tracker statistic.Tracker) {
	tracker.Info().Metadata.SmartBlock = "degraded"
	_ = tracker.Close()
}

// excludedForHost reports whether host-status verdicts keep name off new dials
// to that host. Past the safety valve -- hostBlocked, too many nodes failing
// the host at once -- only a manual block still excludes.
func excludedForHost(failNodes map[string]smart.BlockCode, hostBlocked bool, name string) bool {
	code := failNodes[name]
	return code != smart.BlockNone && (!hostBlocked || code == smart.BlockManual)
}

// groupMemberIn returns the member of group that carries a connection, which is
// the hop just inside the group's own entry: a chain runs from the leaf outward.
func groupMemberIn(chains C.Chain, group string) (string, bool) {
	for hop := 1; hop < len(chains); hop++ {
		if chains[hop] == group {
			return chains[hop-1], true
		}
	}
	return "", false
}

// avoidsMember reports whether new dials through s currently stay off member
// for a connection with metadata -- blocked, failing its health check, or
// blocked for that connection's own target, the verdicts filterProxies applies.
// proxyByName and blockedNodes are the group's, read once per sweep.
func (s *Smart) avoidsMember(member string, metadata *C.Metadata, proxyByName map[string]C.Proxy, blockedNodes map[string]bool) bool {
	proxy := proxyByName[member]
	if proxy == nil {
		// Not a member any more, so not this group's call.
		return false
	}
	if blockedNodes[member] || !proxy.AliveForTestUrl(s.testUrl) {
		return true
	}
	if metadata == nil || metadata.WildcardTarget == "" {
		return false
	}
	failNodes, _, _, hostBlocked := s.store.GetHostStatus(s.Name(), s.configName, metadata.WildcardTarget, int(s.hostFailLimit.Load()), metadata.SmartTarget)
	return excludedForHost(failNodes, hostBlocked, member)
}

func hostRecoveryKey(wildcardTarget, nodeName, host string) string {
	return wildcardTarget + "\x00" + nodeName + "\x00" + host
}

func (s *Smart) markTrafficActivity() {
	s.lastTrafficActivity.Store(time.Now().UnixNano())
}

func (s *Smart) trafficRecentlyActive(now time.Time) bool {
	last := s.lastTrafficActivity.Load()
	return last != 0 && now.Sub(time.Unix(0, last)) <= hostRecoveryActiveWindow
}

func hostRecoveryDelay(failures uint8) time.Duration {
	if failures == 0 {
		return 0
	}
	delay := hostRecoveryBackoffBase
	for i := uint8(1); i < failures && delay < hostRecoveryBackoffMax; i++ {
		delay *= 2
		if delay >= hostRecoveryBackoffMax {
			return hostRecoveryBackoffMax
		}
	}
	return delay
}

func (s *Smart) selectHostRecoveryItems(toCheck map[string]map[string]string, available map[string]C.Proxy, now time.Time) []hostRecoveryItem {
	if !s.trafficRecentlyActive(now) {
		return nil
	}

	all := make([]hostRecoveryItem, 0)
	activeKeys := make(map[string]struct{})
	for wildcardTarget, nodeMap := range toCheck {
		for nodeName, host := range nodeMap {
			if available != nil {
				if _, exists := available[nodeName]; !exists {
					continue
				}
			}
			key := hostRecoveryKey(wildcardTarget, nodeName, host)
			activeKeys[key] = struct{}{}
			all = append(all, hostRecoveryItem{wildcardTarget, nodeName, host, key})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].key < all[j].key })

	s.recoveryMu.Lock()
	eligible := all[:0]
	for _, item := range all {
		state, exists := s.recoveryBackoff[item.key]
		if !exists || !state.next.After(now) {
			eligible = append(eligible, item)
		}
	}
	for key := range s.recoveryBackoff {
		if _, exists := activeKeys[key]; !exists {
			delete(s.recoveryBackoff, key)
		}
	}
	s.recoveryMu.Unlock()

	if len(eligible) <= hostRecoveryProbeBudget {
		return eligible
	}

	start := int(s.recoveryCursor.Add(hostRecoveryProbeBudget)-hostRecoveryProbeBudget) % len(eligible)
	result := make([]hostRecoveryItem, 0, hostRecoveryProbeBudget)
	for i := 0; i < hostRecoveryProbeBudget; i++ {
		result = append(result, eligible[(start+i)%len(eligible)])
	}
	return result
}

func (s *Smart) recordHostRecoveryResult(key string, success bool, now time.Time) {
	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()
	if s.recoveryBackoff == nil {
		s.recoveryBackoff = make(map[string]hostRecoveryState)
	}
	if success {
		delete(s.recoveryBackoff, key)
		return
	}
	state := s.recoveryBackoff[key]
	if state.failures < ^uint8(0) {
		state.failures++
	}
	state.next = now.Add(hostRecoveryDelay(state.failures))
	s.recoveryBackoff[key] = state
}

func (s *Smart) checkHostStatus() {
	now := time.Now()
	if !s.trafficRecentlyActive(now) {
		return
	}

	proxies := s.GetProxies(false)
	proxyMap := uniqueProxiesByName(proxies)

	toCheck, err := s.store.CheckHostStatus(s.Name(), s.configName, int(s.hostFailLimit.Load()))
	if err != nil {
		return
	}

	toProbe := s.selectHostRecoveryItems(toCheck, proxyMap, now)
	if len(toProbe) == 0 {
		return
	}

	jobs := make(chan hostRecoveryItem)
	var wg sync.WaitGroup
	for i := 0; i < parallelDials; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range jobs {
				select {
				case <-s.ctx.Done():
					return
				default:
				}
				p, ok := proxyMap[it.nodeName]
				if !ok {
					continue
				}
				status, okRes, err := s.StatusTest(p, it.host)
				s.recordHostRecoveryResult(it.key, err == nil && okRes, time.Now())
				metadata := &C.Metadata{Host: it.host}
				if err == nil && okRes {
					s.store.UpdateHostStatus(s.Name(), s.configName, it.wildcardTarget, metadata, it.nodeName, s.maxFailedTimes, int(s.hostFailLimit.Load()), false, true, 0)
					log.Debugln("[Smart] Recover Group: [%s] - Node: [%s] for Host: [%s] with HTTP Status: [%d]", s.Name(), it.nodeName, it.host, status)
				} else if err == nil {
					s.store.UpdateHostStatus(s.Name(), s.configName, it.wildcardTarget, metadata, it.nodeName, s.maxFailedTimes, int(s.hostFailLimit.Load()), true, true, 2)
					log.Debugln("[Smart] Recover Group: [%s] - Node: [%s] for Host: [%s] still abnormal with HTTP Status: [%d]", s.Name(), it.nodeName, it.host, status)
				}
			}
		}()
	}

sendLoop:
	for _, it := range toProbe {
		select {
		case jobs <- it:
		case <-s.ctx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()
}

func (s *Smart) StatusTest(proxy C.Proxy, host string) (uint16, bool, error) {
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, C.DefaultTCPTimeout)
	defer cancel()
	url := "https://" + host + "/?z=" + strconv.FormatInt(rand.Int63(), 10)
	return proxy.StatusTest(ctx, url)
}

func (s *Smart) getPriorityFactor(proxyName string) float64 {
	if len(s.policyPriority) == 0 {
		return 1.0
	}
	if v, ok := s.priorityCache.Load(proxyName); ok {
		return v
	}
	factor := 1.0
	for _, rule := range s.policyPriority {
		if rule.isRegex && rule.regex != nil {
			if matched, _ := rule.regex.MatchString(proxyName); matched {
				factor = rule.factor
				break
			}
		} else if strings.Contains(proxyName, rule.pattern) {
			factor = rule.factor
			break
		}
	}
	s.priorityCache.Store(proxyName, factor)
	return factor
}

func (s *Smart) applyHostFailLimit() {
	if proxyCount := len(s.GetProxies(true)); proxyCount > 0 {
		hostFailLimit := proxyCount / 3
		if hostFailLimit < 2 {
			hostFailLimit = 2
		}
		s.hostFailLimit.Store(int32(hostFailLimit))
	}
}

func applyPolicyPriority(s *Smart, policyPriority string) {
	lastUnescapedColon := func(str string) int {
		for i := len(str) - 1; i >= 0; i-- {
			if str[i] == ':' {
				bs := 0
				j := i - 1
				for j >= 0 && str[j] == '\\' {
					bs++
					j--
				}
				if bs%2 == 0 {
					return i
				}
			}
		}
		return -1
	}

	unescapePattern := func(p string) string {
		var b strings.Builder
		for i := 0; i < len(p); i++ {
			if p[i] == '\\' && i+1 < len(p) {
				b.WriteByte(p[i+1])
				i++
			} else {
				b.WriteByte(p[i])
			}
		}
		return b.String()
	}

	pairs := strings.Split(policyPriority, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		idx := lastUnescapedColon(pair)
		if idx <= 0 || idx == len(pair)-1 {
			log.Warnln("[Smart] Invalid policy-priority rule: [%s], must be in 'pattern:factor' format and factor is required", pair)
			continue
		}

		patternRaw := strings.TrimSpace(pair[:idx])
		factorStr := strings.TrimSpace(pair[idx+1:])

		factor, err := strconv.ParseFloat(factorStr, 64)
		if err != nil {
			log.Warnln("[Smart] Invalid priority factor format for pattern [%s:%v]", patternRaw, err)
			continue
		}
		if factor <= 0 || math.IsNaN(factor) || math.IsInf(factor, 0) {
			log.Warnln("[Smart] Invalid priority factor [%v] for pattern [%s], factor must be finite and positive", factor, patternRaw)
			continue
		}

		rule := priorityRule{
			pattern: unescapePattern(patternRaw),
			factor:  factor,
		}

		if re, err := regexp2.Compile(rule.pattern, regexp2.None); err == nil {
			rule.regex = re
			rule.isRegex = true
		}

		s.policyPriority = append(s.policyPriority, rule)
	}
}

func (s *Smart) getASNCode(metadata *C.Metadata) string {
	if metadata.DstIPASN == "unknown" {
		return ""
	}

	if metadata.DstIPASN == "" {
		if !s.preferASN {
			return ""
		}
		var ip netip.Addr
		if metadata.Host != "" && !metadata.Resolved() {
			ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
			defer cancel()
			var err error
			ip, err = resolver.ResolveIP(ctx, metadata.Host)
			if err != nil {
				log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
				metadata.DstIPASN = "unknown"
				return ""
			} else {
				log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
				if !ip.IsValid() {
					metadata.DstIPASN = "unknown"
					return ""
				}
			}
		} else {
			ip = metadata.DstIP
		}

		asn, aso := mmdb.ASNInstance().LookupASN(ip.AsSlice())
		if asn == "" {
			metadata.DstIPASN = "unknown"
		} else {
			metadata.DstIPASN = asn + " " + aso
		}
		return asn
	}

	if idx := strings.IndexByte(metadata.DstIPASN, ' '); idx >= 0 {
		return metadata.DstIPASN[:idx]
	}
	return metadata.DstIPASN
}

func (s *Smart) Close() error {
	s.close.Do(func() {
		s.disableBackgroundWork()
		if s.cancel != nil {
			s.cancel()
		}
		s.wg.Wait()
		s.waitBackgroundWork()
		globalSmartTasks.release(s, s.global)
		s.global = nil
	})
	return nil
}
