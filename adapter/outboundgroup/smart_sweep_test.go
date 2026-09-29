package outboundgroup

import (
	"errors"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/smart"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// sweepTracker is the smallest thing statistic.Manager will index and
// closeStalledConnections will act on.
type sweepTracker struct {
	id     string
	info   *statistic.TrackerInfo
	chain  C.Chain
	closed bool
}

func newSweepTracker(id, target, node, group string) *sweepTracker {
	return &sweepTracker{
		id:    id,
		chain: C.Chain{node, group},
		info: &statistic.TrackerInfo{
			Metadata: &C.Metadata{UUID: id, SmartTarget: target, SmartBlock: "normal"},
		},
	}
}

func (t *sweepTracker) ID() string                    { return t.id }
func (t *sweepTracker) Close() error                  { t.closed = true; return nil }
func (t *sweepTracker) Info() *statistic.TrackerInfo  { return t.info }
func (t *sweepTracker) Chains() C.Chain               { return t.chain }
func (t *sweepTracker) ProviderChains() C.Chain       { return nil }
func (t *sweepTracker) AppendToChains(C.ProxyAdapter) {}
func (t *sweepTracker) RemoteDestination() string     { return "" }
func (t *sweepTracker) block() string                 { return t.info.Metadata.SmartBlock }

// traffic stamps when the tracker last sent and last received, relative to now;
// a zero duration leaves that direction never having carried anything.
func (t *sweepTracker) traffic(now time.Time, sentAgo, receivedAgo time.Duration) *sweepTracker {
	if sentAgo > 0 {
		t.info.LastUpload.Store(now.Add(-sentAgo).UnixNano())
	}
	if receivedAgo > 0 {
		t.info.LastDownload.Store(now.Add(-receivedAgo).UnixNano())
	}
	return t
}

// stuck stamps the tracker as having sent something long enough ago, with
// nothing back since, to count as stalled.
func (t *sweepTracker) stuck(now time.Time) *sweepTracker {
	return t.traffic(now, 2*stalledReplyAfter, 3*stalledReplyAfter)
}

var _ statistic.Tracker = (*sweepTracker)(nil)

func sweepGroup(name string) *Smart {
	return &Smart{GroupBase: &GroupBase{Base: outbound.NewBase(outbound.BaseOption{Name: name})}}
}

func joinSweepTrackers(t *testing.T, trackers ...*sweepTracker) {
	t.Helper()
	for _, tracker := range trackers {
		statistic.DefaultManager.Join(tracker)
		t.Cleanup(func() { statistic.DefaultManager.Leave(tracker) })
	}
}

// A degrade closes what its node left stuck, and nothing that is still working:
// not a connection on another node, not one that is idle, not one whose last
// send was answered, and not one whose send is still within the wait. It used to
// close the whole bucket on every node, so one degraded connection killed all
// the rule's working traffic and the reconnect storm fed the next degrade.
func TestDegradeClosesOnlyTheStuckConnectionsOnTheDegradedNode(t *testing.T) {
	const target = "RuleSet [Proxy]"
	const group = "smart-group"
	s := sweepGroup(group)
	now := time.Now()

	stuck := newSweepTracker("stuck", target, "node-a", group).stuck(now)
	answered := newSweepTracker("answered", target, "node-a", group).traffic(now, 2*stalledReplyAfter, stalledReplyAfter)
	waiting := newSweepTracker("still-waiting", target, "node-a", group).traffic(now, stalledReplyAfter/2, 3*stalledReplyAfter)
	idle := newSweepTracker("idle", target, "node-a", group)
	otherNode := newSweepTracker("other-node", target, "node-b", group).stuck(now)
	joinSweepTrackers(t, stuck, answered, waiting, idle, otherNode)

	dialer := &C.Metadata{UUID: "dialer", SmartTarget: target}
	s.closeStalledConnections(dialer, "node-a", target)

	if !stuck.closed {
		t.Fatal("a connection stuck on the degraded node was left open")
	}
	if stuck.block() != "degraded" {
		t.Fatalf("a connection the group closed itself is marked %q, so its close is read as the node's fault", stuck.block())
	}
	for _, tracker := range []*sweepTracker{answered, waiting, idle, otherNode} {
		if tracker.closed {
			t.Errorf("the degrade closed %q, which was not stuck on the degraded node", tracker.id)
		}
		if tracker.block() != "normal" {
			t.Errorf("an untouched connection %q was marked %q", tracker.id, tracker.block())
		}
	}
}

// stallSweepGroup is a group with a member in each state the periodic sweep
// distinguishes: healthy, failing its health check, blocked outright, and
// blocked for one destination only.
func stallSweepGroup(t *testing.T, group, blockedHost string) *Smart {
	t.Helper()
	const config = "config"
	smart.InitCache()
	smart.InitQueue()

	s := sweepGroup(group)
	s.configName = config
	s.store = &smart.Store{}
	s.maxFailedTimes = 1
	s.hostFailLimit.Store(1_000)
	s.providerProxies = []C.Proxy{
		strategyTestProxy{name: "healthy", alive: true},
		strategyTestProxy{name: "dead", alive: false},
		strategyTestProxy{name: "blocked", alive: true},
		strategyTestProxy{name: "host-blocked", alive: true},
	}
	s.providerVersions = []uint32{}
	s.store.UpdateBlockedNodesCache(group, config, map[string]*smart.NodeState{
		"blocked": {Name: "blocked", BlockedUntil: time.Now().Add(time.Hour).Unix()},
	})
	s.store.UpdateHostStatus(group, config, blockedHost, &C.Metadata{WildcardTarget: blockedHost},
		"host-blocked", 1, 1_000, true, true, smart.BlockNoResponse, 0)
	return s
}

func (t *sweepTracker) to(wildcardTarget string) *sweepTracker {
	t.info.Metadata.WildcardTarget = wildcardTarget
	return t
}

// A degrade sweeps once, and from then on nothing dials the member it degraded,
// so nothing degrades it again. A connection idle at that moment that sends
// into the dead relay later was never looked at and hung until a keep-alive
// gave up. The periodic sweep closes exactly those: stuck, on a member the
// group now avoids -- and nothing that is idle, still answered, on a member
// still in use, or somebody else's.
func TestStalledSweepClosesOnlyWhatIsStuckOnAnAvoidedMember(t *testing.T) {
	const (
		target      = "RuleSet [TelegramIP]"
		group       = "stall-sweep-group"
		blockedHost = "149.154.167.41"
		otherHost   = "91.108.56.194"
	)
	s := stallSweepGroup(t, group, blockedHost)
	now := time.Now()

	nested := newSweepTracker("stuck-nested", target, "dead", group).stuck(now).to(otherHost)
	nested.chain = C.Chain{"dead", group, "outer-select"}
	closes := []*sweepTracker{
		newSweepTracker("stuck-on-dead", target, "dead", group).stuck(now).to(otherHost),
		newSweepTracker("stuck-on-blocked", target, "blocked", group).stuck(now).to(otherHost),
		newSweepTracker("stuck-on-host-block", target, "host-blocked", group).stuck(now).to(blockedHost),
		nested,
	}
	keeps := []*sweepTracker{
		newSweepTracker("stuck-on-healthy", target, "healthy", group).stuck(now).to(otherHost),
		newSweepTracker("stuck-host-block-elsewhere", target, "host-blocked", group).stuck(now).to(otherHost),
		newSweepTracker("answered-on-dead", target, "dead", group).traffic(now, 2*stalledReplyAfter, stalledReplyAfter).to(otherHost),
		newSweepTracker("idle-on-dead", target, "dead", group).to(otherHost),
		newSweepTracker("stuck-on-non-member", target, "gone", group).stuck(now).to(otherHost),
		newSweepTracker("stuck-in-other-group", target, "dead", "another-group").stuck(now).to(otherHost),
	}
	joinSweepTrackers(t, append(append([]*sweepTracker{}, closes...), keeps...)...)

	run := newSmartGlobalTaskRun(s.store)
	run.add(s)
	run.closeStalledConnections()

	for _, tracker := range closes {
		if !tracker.closed {
			t.Errorf("%q was stuck on a member the group avoids and was left open", tracker.id)
		} else if tracker.block() != "degraded" {
			t.Errorf("%q was closed unmarked, so its close is read as the node's fault", tracker.id)
		}
	}
	for _, tracker := range keeps {
		if tracker.closed {
			t.Errorf("the sweep closed %q", tracker.id)
		}
	}

	// Every group the sweep admitted as background work was released again;
	// otherwise closing the group would wait on the sweep forever.
	s.disableBackgroundWork()
	released := make(chan struct{})
	go func() { s.waitBackgroundWork(); close(released) }()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("the sweep left the group's background work admitted")
	}
}

// A group that is closing has stopped admitting background work, and the sweep
// must not act for it.
func TestStalledSweepSkipsAClosingGroup(t *testing.T) {
	const (
		target = "RuleSet [TelegramIP]"
		group  = "stall-sweep-closing-group"
	)
	s := stallSweepGroup(t, group, "149.154.167.41")
	s.disableBackgroundWork()
	stuck := newSweepTracker("stuck-on-dead", target, "dead", group).stuck(time.Now()).to("91.108.56.194")
	joinSweepTrackers(t, stuck)

	run := newSmartGlobalTaskRun(s.store)
	run.add(s)
	run.closeStalledConnections()

	if stuck.closed {
		t.Fatal("the sweep acted for a group that is closing")
	}
}

// A connection belonging to another group shares the bucket but not the blame.
func TestDegradeIgnoresConnectionsOutsideTheGroup(t *testing.T) {
	const target = "RuleSet [Proxy]"
	s := sweepGroup("smart-group")
	now := time.Now()

	foreign := newSweepTracker("foreign", target, "node-a", "another-group").stuck(now)
	joinSweepTrackers(t, foreign)

	dialer := &C.Metadata{UUID: "dialer", SmartTarget: target}
	s.closeStalledConnections(dialer, "node-a", target)

	if foreign.closed {
		t.Fatal("the degrade closed a connection that is not in this group's chain")
	}
	if foreign.block() != "normal" {
		t.Fatalf("the degrade marked a connection outside the group as %q", foreign.block())
	}
}

// The flood suppressor is the only bound on a disconnect storm. Counting a
// connection the group closed itself as a healthy close is what let the storm
// hold its own damper open: a swept victim reports no read or write error, so
// it arrived on the err == nil path and zeroed the counter.
func TestFloodSuppressorIsNotClearedByTheConnectionsItClosed(t *testing.T) {
	s := sweepGroup("smart-group")
	failure := errors.New("connection reset")
	var now int64 = 1000

	for range floodThreshold {
		s.admitConnectionStats(&C.Metadata{SmartBlock: "normal"}, failure, now)
	}
	if proceed, _ := s.admitConnectionStats(&C.Metadata{SmartBlock: "normal"}, failure, now); proceed {
		t.Fatal("the suppressor never engaged after a full flood")
	}

	victim := &C.Metadata{SmartBlock: "degraded"}
	if proceed, _ := s.admitConnectionStats(victim, nil, now); !proceed {
		t.Fatal("a self-closed connection was dropped instead of recorded")
	}
	if proceed, _ := s.admitConnectionStats(&C.Metadata{SmartBlock: "normal"}, failure, now); proceed {
		t.Fatal("a connection the group closed itself cleared the suppressor")
	}

	// Real traffic getting through is the signal that the flood is over.
	s.admitConnectionStats(&C.Metadata{SmartBlock: "normal"}, nil, now)
	if proceed, _ := s.admitConnectionStats(&C.Metadata{SmartBlock: "normal"}, failure, now); !proceed {
		t.Fatal("a genuine success did not clear the suppressor")
	}
}

// Arming the suppressor is what tells the caller to drop the group's queued
// flood records, and it must happen exactly once per engagement.
func TestFloodSuppressorArmsOnce(t *testing.T) {
	s := sweepGroup("smart-group")
	failure := errors.New("connection reset")
	var now int64 = 1000

	var arms int
	for range floodThreshold * 2 {
		if _, tripped := s.admitConnectionStats(&C.Metadata{SmartBlock: "normal"}, failure, now); tripped {
			arms++
		}
	}
	if arms != 1 {
		t.Fatalf("suppressor armed %d times across one flood, want 1", arms)
	}
}

// GetHostStatus unions the wildcard records with the SmartTarget ones, so a
// node is excluded while either scope still holds a block. Blocking wrote both
// scopes but clearing only ever wrote the first, which left the SmartTarget
// block standing and the node excluded anyway.
func TestHostStatusScopePropagationCoversClearsAsWellAsBlocks(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		isDegraded  bool
		failedBlock bool
		checked     bool
		blockCode   smart.BlockCode
		want        bool
	}{
		{name: "degrade blocks both scopes", isDegraded: true, checked: true, blockCode: smart.BlockNoResponse, want: true},
		{name: "accumulated failures block both scopes", failedBlock: true, checked: true, blockCode: smart.BlockDialFailure, want: true},
		{name: "a clean close clears both scopes", checked: true, blockCode: smart.BlockNone, want: true},
		{name: "an unchecked close changes nothing", want: false},
		{name: "a checked non-blocking verdict is not a clear", checked: true, blockCode: smart.BlockAbnormalStatus, want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := hostStatusAppliesToEveryScope(testCase.isDegraded, testCase.failedBlock, testCase.checked, testCase.blockCode)
			if got != testCase.want {
				t.Fatalf("hostStatusAppliesToEveryScope = %v, want %v", got, testCase.want)
			}
		})
	}
}

// A blocked node that carries a connection through cleanly has just proved the
// block wrong. Reporting that close as unchecked meant UpdateHostStatus
// returned before its clearing branch, so nothing but the 24-hour TTL or a
// recovery probe could ever lift a block -- however well the node was working.
// Both exits matter: the safety valve above hostFailLimit is exactly the state
// where blocks most need to drain, because it is what lets blocked nodes carry
// traffic again in the first place.
func TestACleanCloseOnABlockedNodeIsReportedAsChecked(t *testing.T) {
	const (
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	for _, testCase := range []struct {
		name          string
		hostFailLimit int32
	}{
		{name: "below the safety valve", hostFailLimit: 1_000},
		{name: "safety valve open", hostFailLimit: 0},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			smart.InitCache()
			smart.InitQueue()
			group := "smart-group-" + testCase.name

			s := sweepGroup(group)
			s.configName = config
			s.store = &smart.Store{}
			s.maxFailedTimes = 1
			s.hostFailLimit.Store(testCase.hostFailLimit)

			blocking := &C.Metadata{Host: "probe.example.com", WildcardTarget: wildcardTarget}
			s.store.UpdateHostStatus(group, config, wildcardTarget, blocking, node, 1, 1_000, true, true, smart.BlockNoResponse, 0)
			if failNodes, _, _, _ := s.store.GetHostStatus(group, config, wildcardTarget, 1_000); failNodes[node] == 0 {
				t.Fatal("fixture did not block the node")
			}

			metadata := &C.Metadata{
				Host: "probe.example.com", WildcardTarget: wildcardTarget,
				SmartBlock: "normal", NetWork: C.TCP,
			}
			_, isDegraded, checked, blockCode := s.checkNodeQuality(
				nil, metadata, nil, wildcardTarget, "probe.example.com:443", node,
				0.9, 0.9, 1_000, 1.0, 1.0, "tcp", false, 0, 0)

			if isDegraded || blockCode != smart.BlockNone {
				t.Fatalf("a clean close was judged degraded=%v code=%d", isDegraded, blockCode)
			}
			if !checked {
				t.Fatal("a clean close on a blocked node is reported unchecked, so the block can never be lifted by success")
			}
		})
	}
}

// The valve is there to stop new blocks piling up while most of the pool is
// already out. A failing close must not be turned into a clear by the change
// above.
func TestTheSafetyValveStillRefusesToRecordAFailure(t *testing.T) {
	const (
		group          = "valve-group"
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	smart.InitCache()
	smart.InitQueue()

	s := sweepGroup(group)
	s.configName = config
	s.store = &smart.Store{}
	s.maxFailedTimes = 1
	s.hostFailLimit.Store(0)

	blocking := &C.Metadata{Host: "probe.example.com", WildcardTarget: wildcardTarget}
	s.store.UpdateHostStatus(group, config, wildcardTarget, blocking, node, 1, 1_000, true, true, smart.BlockNoResponse, 0)

	metadata := &C.Metadata{
		Host: "probe.example.com", WildcardTarget: wildcardTarget,
		SmartBlock: "normal", NetWork: C.TCP,
	}
	_, isDegraded, checked, blockCode := s.checkNodeQuality(
		errors.New("connection reset"), metadata, nil, wildcardTarget, "probe.example.com:443", node,
		0.9, 0.9, 1_000, 1.0, 1.0, "tcp", false, 0, 0)

	if isDegraded || blockCode != smart.BlockNone {
		t.Fatalf("the valve recorded a blocking verdict: degraded=%v code=%d", isDegraded, blockCode)
	}
	if checked {
		t.Fatal("a failed close was reported as checked, which clears the very blocks the valve is waiting out")
	}
}

// The safety valve reports a clean close as checked so blocks can drain, but
// only for a node that is itself blocked. Reporting every clean close as
// checked would send a second, pointless UpdateHostStatus write down the
// SmartTarget scope for every healthy connection while the valve is open.
func TestTheSafetyValveOnlyReportsClosesOnBlockedNodes(t *testing.T) {
	const (
		group          = "valve-scope-group"
		config         = "config"
		wildcardTarget = "example.com"
		blocked        = "node-blocked"
		healthy        = "node-healthy"
	)
	smart.InitCache()
	smart.InitQueue()

	s := sweepGroup(group)
	s.configName = config
	s.store = &smart.Store{}
	s.maxFailedTimes = 1
	s.hostFailLimit.Store(0)

	blocking := &C.Metadata{Host: "probe.example.com", WildcardTarget: wildcardTarget}
	s.store.UpdateHostStatus(group, config, wildcardTarget, blocking, blocked, 1, 1_000, true, true, smart.BlockNoResponse, 0)

	metadata := &C.Metadata{
		Host: "probe.example.com", WildcardTarget: wildcardTarget,
		SmartBlock: "normal", NetWork: C.TCP,
	}
	_, _, checked, _ := s.checkNodeQuality(
		nil, metadata, nil, wildcardTarget, "probe.example.com:443", healthy,
		0.9, 0.9, 1_000, 1.0, 1.0, "tcp", false, 0, 0)
	if checked {
		t.Fatal("a clean close on an unblocked node was reported as checked, which writes a host-status update with nothing to clear")
	}
}

// liuran001/mihomo#2. Every Telegram DC matches one rule, so they share one
// bucket, while the node a dial lands on depends on per-destination blocks. With
// node-b excluded for one DC and node-a for another, their dials alternate the
// bucket's winner between the two, and adopting a winner used to close every
// connection in the bucket not on it: each DC's dial killed the other DC's
// working connections, the client redialled, and the pair looped every few
// seconds. A new winner steers later dials and must leave live traffic alone.
func TestAdoptingAWinnerLeavesExistingConnectionsAlone(t *testing.T) {
	const (
		target = "RuleSet [TelegramIP]"
		group  = "adopt-group"
		config = "config"
	)
	smart.InitCache()
	smart.InitQueue()

	s := sweepGroup(group)
	s.configName = config
	s.store = &smart.Store{}
	now := time.Now()

	nodeA, nodeB := &proxyNamed{name: "node-a"}, &proxyNamed{name: "node-b"}
	toDCOne := &C.Metadata{UUID: "dial-dc-1", SmartTarget: target, WildcardTarget: "149.154.167.41"}
	toDCTwo := &C.Metadata{UUID: "dial-dc-2", SmartTarget: target, WildcardTarget: "91.108.56.194"}

	// Live traffic on both nodes, including a connection that looks stuck:
	// winning a dial is no verdict on the node it is on either way.
	onA := newSweepTracker("dc-1-on-a", target, "node-a", group).traffic(now, time.Second, time.Second/2)
	onB := newSweepTracker("dc-2-on-b", target, "node-b", group).stuck(now)
	joinSweepTrackers(t, onA, onB)

	for round := range 4 {
		s.adoptUnwrapWinner(toDCOne, nodeA)
		s.adoptUnwrapWinner(toDCTwo, nodeB)
		if onA.closed || onB.closed {
			t.Fatalf("round %d: adopting a winner closed a live connection (dc-1 closed=%v, dc-2 closed=%v)",
				round, onA.closed, onB.closed)
		}
	}

	// The winner still moves: the next dial for the rule is steered to it.
	if names, _ := s.store.GetUnwrapResult(group, config, target); len(names) == 0 || names[0] != "node-b" {
		t.Fatalf("the bucket's winner is %v, want the most recent winner node-b", names)
	}
}

type proxyNamed struct {
	C.Proxy
	name string
}

func (p *proxyNamed) Name() string { return p.name }

// A swept victim usually reports no error, but one whose first read had already
// failed before the sweep reached it arrives with both an error and the marker.
// Counting that toward the suppressor is not the safe direction: tripping runs
// ClearFloodRecordsByGroup, which throws away the group's queued stat and
// host-status writes.
func TestFloodSuppressorIgnoresSelfClosedConnectionsThatAlsoErrored(t *testing.T) {
	s := sweepGroup("flood-both-ways")
	failure := errors.New("connection reset")
	var now int64 = 1000

	for range floodThreshold * 2 {
		if _, tripped := s.admitConnectionStats(&C.Metadata{SmartBlock: "degraded"}, failure, now); tripped {
			t.Fatal("connections this group closed armed the suppressor and discarded the group's queued writes")
		}
	}
	if proceed, _ := s.admitConnectionStats(&C.Metadata{SmartBlock: "normal"}, failure, now); !proceed {
		t.Fatal("the suppressor engaged on evidence that was entirely self-inflicted")
	}
}
