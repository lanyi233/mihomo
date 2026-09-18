package outboundgroup

import (
	"errors"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/smart"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

// sweepTracker is the smallest thing statistic.Manager will index and
// closeSameConnection will act on.
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

var _ statistic.Tracker = (*sweepTracker)(nil)

func sweepGroup(name string) *Smart {
	return &Smart{GroupBase: &GroupBase{Base: outbound.NewBase(outbound.BaseOption{Name: name})}}
}

// The non-force sweep closes every connection in the bucket that is not on the
// winning node. Those victims used to be closed without the marker the force
// sweep sets, so unlike force-closed connections they ran the full quality
// check on the way out -- and a connection killed moments after it was
// established has moved no bytes, which the zero-traffic rule reads as a broken
// node and answers with a 24-hour block. Closing a connection is this group's
// own decision; it is not evidence about the node that carried it.
func TestSweepMarksEveryConnectionItCloses(t *testing.T) {
	const target = "RuleSet [Proxy]"
	const group = "smart-group"
	s := sweepGroup(group)

	winner := newSweepTracker("winner", target, "node-a", group)
	loser := newSweepTracker("loser", target, "node-b", group)
	for _, tracker := range []*sweepTracker{winner, loser} {
		statistic.DefaultManager.Join(tracker)
		defer statistic.DefaultManager.Leave(tracker)
	}

	dialer := &C.Metadata{UUID: "dialer", SmartTarget: target}
	s.closeSameConnection(dialer, "node-a", target, "", false)

	if !loser.closed {
		t.Fatal("the sweep left a connection on a losing node open")
	}
	if loser.block() != "degraded" {
		t.Fatalf("a connection the group closed itself is marked %q, so its close is read as the node's fault", loser.block())
	}
	if winner.closed {
		t.Fatal("the sweep closed a connection already on the winning node")
	}
	if winner.block() != "normal" {
		t.Fatalf("an untouched connection was marked %q", winner.block())
	}
}

// The force sweep is the one that answers a degrade, and it takes the whole
// bucket -- winning node included.
func TestForceSweepTakesTheWholeTargetAndMarksIt(t *testing.T) {
	const target = "RuleSet [Proxy]"
	const group = "smart-group"
	s := sweepGroup(group)

	onWinner := newSweepTracker("on-winner", target, "node-a", group)
	elsewhere := newSweepTracker("elsewhere", target, "node-b", group)
	for _, tracker := range []*sweepTracker{onWinner, elsewhere} {
		statistic.DefaultManager.Join(tracker)
		defer statistic.DefaultManager.Leave(tracker)
	}

	dialer := &C.Metadata{UUID: "dialer", SmartTarget: target}
	s.closeSameConnection(dialer, "node-a", target, "", true)

	for _, tracker := range []*sweepTracker{onWinner, elsewhere} {
		if !tracker.closed {
			t.Fatalf("force sweep spared %q", tracker.id)
		}
		if tracker.block() != "degraded" {
			t.Fatalf("force sweep left %q marked %q", tracker.id, tracker.block())
		}
	}
}

// A connection belonging to another group shares the bucket but not the blame.
func TestSweepIgnoresConnectionsOutsideTheGroup(t *testing.T) {
	const target = "RuleSet [Proxy]"
	s := sweepGroup("smart-group")

	foreign := newSweepTracker("foreign", target, "node-b", "another-group")
	statistic.DefaultManager.Join(foreign)
	defer statistic.DefaultManager.Leave(foreign)

	dialer := &C.Metadata{UUID: "dialer", SmartTarget: target}
	s.closeSameConnection(dialer, "node-a", target, "", true)

	if foreign.closed {
		t.Fatal("the sweep closed a connection that is not in this group's chain")
	}
	if foreign.block() != "normal" {
		t.Fatalf("the sweep marked a connection outside the group as %q", foreign.block())
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
			s.store.UpdateHostStatus(group, config, wildcardTarget, blocking, node, 1, 1_000, true, true, smart.BlockNoResponse)
			if failNodes, _, _, _ := s.store.GetHostStatus(group, config, wildcardTarget, 1_000); failNodes[node] == 0 {
				t.Fatal("fixture did not block the node")
			}

			metadata := &C.Metadata{
				Host: "probe.example.com", WildcardTarget: wildcardTarget,
				SmartBlock: "normal", NetWork: C.TCP,
			}
			_, isDegraded, checked, blockCode := s.checkNodeQuality(
				nil, metadata, nil, wildcardTarget, "probe.example.com:443", node,
				0.9, 0.9, 1_000, 1.0, 1.0, "tcp", "", false, 0, 0)

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
	s.store.UpdateHostStatus(group, config, wildcardTarget, blocking, node, 1, 1_000, true, true, smart.BlockNoResponse)

	metadata := &C.Metadata{
		Host: "probe.example.com", WildcardTarget: wildcardTarget,
		SmartBlock: "normal", NetWork: C.TCP,
	}
	_, isDegraded, checked, blockCode := s.checkNodeQuality(
		errors.New("connection reset"), metadata, nil, wildcardTarget, "probe.example.com:443", node,
		0.9, 0.9, 1_000, 1.0, 1.0, "tcp", "", false, 0, 0)

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
	s.store.UpdateHostStatus(group, config, wildcardTarget, blocking, blocked, 1, 1_000, true, true, smart.BlockNoResponse)

	metadata := &C.Metadata{
		Host: "probe.example.com", WildcardTarget: wildcardTarget,
		SmartBlock: "normal", NetWork: C.TCP,
	}
	_, _, checked, _ := s.checkNodeQuality(
		nil, metadata, nil, wildcardTarget, "probe.example.com:443", healthy,
		0.9, 0.9, 1_000, 1.0, 1.0, "tcp", "", false, 0, 0)
	if checked {
		t.Fatal("a clean close on an unblocked node was reported as checked, which writes a host-status update with nothing to clear")
	}
}

// The sweep exists to move traffic onto a new winner. When the winner has not
// moved there is nothing to move, and scanning anyway costs dial-rate x
// bucket-size per dial -- and the bucket, keyed by the matched rule, grows with
// the dial rate too. A connection a parallel dial placed elsewhere after the
// winner settled now survives; that is working traffic, and killing it was the
// churn this whole area is trying to stop.
func TestAdoptingAnUnchangedWinnerDoesNotSweep(t *testing.T) {
	const (
		target = "RuleSet [Proxy]"
		group  = "adopt-group"
		config = "config"
	)
	smart.InitCache()
	smart.InitQueue()

	s := sweepGroup(group)
	s.configName = config
	s.store = &smart.Store{}

	winner := &proxyNamed{name: "node-a"}
	dialer := &C.Metadata{UUID: "dialer", SmartTarget: target, WildcardTarget: "example.com"}

	// First adopt: records the winner.
	s.adoptUnwrapWinner(dialer, "", winner)

	// A connection lands on another node afterwards.
	straggler := newSweepTracker("straggler", target, "node-b", group)
	statistic.DefaultManager.Join(straggler)
	defer statistic.DefaultManager.Leave(straggler)

	// Second adopt, same winner: nothing to consolidate.
	s.adoptUnwrapWinner(dialer, "", winner)
	if straggler.closed {
		t.Fatal("a dial that changed nothing still swept the bucket")
	}

	// A winner that actually moves still sweeps.
	s.adoptUnwrapWinner(dialer, "", &proxyNamed{name: "node-c"})
	if !straggler.closed {
		t.Fatal("a changed winner did not consolidate traffic onto it")
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
