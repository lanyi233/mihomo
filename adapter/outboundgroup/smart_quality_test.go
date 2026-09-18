package outboundgroup

import (
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/smart"
	C "github.com/metacubex/mihomo/constant"
)

// The rule is meant to catch a node that accepts a flow and then swallows it.
// Requiring zero upload inverted the attribution: if the client never sent a
// byte the node had nothing to answer, so every speculative TLS connection a
// browser opens and closes unused cost the node a 24-hour block. The fork's
// own stall detector draws the line the same way.
func TestNoResponseVerdictNeedsTheClientToHaveSentSomething(t *testing.T) {
	const (
		group          = "quality-group"
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	smart.InitCache()
	smart.InitQueue()

	for _, testCase := range []struct {
		name         string
		uploadTotal  float64
		wantDegraded bool
		wantCode     smart.BlockCode
	}{
		{name: "client sent nothing", uploadTotal: 0, wantDegraded: false, wantCode: smart.BlockNone},
		{name: "client sent a request and got nothing back", uploadTotal: 1, wantDegraded: true, wantCode: smart.BlockNoResponse},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			s := sweepGroup(group + testCase.name)
			s.configName = config
			s.store = &smart.Store{}
			s.maxFailedTimes = 3
			s.hostFailLimit.Store(1_000)

			// Host is empty so the abnormal-status branch below cannot run a
			// live StatusTest through a nil proxy.
			metadata := &C.Metadata{
				WildcardTarget: wildcardTarget, SmartBlock: "normal",
				NetWork: C.TCP, DstPort: 443,
			}
			_, isDegraded, _, blockCode := s.checkNodeQuality(
				nil, metadata, nil, wildcardTarget, "example.com:443", node,
				0.9, 0.9, 1_000, testCase.uploadTotal, 0, "tcp", "", false, 0, 0)

			if isDegraded != testCase.wantDegraded || blockCode != testCase.wantCode {
				t.Fatalf("degraded=%v code=%d, want %v and %d",
					isDegraded, blockCode, testCase.wantDegraded, testCase.wantCode)
			}
		})
	}
}

// blameTestProxy reports a type recordConnectionStats returns on immediately,
// so the test exercises the markCloseFailure branch alone.
type blameTestProxy struct {
	C.Proxy
	name string
}

func (p blameTestProxy) Name() string        { return p.name }
func (p blameTestProxy) Type() C.AdapterType { return C.Reject }

// A connection this group closed itself says nothing about the node that
// carried it. checkNodeQuality honours the degraded marker; the close-failure
// path did not, so a victim whose first read had already failed before the
// sweep reached it was blamed anyway.
func TestASweptConnectionIsNotBlamedForItsCloseError(t *testing.T) {
	const (
		config         = "config"
		wildcardTarget = "example.com"
		node           = "node-a"
	)
	smart.InitCache()
	smart.InitQueue()

	for _, testCase := range []struct {
		name       string
		smartBlock string
		wantBlamed bool
	}{
		{name: "closed by this group", smartBlock: "degraded", wantBlamed: false},
		{name: "closed by the network", smartBlock: "normal", wantBlamed: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			group := "blame-group-" + testCase.name
			s := sweepGroup(group)
			s.configName = config
			s.store = &smart.Store{}
			s.maxFailedTimes = 1

			metadata := &C.Metadata{
				Host: "probe.example.com", WildcardTarget: wildcardTarget,
				SmartBlock: testCase.smartBlock, NetWork: C.TCP,
			}
			if !s.submitConnectionStats(metadata, blameTestProxy{name: node},
				0, 0, 0, 0, 0, 0, 1_000, nil, errors.New("connection reset"), true) {
				t.Fatal("submission was refused")
			}
			s.workWG.Wait()

			failNodes, _, _, _ := s.store.GetHostStatus(group, config, wildcardTarget, 1_000)
			if blamed := failNodes[node] != 0; blamed != testCase.wantBlamed {
				t.Fatalf("blamed=%v (code %d), want %v", blamed, failNodes[node], testCase.wantBlamed)
			}
		})
	}
}
