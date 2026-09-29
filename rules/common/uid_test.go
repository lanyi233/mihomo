package common

import (
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// "could not get uid" is for a connection whose uid is unknown. A known uid that
// is simply another user's must not be reported as missing: with several UID
// rules every such connection logged one warning per rule (issue #3135).
func TestUidRuleOnlyWarnsWhenTheUidIsUnknown(t *testing.T) {
	uids, err := utils.NewUnsignedRanges[uint32]("1000")
	if err != nil {
		t.Fatal(err)
	}
	// Built by hand: NewUid refuses to build off Linux.
	rule := &Uid{uids: uids, oUid: "1000", adapter: "REJECT"}

	subscription := log.Subscribe()
	defer log.UnSubscribe(subscription)

	known := &C.Metadata{NetWork: C.TCP, Host: "known-uid.example", DstPort: 443, Uid: 1001}
	if matched, _ := rule.Match(known, C.RuleMatchHelper{}); matched {
		t.Fatal("uid 1001 must not match UID,1000")
	}
	unknown := &C.Metadata{NetWork: C.TCP, Host: "missing-uid.example", DstPort: 443}
	if matched, _ := rule.Match(unknown, C.RuleMatchHelper{}); matched {
		t.Fatal("an unknown uid must not match UID,1000")
	}
	if matched, adapter := rule.Match(&C.Metadata{Uid: 1000}, C.RuleMatchHelper{}); !matched || adapter != "REJECT" {
		t.Fatalf("uid 1000 must match UID,1000,REJECT, got %v %q", matched, adapter)
	}

	// The log bus is process-wide and ordered, so reading up to the line for the
	// unknown uid shows whether one for the known uid came before it.
	timeout := time.After(5 * time.Second)
	for {
		select {
		case event, ok := <-subscription:
			if !ok {
				t.Fatal("log subscription closed")
			}
			if strings.Contains(event.Payload, known.String()) {
				t.Fatalf("a known but non-matching uid was logged as missing: %q", event.Payload)
			}
			if strings.Contains(event.Payload, "could not get uid from "+unknown.String()) {
				return
			}
		case <-timeout:
			t.Fatal("timed out waiting for the warning about the unknown uid")
		}
	}
}
