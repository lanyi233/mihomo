package log

import (
	"testing"
	"time"
)

func BenchmarkDisabledInfo(b *testing.B) {
	previous := Level()
	SetLevel(SILENT)
	b.Cleanup(func() { SetLevel(previous) })
	b.ReportAllocs()
	for b.Loop() {
		Infoln("connection %s -> %s", "source", "destination")
	}
}

func BenchmarkDisabledDebugParallel(b *testing.B) {
	previous := Level()
	SetLevel(INFO)
	b.Cleanup(func() { SetLevel(previous) })
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			DebugEnabled()
		}
	})
}

type formatProbe struct{ calls int }

func (p *formatProbe) String() string {
	p.calls++
	return "formatted"
}

func TestDisabledInfoSkipsFormattingButKeepsSubscribers(t *testing.T) {
	previous := Level()
	SetLevel(SILENT)
	t.Cleanup(func() { SetLevel(previous) })
	probe := &formatProbe{}
	Infoln("%s", probe)
	if probe.calls != 0 {
		t.Fatal("disabled info log still formatted its payload")
	}
	sub := Subscribe()
	defer UnSubscribe(sub)
	Infoln("%s", probe)
	select {
	case event := <-sub:
		if event.LogLevel != INFO || event.Payload != "formatted" || probe.calls != 1 {
			t.Fatalf("unexpected subscriber event: %+v; format calls: %d", event, probe.calls)
		}
	case <-time.After(time.Second):
		t.Fatal("silent output suppressed a live subscriber's info log")
	}
}

func TestDebugEnabledIncludesLiveSubscribers(t *testing.T) {
	oldLevel := Level()
	SetLevel(INFO)
	t.Cleanup(func() { SetLevel(oldLevel) })

	if DebugEnabled() {
		t.Fatal("debug unexpectedly enabled without a subscriber")
	}

	sub := Subscribe()
	if !DebugEnabled() {
		t.Fatal("debug subscriber must keep debug event construction enabled")
	}
	UnSubscribe(sub)

	if DebugEnabled() {
		t.Fatal("debug remained enabled after the last subscriber left")
	}
}
