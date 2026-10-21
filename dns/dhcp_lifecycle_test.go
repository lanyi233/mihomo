package dns

import (
	"sync"
	"testing"
	"time"
)

func TestDHCPReadersDuringRefresh(t *testing.T) {
	d := &dhcpClient{}
	clients := []dnsClient{&gatedClient{}}
	var workers sync.WaitGroup
	workers.Go(func() {
		for n := 0; n < 1000; n++ {
			d.lock.Lock()
			d.clients = clients
			d.lock.Unlock()
			d.lock.Lock()
			d.clients = nil
			d.lock.Unlock()
		}
	})
	for n := 0; n < 4; n++ {
		workers.Go(func() {
			for n := 0; n < 1000; n++ {
				d.Address()
				d.ResetConnection()
			}
		})
	}
	workers.Wait()
}

func TestDHCPInflightRefreshPreservesDeadlines(t *testing.T) {
	deadline := time.Now().Add(-time.Second)
	d := &dhcpClient{
		ifaceName: "missing-interface", done: make(chan struct{}),
		ifaceInvalidate: deadline, dnsInvalidate: deadline,
	}
	invalidated, err := d.invalidate()
	if invalidated || err != nil {
		t.Fatalf("in-flight refresh invalidated=%v, err=%v", invalidated, err)
	}
	if d.ifaceInvalidate != deadline || d.dnsInvalidate != deadline {
		t.Fatal("in-flight refresh changed its lease deadlines")
	}
}
