//go:build with_ebpf && linux && ebpf_integration

package sing_ebpf

import (
	"errors"
	"net"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netns"
)

func TestTCNamespaceLifetimeIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires CAP_SYS_ADMIN")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	n, err := NewTCNamespace()
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if n.Path() == "" {
		t.Fatal("missing namespace path")
	}
	checkHost := func() {
		t.Helper()
		current, err := netns.Get()
		if err != nil {
			t.Fatal(err)
		}
		defer current.Close()
		if !original.Equal(current) {
			t.Fatal("caller changed namespace")
		}
	}
	checkHost()
	var host, isolated net.Listener
	host, err = net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	err = n.with(func() error {
		current, err := netns.Get()
		if err != nil {
			return err
		}
		defer current.Close()
		if original.Equal(current) {
			return errors.New("namespace was not isolated")
		}
		isolated, err = net.Listen("tcp4", host.Addr().String())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	defer isolated.Close()
	checkHost()
	want := errors.New("callback failure")
	if err = n.with(func() error { return want }); !errors.Is(err, want) {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() != "test panic" {
				t.Error("panic not propagated")
			}
		}()
		_ = n.with(func() error { panic("test panic") })
	}()
	checkHost()
	if err = n.with(func() error { runtime.Goexit(); return nil }); err == nil {
		t.Fatal("Goexit not reported")
	}
	checkHost()
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
	if n.Path() != "" {
		t.Fatal("closed namespace still advertised")
	}
	if err = n.with(func() error { t.Error("closed callback invoked"); return nil }); !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
	if err = n.Close(); err != nil {
		t.Fatal(err)
	}
}
