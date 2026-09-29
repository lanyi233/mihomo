package sing_tun

import (
	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
)

// guardedNativeTun embeds the device so everything the stacks assert for
// besides DarwinTUN -- GVisorTun for the gvisor and mixed stacks -- is still
// promoted from it.
type guardedNativeTun struct {
	*tun.NativeTun
	guard closeGuard
}

var _ tun.DarwinTUN = (*guardedNativeTun)(nil)

func (t *guardedNativeTun) BatchRead() ([]*buf.Buffer, error) {
	return t.guard.batchRead(t.NativeTun)
}

func (t *guardedNativeTun) BatchWrite(buffers []*buf.Buffer) error {
	return t.guard.batchWrite(t.NativeTun, buffers)
}

func (t *guardedNativeTun) Close() error {
	return t.guard.close(t.NativeTun)
}

// guardTunClose wraps the utun in closeGuard; see there.
func guardTunClose(device tun.Tun) tun.Tun {
	if native, isNative := device.(*tun.NativeTun); isNative {
		return &guardedNativeTun{NativeTun: native}
	}
	return device
}
