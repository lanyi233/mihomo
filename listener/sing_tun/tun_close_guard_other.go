//go:build !darwin

package sing_tun

import (
	tun "github.com/metacubex/sing-tun"
)

// guardTunClose is macOS-only: the Linux device reads through its *os.File,
// which the runtime poller already fails cleanly once it is closed.
func guardTunClose(device tun.Tun) tun.Tun {
	return device
}
