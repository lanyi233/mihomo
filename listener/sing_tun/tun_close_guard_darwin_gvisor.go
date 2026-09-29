//go:build darwin && with_gvisor

package sing_tun

import (
	tun "github.com/metacubex/sing-tun"
)

// The mixed stack asserts GVisorTun on the device without checking, so losing
// the promoted methods would be a panic at startup rather than a build error.
var _ tun.GVisorTun = (*guardedNativeTun)(nil)
