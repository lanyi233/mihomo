//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"os"
	"strings"

	E "github.com/metacubex/sing/common/exceptions"
)

func sharedArpAnnouncePath(interfaceName string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/arp_announce"
}

// raiseSharedArpAnnounce sets arp_announce=2 on the downstream interface.
//
// Redirected IPv4 replies carry a source address from the loopback redirect
// pool (127.128.0.0/9); with the default arp_announce=0 the kernel uses that
// packet source as the ARP sender address when resolving the LAN client, and
// clients discard such martian ARP requests, blackholing return traffic until
// the client refreshes the gateway neighbor entry itself. arp_announce=2
// makes the kernel always pick the interface's own primary address instead.
// It returns the original value to restore on detach, or "" when no change
// was made.
func raiseSharedArpAnnounce(interfaceName string) (string, error) {
	path := sharedArpAnnouncePath(interfaceName)
	value, err := os.ReadFile(path)
	if err != nil {
		return "", E.Cause(err, "read arp_announce for ", interfaceName)
	}
	original := strings.TrimSpace(string(value))
	if original == "2" {
		return "", nil
	}
	if err = os.WriteFile(path, []byte("2"), 0o644); err != nil {
		return "", E.Cause(err, "raise arp_announce for ", interfaceName)
	}
	return original, nil
}

// restoreSharedArpAnnounce puts the recorded value back, unless someone else
// changed the setting in the meantime.
func restoreSharedArpAnnounce(interfaceName string, original string) error {
	if original == "" {
		return nil
	}
	path := sharedArpAnnouncePath(interfaceName)
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "read arp_announce for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) != "2" {
		return nil
	}
	if err = os.WriteFile(path, []byte(original), 0o644); err != nil {
		return E.Cause(err, "restore arp_announce for ", interfaceName)
	}
	return nil
}
