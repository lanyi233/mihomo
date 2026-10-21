//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/sagernet/netlink"
)

const (
	sharedRewriteIngressFilterHandle = 0x5342
	sharedRewriteEgressFilterHandle  = 0x5343
	sharedRewriteICMPFilterHandle    = 0x5341
)

type sharedRewriteDataPlane struct {
	access        sync.Mutex
	owner         *sharedRewrite
	backend       *ECommon.SharedNetworkBackend
	retired       []*sharedRewriteAttachment
	attachments   map[string]*sharedRewriteAttachment
	hostAddresses []netip.Addr
	priority      uint16
	enabled       bool
	ready         bool
}

type sharedRewriteAttachment struct {
	interfaceName  string
	interfaceIndex int
	lock           io.Closer
	ingressFilter  *netlink.BpfFilter
	egressFilter   *netlink.BpfFilter
	ingressName    string
	egressName     string
	icmpName       string
	ingressHandle  uint16
	egressHandle   uint16
	icmpHandle     uint16
	ingressLink    link.Link
	egressLink     link.Link
	// icmpFilter/icmpLink are the fakeip_icmp shared-reply filter, attached
	// alongside ingressFilter/ingressLink (same interface, same direction)
	// only when backend.FakeIPICMPEnabled(); nil whenever that feature is
	// off, the same as every other field here is nil when it does not apply.
	icmpFilter     *netlink.BpfFilter
	icmpLink       link.Link
	localnetLease  *ECommon.InstanceLease
	arpLease       *ECommon.InstanceLease
	attachmentType string
}

func newSharedRewriteDataPlane(owner *sharedRewrite, priority uint16) *sharedRewriteDataPlane {
	return &sharedRewriteDataPlane{
		owner:       owner,
		attachments: make(map[string]*sharedRewriteAttachment),
		priority:    priority,
	}
}

func (d *sharedRewriteDataPlane) reconcile(interfaceNames []string, hostAddresses []netip.Addr) error {
	if d == nil {
		return nil
	}
	d.owner.lifecycleAccess.Lock()
	defer d.owner.lifecycleAccess.Unlock()
	d.access.Lock()
	defer d.access.Unlock()

	desired := make(map[string]netlink.Link, len(interfaceNames))
	for _, interfaceName := range interfaceNames {
		device, err := netlink.LinkByName(interfaceName)
		if tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return E.Cause(err, "find shared packet-rewrite interface ", interfaceName)
		}
		framing, err := tcLinkFraming(device)
		if err != nil {
			return err
		}
		if framing != ECommon.TCLinkFramingEthernet {
			return E.New("shared packet-rewrite interface ", interfaceName, " must use Ethernet framing")
		}
		desired[interfaceName] = device
	}

	backend := d.backend
	newBackend := false
	if len(desired) > 0 && backend == nil {
		var err error
		backend, err = d.owner.prepareBackend()
		if err != nil {
			return E.Cause(err, "initialize shared packet-rewrite backend")
		}
		newBackend = true
	}
	hostChanged := backend != nil && !slices.Equal(d.hostAddresses, hostAddresses)
	if hostChanged {
		if err := backend.UpdateHostAddresses(hostAddresses); err != nil {
			if newBackend {
				return E.Errors(
					E.Cause(err, "update shared packet-rewrite host addresses"),
					discardSharedRewriteBackend(d.owner, backend),
				)
			}
			return E.Cause(err, "update shared packet-rewrite host addresses")
		}
	}

	current := make(map[string]*sharedRewriteAttachment, len(d.attachments))
	for name, attachment := range d.attachments {
		current[name] = attachment
	}
	candidate := make(map[string]*sharedRewriteAttachment, len(desired))
	created := make([]*sharedRewriteAttachment, 0, len(desired))
	retired := make([]*sharedRewriteAttachment, 0, len(d.attachments))
	changed := hostChanged
	names := make([]string, 0, len(desired))
	for name := range desired {
		names = append(names, name)
	}
	slices.Sort(names)

	cleanupCandidates := func(cause error) error {
		for _, attachment := range slices.Backward(created) {
			if err := attachment.Close(); err != nil {
				cause = E.Errors(cause, err)
				d.retired = append(d.retired, attachment)
			}
		}
		if hostChanged {
			rollbackErr := backend.UpdateHostAddresses(d.hostAddresses)
			if rollbackErr != nil {
				cause = E.Errors(cause, E.Cause(rollbackErr, "rollback shared packet-rewrite host addresses"))
			}
		}
		if newBackend {
			if len(d.retired) > 0 {
				d.backend = backend
			} else {
				cause = E.Errors(cause, discardSharedRewriteBackend(d.owner, backend))
			}
		}
		return cause
	}

	for _, name := range names {
		device := desired[name]
		previous := current[name]
		if previous != nil && device.Attrs().Index == previous.interfaceIndex {
			if err := claimSharedRewriteLocalnet(name, &previous.localnetLease); err != nil {
				return cleanupCandidates(err)
			}
			if err := claimSharedArpAnnounce(name, &previous.arpLease); err != nil {
				return cleanupCandidates(err)
			}
			healthy, err := previous.healthy(device, d.priority, backend.FakeIPICMPEnabled())
			if err != nil {
				return cleanupCandidates(E.Cause(err, "inspect shared packet-rewrite attachment on ", name))
			}
			if healthy {
				candidate[name] = previous
				delete(current, name)
				continue
			}
		}
		if previous != nil {
			retired = append(retired, previous)
		}
		attachment, err := attachSharedRewriteInterface(device, backend, d.priority)
		if err != nil {
			if attachment != nil {
				created = append(created, attachment)
			}
			return cleanupCandidates(E.Cause(err, "attach shared packet-rewrite interface ", name))
		}
		candidate[name] = attachment
		created = append(created, attachment)
		changed = true
	}
	for _, previous := range current {
		retired = append(retired, previous)
		changed = true
	}

	wantEnabled := len(candidate) > 0
	if wantEnabled != d.enabled {
		var err error
		if wantEnabled {
			err = backend.Enable()
		} else if backend != nil {
			err = backend.Disable()
		}
		if err != nil {
			return cleanupCandidates(err)
		}
		changed = true
	}

	var closeErr error
	pending := append(d.retired, retired...)
	d.retired = nil
	for _, previous := range pending {
		if err := d.detachLocked(previous); err != nil {
			closeErr = E.Errors(closeErr, err)
			d.retired = append(d.retired, previous)
		}
	}

	d.backend = backend
	d.attachments = candidate
	d.hostAddresses = slices.Clone(hostAddresses)
	d.enabled = wantEnabled
	if changed {
		d.owner.purgeUDP()
	}
	if d.enabled && !d.ready {
		d.ready = true
		d.owner.sharedRewriteReadyLocked(d.attachmentDescriptionsLocked())
	}
	return closeErr
}

func discardSharedRewriteBackend(owner *sharedRewrite, backend *ECommon.SharedNetworkBackend) error {
	if backend == nil {
		return nil
	}
	if owner.sharedBackendInstance() == backend {
		owner.takeSharedBackend()
	}
	return backend.Close()
}

func (d *sharedRewriteDataPlane) detachLocked(attachment *sharedRewriteAttachment) error {
	if d.backend != nil {
		if _, _, err := d.backend.PurgeInterfaceFlows(uint32(attachment.interfaceIndex), d.backend.MapCapacity().Proxy); err != nil {
			d.owner.janitorWarnings.warn(d.owner.inbound.logWarn, "purge shared packet-rewrite state for ", attachment.interfaceName, ": ", err)
		}
	}
	return attachment.Close()
}

func (d *sharedRewriteDataPlane) isEnabled() bool {
	if d == nil {
		return false
	}
	d.access.Lock()
	defer d.access.Unlock()
	return d.enabled
}

func (d *sharedRewriteDataPlane) attachmentDescriptions() []string {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	return d.attachmentDescriptionsLocked()
}

func (d *sharedRewriteDataPlane) attachmentDescriptionsLocked() []string {
	descriptions := make([]string, 0, len(d.attachments))
	for _, attachment := range d.attachments {
		descriptions = append(descriptions, attachment.interfaceName+"("+attachment.attachmentType+")")
	}
	slices.Sort(descriptions)
	return descriptions
}

func (d *sharedRewriteDataPlane) IsClosed() bool {
	if d == nil {
		return true
	}
	d.access.Lock()
	defer d.access.Unlock()
	return !d.enabled && len(d.attachments) == 0 && len(d.retired) == 0
}

func (d *sharedRewriteDataPlane) Close() error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	var closeErr error
	if d.enabled && d.backend != nil {
		closeErr = d.backend.Disable()
		if closeErr == nil {
			d.enabled = false
		}
	}
	for name, attachment := range d.attachments {
		if err := d.detachLocked(attachment); err != nil {
			closeErr = E.Errors(closeErr, err)
			d.retired = append(d.retired, attachment)
		}
		delete(d.attachments, name)
	}
	pending := d.retired
	d.retired = nil
	for _, attachment := range pending {
		if err := attachment.Close(); err != nil {
			closeErr = E.Errors(closeErr, err)
			d.retired = append(d.retired, attachment)
		}
	}
	return closeErr
}

func attachSharedRewriteInterface(
	device netlink.Link,
	backend *ECommon.SharedNetworkBackend,
	priority uint16,
) (*sharedRewriteAttachment, error) {
	name := device.Attrs().Name
	attachment := &sharedRewriteAttachment{interfaceName: name, interfaceIndex: device.Attrs().Index}
	var err error
	cleanup := func(err error) (*sharedRewriteAttachment, error) {
		if closeErr := attachment.Close(); closeErr != nil {
			return attachment, E.Errors(err, closeErr)
		}
		return nil, err
	}
	interfaceLock, err := acquireTCInterfaceLock(name, device.Attrs().Index)
	if err != nil {
		return nil, err
	}
	attachment.lock = interfaceLock
	slot := tcLockSlot(attachment.lock)
	ingress := tcSlotFilter(slot, 0, tcFilterRoleRewriteIngress)
	egress := tcSlotFilter(slot, 0, tcFilterRoleRewriteEgress)
	icmp := tcSlotFilter(slot, 0, tcFilterRoleRewriteICMP)
	attachment.ingressName, attachment.ingressHandle = ingress.name, ingress.handle
	attachment.egressName, attachment.egressHandle = egress.name, egress.handle
	attachment.icmpName, attachment.icmpHandle = icmp.name, icmp.handle
	err = claimSharedRewriteLocalnet(name, &attachment.localnetLease)
	if err != nil {
		return cleanup(err)
	}
	err = claimSharedArpAnnounce(name, &attachment.arpLease)
	if err != nil {
		return cleanup(err)
	}
	if tcxSupport.Load() != tcxSupportUnavailable {
		attachment.egressLink, err = ECommon.AttachTCXOrdered(device.Attrs().Index, CiliumEBPF.AttachTCXEgress, backend.EgressProgram(), priority)
		if err == nil {
			attachment.ingressLink, err = ECommon.AttachTCXOrdered(device.Attrs().Index, CiliumEBPF.AttachTCXIngress, backend.IngressProgram(), priority)
		}
		if err == nil && backend.FakeIPICMPEnabled() {
			attachment.icmpLink, err = ECommon.AttachTCXOrdered(device.Attrs().Index, CiliumEBPF.AttachTCXIngress, backend.FakeIPICMPSharedReplyProgram(ECommon.TCLinkFramingEthernet), priority)
		}
		if err == nil {
			tcxSupport.Store(tcxSupportAvailable)
			attachment.attachmentType = "tcx"
			return attachment, nil
		}
		if closeErr := attachment.closeLinks(); closeErr != nil {
			return cleanup(E.Errors(err, closeErr))
		}
		if !tcxUnsupportedError(err) && !errors.Is(err, ECommon.ErrTCXOrderUnavailable) {
			return cleanup(err)
		}
		if tcxUnsupportedError(err) {
			tcxSupport.CompareAndSwap(tcxSupportUnknown, tcxSupportUnavailable)
		}
	}
	if err = ensureTCClsact(device); err != nil {
		return cleanup(err)
	}
	attachment.egressFilter, err = attachTCFilter(device, netlink.HANDLE_MIN_EGRESS, backend.EgressProgramFD(), attachment.egressName, attachment.egressHandle, priority)
	if err != nil {
		return cleanup(err)
	}
	attachment.ingressFilter, err = attachTCFilter(device, netlink.HANDLE_MIN_INGRESS, backend.IngressProgramFD(), attachment.ingressName, attachment.ingressHandle, priority)
	if err != nil {
		return cleanup(err)
	}
	if backend.FakeIPICMPEnabled() {
		attachment.icmpFilter, err = attachTCFilter(
			device,
			netlink.HANDLE_MIN_INGRESS,
			backend.FakeIPICMPSharedReplyProgramFD(ECommon.TCLinkFramingEthernet),
			attachment.icmpName,
			attachment.icmpHandle,
			priority,
		)
		if err != nil {
			return cleanup(err)
		}
	}
	attachment.attachmentType = "clsact"
	return attachment, nil
}

// healthy reports whether every program this attachment installed is still
// attached. fakeIPICMPEnabled comes from the backend: when the feature is off
// a nil icmpLink/icmpFilter is the correct state rather than a fault, so the
// ICMP check is skipped entirely.
func (a *sharedRewriteAttachment) healthy(device netlink.Link, priority uint16, fakeIPICMPEnabled bool) (bool, error) {
	if a.ingressLink != nil || a.egressLink != nil {
		ingress, err := tcxLinkAttached(a.ingressLink, a.interfaceIndex, CiliumEBPF.AttachTCXIngress)
		if err != nil || !ingress {
			return false, err
		}
		egress, err := tcxLinkAttached(a.egressLink, a.interfaceIndex, CiliumEBPF.AttachTCXEgress)
		if err != nil || !egress || !fakeIPICMPEnabled {
			return egress, err
		}
		return tcxLinkAttached(a.icmpLink, a.interfaceIndex, CiliumEBPF.AttachTCXIngress)
	}
	ingress, err := tcFilterAttached(device, netlink.HANDLE_MIN_INGRESS, a.ingressName, a.ingressHandle, priority)
	if err != nil || !ingress {
		return false, err
	}
	egress, err := tcFilterAttached(device, netlink.HANDLE_MIN_EGRESS, a.egressName, a.egressHandle, priority)
	if err != nil || !egress || !fakeIPICMPEnabled {
		return egress, err
	}
	return tcFilterAttached(device, netlink.HANDLE_MIN_INGRESS, a.icmpName, a.icmpHandle, priority)
}

func (a *sharedRewriteAttachment) closeLinks() error {
	return E.Errors(closeOwned(&a.ingressLink), closeOwned(&a.egressLink), closeOwned(&a.icmpLink))
}

func (a *sharedRewriteAttachment) Close() error {
	if a == nil {
		return nil
	}
	closeErr := E.Errors(a.closeLinks(), detachTCFilterOwned(&a.ingressFilter, detachTCFilter), detachTCFilterOwned(&a.egressFilter, detachTCFilter), detachTCFilterOwned(&a.icmpFilter, detachTCFilter))
	if closeErr != nil {
		return closeErr
	}
	closeErr = E.Errors(releaseSharedRewriteLocalnet(a.interfaceName, &a.localnetLease), releaseSharedArpAnnounce(a.interfaceName, &a.arpLease))
	if closeErr != nil {
		return closeErr
	}
	closeErr = closeOwned(&a.lock)
	return closeErr
}

func sharedRewriteLocalnetPath(interfaceName string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/route_localnet"
}

func ensureSharedRewriteLocalnet(interfaceName string) (bool, error) {
	value, err := os.ReadFile(sharedRewriteLocalnetPath(interfaceName))
	if err != nil {
		return false, E.Cause(err, "read route_localnet for ", interfaceName)
	}
	switch strings.TrimSpace(string(value)) {
	case "1":
		return false, nil
	case "0":
		if err = os.WriteFile(sharedRewriteLocalnetPath(interfaceName), []byte("1"), 0o644); err != nil {
			return false, E.Cause(err, "enable route_localnet for ", interfaceName)
		}
		return true, nil
	default:
		return false, E.New("unexpected route_localnet value for ", interfaceName)
	}
}

func restoreSharedRewriteLocalnet(interfaceName string) error {
	path := sharedRewriteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) != "1" {
		return nil
	}
	if err = os.WriteFile(path, []byte("0"), 0o644); err != nil {
		return E.Cause(err, "restore route_localnet for ", interfaceName)
	}
	return nil
}
