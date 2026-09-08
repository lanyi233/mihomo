//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/metacubex/mihomo/adapter/inbound"
	ECommon "github.com/metacubex/mihomo/common/ebpf"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"

	"go4.org/netipx"
)

// Listener is the eBPF inbound listener.
type Listener interface {
	Close() error
	Address() string
	InterfaceUpdated()
}

type Inbound struct {
	ctx             context.Context
	tunnel          C.Tunnel
	additions       []inbound.Addition
	mode            string
	localEnabled    bool
	localDataPlane  string
	cgroupPath      string
	sharedEnabled   bool
	sharedDataPlane string
	enableTCP       bool
	enableUDP       bool

	localDNSMode        string
	sharedDNSMode       string
	localIPv6           bool
	sharedIPv6          bool
	sharedBypassPrivate bool
	tcPriority          uint16
	localPolicy         ECommon.LocalPolicy
	compiledPolicy      ECommon.CompiledPolicy
	sharedOptions       LC.EBPFShared
	sharedIncludeMAC    []ECommon.MACAddress
	sharedExcludeMAC    []ECommon.MACAddress
	localBypassPort     []ECommon.PortRange
	sharedBypassPort    []ECommon.PortRange
	fakeIPIPv4Prefix    netip.Prefix
	fakeIPIPv6Prefix    netip.Prefix
	redirectIPv4Prefix  netip.Prefix
	redirectIPv6Prefix  netip.Prefix
	androidUIDOptions   *androidUIDOptions
	udpTimeout          time.Duration
	bypassTUNDirect     bool
	localStateCapacity  uint32
	sharedStateCapacity uint32

	// policyAccess guards compiledPolicy and the fake-ip prefixes once the
	// inbound is running: the fake-ip observer rewrites them while a shared
	// data plane may be building a backend from the snapshot.
	policyAccess sync.RWMutex

	selfBypass       *ECommon.SelfBypass
	selfBypassCgroup bool
	processTracker   *ECommon.ProcessTracker

	listeners         internalListenerSet
	udpClientTable    udpClientTable
	udpReplySockets   udpReplySocketPool
	udpWarnings       udpWarningLimiters
	interfaceWarnings interfaceWarningLimiters

	cgroupBackend       *ECommon.CgroupBackend
	cgroupBackendAccess sync.RWMutex
	tcDataPlane         *tcDataPlane
	tcDataPlaneAccess   sync.RWMutex
	interfaceMonitor    tcInterfaceMonitor
	lifecycleAccess     sync.RWMutex
	localRoutes         []*localRoute

	sharedRewrite *sharedRewrite

	bypassRuleSetAccess   sync.Mutex
	bypassRuleSet         []P.RuleProvider
	bypassRuleSetCallback io.Closer
	bypassRuleSetStarted  bool
	bypassCIDR            []netip.Prefix
	bypassRuleSetPolicy   ECommon.BypassCIDRPolicy
	bypassRuleSetDirty    bool

	// TUN coexistence and fake-ip tracking, see tun_coexist.go and fakeip.go.
	fakeIPRangeRemove  func()
	tunOverlapWarnings warningLimiter
	bypassPublisher    *resolver.EBPFBypassPublisher
	dnsBypassSet       *netipx.IPSet

	protectRegistered bool

	closeOnce sync.Once
}

type interfaceWarningLimiters struct {
	inventory        warningLimiter
	topology         warningLimiter
	defaultInterface warningLimiter
	infrastructure   warningLimiter
	hostPolicy       warningLimiter
	reconcile        warningLimiter
}

func (i *Inbound) logWarn(format string, args ...any) {
	log.Warnln(format, args...)
}

func (i *Inbound) localTCEnabled() bool {
	return i.localEnabled && i.localDataPlane == localDataPlaneTC
}

func (i *Inbound) localCgroupEnabled() bool {
	return i.localEnabled && i.localDataPlane == localDataPlaneCgroup
}

func (i *Inbound) sharedSocketAssignEnabled() bool {
	return i.sharedEnabled && i.sharedDataPlane == sharedDataPlaneSocketAssign
}

func (i *Inbound) sharedRewriteEnabled() bool {
	return i.sharedEnabled && i.sharedDataPlane == sharedDataPlanePacketRewrite
}

func (i *Inbound) cgroupIPv6Enabled() bool {
	return i.localIPv6
}

func (i *Inbound) sharedRewriteIPv6Enabled() bool {
	return i.sharedIPv6
}

// New creates, prepares, and attaches the eBPF inbound with data-plane
// selection (cgroup or TC local; socket_assign or packet_rewrite shared).
func New(ctx context.Context, options LC.EBPF, tunnel C.Tunnel, additions ...inbound.Addition) (Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{inbound.WithInName("DEFAULT-EBPF")}
	}
	options, legacyNotes, err := applyLegacyOptions(options)
	if err != nil {
		return nil, err
	}
	for _, note := range legacyNotes {
		log.Warnln("[EBPF] %s", note)
	}
	selection, err := normalizeDataPlanes(options)
	if err != nil {
		return nil, err
	}
	mode, localEnabled, sharedEnabled := selection.mode, selection.localEnabled, selection.sharedEnabled
	if err = validateLocalOptions(localEnabled, options.Local); err != nil {
		return nil, err
	}
	if err = validateSharedOptions(sharedEnabled, options.Shared); err != nil {
		return nil, err
	}
	if err = validateAndroidUIDOptions(runtime.GOOS, options.Local); err != nil {
		return nil, err
	}
	localDataPlane, cgroupPath, sharedDataPlane := selection.localDataPlane, selection.cgroupPath, selection.sharedDataPlane
	localDNSMode, err := normalizeDNSMode(options.Local.DNSMode)
	if err != nil {
		return nil, E.Cause(err, "parse local.dns_mode")
	}
	sharedDNSMode, err := normalizeDNSMode(options.Shared.DNSMode)
	if err != nil {
		return nil, E.Cause(err, "parse shared.dns_mode")
	}
	includeUIDRanges, err := parseUIDRanges(options.Local.IncludeUID, options.Local.IncludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse include_uid_range")
	}
	excludeUIDRanges, err := parseUIDRanges(options.Local.ExcludeUID, options.Local.ExcludeUIDRange)
	if err != nil {
		return nil, E.Cause(err, "parse exclude_uid_range")
	}
	sharedOptions := LC.EBPFShared{}
	if sharedEnabled {
		sharedOptions, err = normalizeSharedOptions(options.Shared)
		if err != nil {
			return nil, err
		}
	}
	localBypassPort, err := parsePortRanges("local.bypass_port", options.Local.BypassPort, options.Local.BypassPortRange)
	if err != nil {
		return nil, err
	}
	sharedBypassPort, err := parsePortRanges("shared.bypass_port", options.Shared.BypassPort, options.Shared.BypassPortRange)
	if err != nil {
		return nil, err
	}
	sharedIncludeMAC, err := parseSharedMACAddresses(
		"include_mac_address",
		sharedOptions.IncludeMACAddress,
	)
	if err != nil {
		return nil, err
	}
	sharedExcludeMAC, err := parseSharedMACAddresses(
		"exclude_mac_address",
		sharedOptions.ExcludeMACAddress,
	)
	if err != nil {
		return nil, err
	}
	enableTCP := len(options.Network) == 0 || containsNetwork(options.Network, "tcp")
	enableUDP := len(options.Network) == 0 || containsNetwork(options.Network, "udp")

	var selfBypass *ECommon.SelfBypass
	if localEnabled {
		selfBypass, err = ECommon.NewSelfBypass()
		if err != nil {
			return nil, E.Cause(err, "prepare eBPF self-bypass sockets")
		}
	}

	inbound := &Inbound{
		ctx:                 ctx,
		tunnel:              tunnel,
		additions:           additions,
		mode:                mode,
		localEnabled:        localEnabled,
		localDataPlane:      localDataPlane,
		cgroupPath:          cgroupPath,
		sharedEnabled:       sharedEnabled,
		sharedDataPlane:     sharedDataPlane,
		enableTCP:           enableTCP,
		enableUDP:           enableUDP,
		selfBypass:          selfBypass,
		localDNSMode:        localDNSMode,
		sharedDNSMode:       sharedDNSMode,
		localIPv6:           localEnabled && enabledByDefault(options.Local.IPv6),
		sharedIPv6:          sharedEnabled && enabledByDefault(options.Shared.IPv6),
		sharedBypassPrivate: options.Shared.BypassPrivateAddress == nil || *options.Shared.BypassPrivateAddress,
		localBypassPort:     localBypassPort,
		sharedBypassPort:    sharedBypassPort,
		tcPriority:          options.TCPriority,
		sharedOptions:       sharedOptions,
		sharedIncludeMAC:    sharedIncludeMAC,
		sharedExcludeMAC:    sharedExcludeMAC,
		localPolicy: ECommon.LocalPolicy{
			EnableBypassCIDR:     true,
			DNSMode:              toCommonDNSMode(localDNSMode),
			BypassPrivateAddress: options.Local.BypassPrivateAddress == nil || *options.Local.BypassPrivateAddress,
			IncludeUIDConfigured: len(options.Local.IncludeUID) > 0 ||
				len(options.Local.IncludeUIDRange) > 0 || len(options.Local.IncludePackage) > 0,
			IncludeUID: includeUIDRanges,
			ExcludeUID: excludeUIDRanges,
		},
		androidUIDOptions: newAndroidUIDOptions(options.Local),
	}
	if inbound.tcPriority == 0 {
		inbound.tcPriority = defaultTCPriority
	}
	// On by default: a destination this inbound bypasses is one the user asked
	// to keep off the proxy, and letting TUN hand it to the rules instead is
	// what makes a bypassed address unreachable.
	inbound.bypassTUNDirect = options.BypassTUNDirect == nil || *options.BypassTUNDirect
	inbound.localStateCapacity = options.Local.StateCapacity
	inbound.sharedStateCapacity = options.Shared.StateCapacity
	inbound.tunOverlapWarnings.interval = tunOverlapWarningInterval
	// Several eBPF inbounds can run at once, so each keeps its own slot in the
	// coexistence registry: closing one -- including this one, if start fails
	// below -- must not drop what the others published.
	inbound.bypassPublisher = resolver.NewEBPFBypassPublisher()
	inbound.fakeIPIPv4Prefix, inbound.fakeIPIPv6Prefix = resolver.FakeIPRanges()
	if err = inbound.normalizeFakeIPPrefixes(); err != nil {
		return nil, err
	}
	if inbound.localCgroupEnabled() || inbound.sharedRewriteEnabled() {
		if err = inbound.selectRedirectPrefixes(); err != nil {
			return nil, err
		}
	}
	if err = inbound.resolveProcessPolicy(); err != nil {
		return nil, err
	}
	rp, ok := tunnel.(P.Tunnel)
	if !ok {
		return nil, E.New("tunnel does not expose rule providers")
	}
	for _, ruleSetTag := range options.BypassRuleSet {
		ruleSet, loaded := rp.RuleProviders()[ruleSetTag]
		if !loaded {
			return nil, E.New("parse bypass_rule_set: rule-set not found: ", ruleSetTag)
		}
		inbound.bypassRuleSet = append(inbound.bypassRuleSet, ruleSet)
	}
	inbound.udpTimeout = resolveUDPTimeout(options.UDPTimeout)
	if err := inbound.compilePolicy(); err != nil {
		return nil, err
	}
	if err := inbound.start(); err != nil {
		_ = inbound.Close()
		return nil, err
	}
	return inbound, nil
}

// compilePolicy builds the immutable compiled policy snapshot shared by every
// eBPF data plane created for this inbound.
func (i *Inbound) compilePolicy() error {
	i.policyAccess.Lock()
	defer i.policyAccess.Unlock()
	return i.compilePolicyLocked()
}

// policySnapshot returns the current compiled policy. Backends created after
// start -- a shared interface that appears later -- must build from the live
// snapshot rather than the one compiled at start, or a fake-ip range changed
// by a reload would be missing from them.
func (i *Inbound) policySnapshot() ECommon.CompiledPolicy {
	i.policyAccess.RLock()
	defer i.policyAccess.RUnlock()
	return i.compiledPolicy
}

// compilePolicyLocked expects policyAccess to be held for writing.
func (i *Inbound) compilePolicyLocked() error {
	localPolicy := i.localPolicy
	localPolicy.EnableBypassCIDR = true
	policy, err := ECommon.CompilePolicy(ECommon.PolicyConfig{
		EnableTCP:           i.enableTCP,
		EnableUDP:           i.enableUDP,
		Local:               localPolicy,
		SharedDNSMode:       toCommonDNSMode(i.sharedDNSMode),
		SharedBypassPrivate: i.sharedBypassPrivate,
		FakeIPIPv4:          i.fakeIPIPv4Prefix,
		FakeIPIPv6:          i.fakeIPIPv6Prefix,
		IncludeSourceCIDR:   i.sharedOptions.IncludeSourceCIDR,
		ExcludeSourceCIDR:   i.sharedOptions.ExcludeSourceCIDR,
		IncludeSourceMAC:    i.sharedIncludeMAC,
		ExcludeSourceMAC:    i.sharedExcludeMAC,
		LocalBypassPort:     i.localBypassPort,
		SharedBypassPort:    i.sharedBypassPort,
	})
	if err != nil {
		return E.Cause(err, "compile eBPF policy")
	}
	i.compiledPolicy = policy
	return nil
}

func (i *Inbound) resolveProcessPolicy() error {
	if i.localEnabled && i.androidUIDOptions != nil {
		if err := i.resolveAndroidUIDPolicy(); err != nil {
			return E.Cause(err, "resolve Android UID policy")
		}
	}
	return nil
}

func containsNetwork(networks []string, target string) bool {
	for _, network := range networks {
		if network == target {
			return true
		}
	}
	return false
}

func joinStringList(values []string) string {
	return strings.Join(values, ", ")
}

func (i *Inbound) start() error {
	if i.localEnabled && i.androidUIDOptions != nil {
		if err := i.resolveAndroidUIDPolicy(); err != nil {
			return E.Cause(err, "resolve Android UID policy")
		}
	}
	if i.selfBypass != nil {
		dialer.RegisterSocketProtectFunc(func(_ context.Context, network, address string, rawConn syscall.RawConn) error {
			return i.selfBypass.RegisterSocket(rawConn)
		})
		i.protectRegistered = true
	}
	if i.localEnabled {
		if err := i.startSelfBypass(); err != nil {
			log.Debugln("[EBPF] cgroup socket tracking unavailable; using socket-cookie registration: %s", err.Error())
		}
	}
	if i.localEnabled {
		i.startProcessTracker()
	}
	defaultInterface := i.currentDefaultInterfaceName()
	hostAddresses := i.hostAddresses()
	localInterface := ""
	localTCEnabled := i.localTCEnabled()
	sharedSocketAssignEnabled := i.sharedSocketAssignEnabled()
	sharedRewriteEnabled := i.sharedRewriteEnabled()
	if localTCEnabled {
		localInterface = defaultInterface
		if localInterface == "" {
			log.Warnln("[EBPF] default interface unavailable; local TC eBPF interception is paused")
		}
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface)
	tcSharedInterfaces := []string(nil)
	if sharedSocketAssignEnabled {
		tcSharedInterfaces = sharedInterfaces
	}
	if i.localEnabled || sharedSocketAssignEnabled {
		if err := i.startTCListeners(); err != nil {
			return err
		}
	}
	if i.localCgroupEnabled() {
		if err := i.prepareCgroupBackend(); err != nil {
			return err
		}
		cgroupBackend := i.cgroupBackendInstance()
		if err := cgroupBackend.UpdateHostAddresses(hostAddresses); err != nil {
			return E.Cause(err, "initialize cgroup eBPF host address policy")
		}
		if err := cgroupBackend.LoadPrograms(i.listeners.selectedPort()); err != nil {
			return err
		}
	}
	if i.localCgroupEnabled() || sharedRewriteEnabled {
		if err := i.setupLocalRoutes(); err != nil {
			return E.Cause(err, "configure eBPF redirect routes")
		}
	}
	var backend *ECommon.TCBackend
	var dataPlane *tcDataPlane
	if localTCEnabled || sharedSocketAssignEnabled {
		backendConfig := ECommon.TCConfig{
			ListenerPort:     i.listeners.selectedPort(),
			EnableLocal:      localTCEnabled,
			EnableShared:     sharedSocketAssignEnabled,
			EnableIPv4:       true,
			EnableLocalIPv6:  i.localIPv6,
			EnableSharedIPv6: i.sharedIPv6,
			EnableTCP:        i.enableTCP,
			EnableUDP:        i.enableUDP,
			Policy:           i.policySnapshot(),
			TrackProcess:     i.processTracker != nil,
		}
		if i.selfBypass != nil {
			backendConfig.SelfBypassMap = i.selfBypass.Map()
		}
		var err error
		backend, err = ECommon.PrepareTC(backendConfig)
		if err != nil && i.processTracker != nil {
			trackingErr := err
			_ = i.processTracker.Close()
			i.processTracker = nil
			backendConfig.TrackProcess = false
			backend, err = ECommon.PrepareTC(backendConfig)
			if err == nil {
				log.Debugln("[EBPF] cgroup process tracking unavailable; using userspace process search: %s", trackingErr.Error())
			}
		}
		if err != nil {
			return err
		}
		if err = i.listeners.registerTCTCPListeners(backend); err != nil {
			return E.Errors(err, backend.Close())
		}
		tcIPv6Enabled := localTCEnabled && i.localIPv6 || sharedSocketAssignEnabled && i.sharedIPv6
		dataPlane, err = startTCDataPlane(
			backend,
			localTCEnabled,
			tcIPv6Enabled,
			localInterface,
			tcSharedInterfaces,
			hostAddresses,
			len(i.sharedIncludeMAC)+len(i.sharedExcludeMAC) > 0,
			i.tcPriority,
		)
		if err != nil {
			return err
		}
		i.setTCDataPlane(dataPlane)
	}
	if err := i.startBypassRuleSets(); err != nil {
		return E.Cause(err, "initialize TC eBPF bypass_rule_set")
	}
	if sharedRewriteEnabled {
		i.sharedRewrite = newSharedRewrite(i, i.sharedOptions)
		if err := i.sharedRewrite.Start(sharedInterfaces, hostAddresses); err != nil {
			return err
		}
	}
	if cgroupBackend := i.cgroupBackendInstance(); cgroupBackend != nil {
		if err := cgroupBackend.Attach(); err != nil {
			return err
		}
	}
	if backend != nil {
		if err := backend.Enable(); err != nil {
			return err
		}
	}
	if backend != nil || i.cgroupBackendInstance() != nil || i.sharedRewrite != nil {
		if err := i.startTCInterfaceMonitor(); err != nil {
			return err
		}
	}
	// Publish the bypass policy even when no bypass_rule_set refresh will ever
	// run (no rule sets configured), so a TUN listener can still report an
	// overlap with the private ranges and keep them off its routes.
	i.bypassRuleSetAccess.Lock()
	i.publishBypassPolicyLocked()
	i.bypassRuleSetAccess.Unlock()
	i.startFakeIPTracking()
	i.reportKernelCapabilities()
	network := "tcp"
	if i.enableTCP && i.enableUDP {
		network = "tcp,udp"
	} else if i.enableUDP {
		network = "udp"
	}
	i.logInboundReady(network, defaultInterface, localInterface, sharedInterfaces, dataPlane)
	return nil
}

func (i *Inbound) logInboundReady(network, defaultInterface, localInterface string, sharedInterfaces []string, dataPlane *tcDataPlane) {
	if dataPlane == nil && i.sharedRewrite == nil {
		cgroupBackend := i.cgroupBackendInstance()
		log.Infoln("[EBPF] cgroup active: mode=%s, network=%s, cgroup=%s, ipv6=%v, listeners=[%s], self_bypass=%s, process_tracking=%s, local_uid_include=%s, local_uid_exclude=%s",
			i.mode,
			network,
			cgroupBackend.CgroupPath(),
			i.cgroupIPv6Enabled(),
			i.listeners.String(),
			i.selfBypassMode(),
			i.processTrackingMode(),
			formatUIDRanges(i.localPolicy.IncludeUID),
			formatUIDRanges(i.localPolicy.ExcludeUID),
		)
		return
	}
	log.Infoln("[EBPF] TC active: mode=%s, network=%s, local_data_plane=%s, shared_data_plane=%s, default_interface=%s, local_interface=%s, shared_interfaces=[%s], listeners=[%s], tc_priority=%d, local_uid_include=%s, local_uid_exclude=%s",
		i.mode,
		network,
		func() string {
			if !i.localEnabled {
				return "off"
			}
			return i.localDataPlane
		}(),
		func() string {
			if !i.sharedEnabled {
				return "off"
			}
			return i.sharedDataPlane
		}(),
		defaultInterface,
		localInterface,
		joinStringList(sharedInterfaces),
		i.listeners.String(),
		i.tcPriority,
		formatUIDRanges(i.localPolicy.IncludeUID),
		formatUIDRanges(i.localPolicy.ExcludeUID),
	)
}

func (i *Inbound) selfBypassMode() string {
	if !i.localEnabled || i.selfBypass == nil {
		return "none"
	}
	if i.selfBypassCgroup {
		return "cgroup_socket_cookie"
	}
	return "userspace_socket_cookie"
}

func (i *Inbound) processTrackingMode() string {
	if !i.localEnabled {
		return "off"
	}
	if i.processTracker != nil {
		return "cgroup_socket"
	}
	return "userspace"
}

func (i *Inbound) startSelfBypass() error {
	if i.selfBypass == nil || i.selfBypassCgroup {
		return nil
	}
	if err := i.selfBypass.AttachCgroup(ECommon.SelfBypassCgroupConfig{
		EnableTCP:  i.enableTCP,
		EnableUDP:  i.enableUDP,
		EnableIPv6: i.localIPv6,
	}); err != nil {
		return err
	}
	i.selfBypassCgroup = true
	return nil
}

func (i *Inbound) startProcessTracker() {
	if i.processTracker != nil {
		return
	}
	var metadataMap *CiliumEBPF.Map
	if i.selfBypass != nil {
		metadataMap = i.selfBypass.Map()
	}
	tracker, err := ECommon.AttachProcessTracker(ECommon.ProcessTrackerConfig{
		EnableTCP:   i.enableTCP,
		EnableUDP:   i.enableUDP,
		EnableIPv6:  i.localIPv6,
		LocalPolicy: i.localPolicy,
		MetadataMap: metadataMap,
	})
	if err != nil {
		log.Debugln("[EBPF] cgroup process tracking unavailable; using userspace process search: %s", err.Error())
		return
	}
	i.processTracker = tracker
}

func (i *Inbound) setTCDataPlane(dataPlane *tcDataPlane) {
	i.tcDataPlaneAccess.Lock()
	i.tcDataPlane = dataPlane
	i.tcDataPlaneAccess.Unlock()
}

func (i *Inbound) takeTCDataPlane() *tcDataPlane {
	i.tcDataPlaneAccess.Lock()
	dataPlane := i.tcDataPlane
	i.tcDataPlane = nil
	i.tcDataPlaneAccess.Unlock()
	return dataPlane
}

func (i *Inbound) tcBackend() *ECommon.TCBackend {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.backend
}

func (i *Inbound) reconcileTCDataPlane(localInterface string, sharedInterfaces []string, hostAddresses []netip.Addr) error {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.reconcile(localInterface, sharedInterfaces, hostAddresses)
}

func (i *Inbound) cgroupBackendInstance() *ECommon.CgroupBackend {
	i.cgroupBackendAccess.RLock()
	defer i.cgroupBackendAccess.RUnlock()
	return i.cgroupBackend
}

func (i *Inbound) setCgroupBackend(backend *ECommon.CgroupBackend) {
	i.cgroupBackendAccess.Lock()
	i.cgroupBackend = backend
	i.cgroupBackendAccess.Unlock()
}

func (i *Inbound) takeCgroupBackend() *ECommon.CgroupBackend {
	i.cgroupBackendAccess.Lock()
	backend := i.cgroupBackend
	i.cgroupBackend = nil
	i.cgroupBackendAccess.Unlock()
	return backend
}

func (i *Inbound) prepareCgroupBackend() error {
	backendConfig := ECommon.CgroupConfig{
		Path:          i.cgroupPath,
		EnableTCP:     i.enableTCP,
		EnableUDP:     i.enableUDP,
		EnableIPv6:    i.cgroupIPv6Enabled(),
		RedirectIPv4:  i.redirectIPv4Prefix,
		RedirectIPv6:  i.redirectIPv6Prefix,
		MapCapacity:   i.cgroupMapCapacity(),
		UDPTimeout:    i.udpTimeout,
		Policy:        i.policySnapshot(),
		SelfBypassMap: i.selfBypass.Map(),
	}
	backend, err := ECommon.PrepareCgroup(backendConfig)
	if err != nil {
		return err
	}
	i.setCgroupBackend(backend)
	return nil
}

// cgroupMapCapacity honours the legacy local.state-capacity knob: every
// redirect and flow map is sized to it. The default layout is used when the
// knob is unset.
func (i *Inbound) cgroupMapCapacity() ECommon.CgroupMapCapacity {
	capacity := ECommon.DefaultCgroupMapCapacity()
	if i.localStateCapacity == 0 {
		return capacity
	}
	capacity.TCPRedirect = i.localStateCapacity
	capacity.UDPRedirect = i.localStateCapacity
	capacity.UDPPeer = i.localStateCapacity
	capacity.UDPFlow = i.localStateCapacity
	capacity.SocketBypass = i.localStateCapacity
	return capacity
}

// sharedMapCapacity honours the legacy shared.state-capacity knob for the
// shared packet-rewrite flow tables.
func (i *Inbound) sharedMapCapacity() ECommon.SharedNetworkMapCapacities {
	capacity := ECommon.DefaultSharedNetworkMapCapacities()
	if i.sharedStateCapacity != 0 {
		capacity.Proxy = i.sharedStateCapacity
		capacity.Bypass = i.sharedStateCapacity
	}
	return capacity
}

func (i *Inbound) isCgroupRedirectAddress(address netip.Addr) bool {
	address = address.Unmap()
	if address.Is4() {
		return i.redirectIPv4Prefix.IsValid() && i.redirectIPv4Prefix.Contains(address)
	}
	return address.Is6() && i.redirectIPv6Prefix.IsValid() && i.redirectIPv6Prefix.Contains(address)
}

func (i *Inbound) Close() error {
	var closeErr error
	i.closeOnce.Do(func() {
		if i.protectRegistered {
			dialer.UnregisterSocketProtectFunc()
			i.protectRegistered = false
		}
		i.stopFakeIPTracking()
		monitorErr := i.stopTCInterfaceMonitor()
		i.stopBypassRuleSets()
		// Remove only this inbound's contribution to the coexistence registry;
		// another eBPF inbound may still be publishing.
		i.bypassPublisher.Close()
		var sharedRewriteErr error
		if i.sharedRewrite != nil {
			sharedRewriteErr = i.sharedRewrite.Close()
			i.sharedRewrite = nil
		}
		dataPlane := i.takeTCDataPlane()
		disableErr := dataPlane.disable()
		cgroupBackend := i.takeCgroupBackend()
		var cgroupErr error
		if cgroupBackend != nil {
			cgroupErr = cgroupBackend.Close()
		}
		listenerErr := i.listeners.close()
		udpReplySocketErr := i.udpReplySockets.close()
		dataPlaneErr := dataPlane.Close()
		routeErr := i.removeLocalRoutes()
		var processTrackerErr error
		if i.processTracker != nil {
			processTrackerErr = i.processTracker.Close()
			i.processTracker = nil
		}
		var selfBypassErr error
		if i.selfBypass != nil {
			selfBypassErr = i.selfBypass.Close()
			i.selfBypass = nil
		}
		closeErr = E.Errors(monitorErr, sharedRewriteErr, disableErr, listenerErr, udpReplySocketErr, dataPlaneErr, cgroupErr, routeErr, processTrackerErr, selfBypassErr)
	})
	return closeErr
}

func (i *Inbound) Address() string {
	if i.cgroupBackendInstance() != nil {
		return "eBPF(cgroup=" + i.cgroupBackendInstance().CgroupPath() + ", listen_port=" + fmt.Sprint(i.listeners.selectedPort()) + ")"
	}
	if i.tcDataPlane != nil {
		return "eBPF(TC, listen_port=" + fmt.Sprint(i.listeners.selectedPort()) + ")"
	}
	return "eBPF"
}
