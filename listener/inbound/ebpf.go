package inbound

import (
	"context"
	"errors"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_ebpf"
	"github.com/metacubex/mihomo/log"
)

type EBPFOption struct {
	BaseOption
	Mode            string        `inbound:"mode,omitempty"`
	Network         []string      `inbound:"network,omitempty"`
	UDPTimeout      int64         `inbound:"udp-timeout,omitempty"`
	TCPriority      uint16        `inbound:"tc-priority,omitempty"`
	BypassRuleSet   []string      `inbound:"bypass-rule-set,omitempty"`
	FakeIPICMP      string        `inbound:"fakeip-icmp,omitempty"`
	BypassTUNDirect *bool         `inbound:"bypass-tun-direct,omitempty"`
	Local           LC.EBPFLocal  `inbound:"local,omitempty"`
	Shared          LC.EBPFShared `inbound:"shared,omitempty"`

	// Legacy top-level keys, folded into local/shared by the listener. The
	// option decoder ignores unknown keys, so leaving these out would make an
	// older config silently lose its DNS and private-address policy.
	DNSMode              string `inbound:"dns-mode,omitempty"`
	BypassPrivateAddress *bool  `inbound:"bypass-private-address,omitempty"`
	TCPSplice            bool   `inbound:"tcp-splice,omitempty"`
}

func (o EBPFOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type EBPF struct {
	*Base
	config *EBPFOption
	ebpf   LC.EBPF
	l      sing_ebpf.Listener
}

func NewEBPF(options *EBPFOption) (*EBPF, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	return &EBPF{
		Base:   base,
		config: options,
		ebpf:   ebpfListenerConfig(options),
	}, nil
}

// ebpfListenerConfig is the listener's half of the option. Update builds it
// too, so it lives here rather than inline: the two drifting apart would mean
// an in-place update quietly applying a different config from the one a
// rebuild would have produced.
func ebpfListenerConfig(options *EBPFOption) LC.EBPF {
	return LC.EBPF{
		Mode:                 options.Mode,
		Network:              options.Network,
		UDPTimeout:           options.UDPTimeout,
		TCPriority:           options.TCPriority,
		BypassRuleSet:        options.BypassRuleSet,
		FakeIPICMP:           options.FakeIPICMP,
		BypassTUNDirect:      options.BypassTUNDirect,
		DNSMode:              options.DNSMode,
		BypassPrivateAddress: options.BypassPrivateAddress,
		TCPSplice:            options.TCPSplice,
		Local:                options.Local,
		Shared:               options.Shared,
	}
}

// withoutInPlaceUpdatableFields zeroes every field the running listener can
// change without being rebuilt. Two options whose cleared copies compare equal
// differ only in fields it can absorb.
//
// Clearing rather than listing the rebuild-forcing fields is what makes this
// fail closed. A field added to EBPFOption later is not cleared here, so it
// takes part in the comparison and forces a rebuild until someone decides
// otherwise. Listing the other way round would silently admit a new field as
// updatable and then apply none of it, leaving the listener running a config
// the user cannot see it is not running.
func withoutInPlaceUpdatableFields(options EBPFOption) EBPFOption {
	options.UDPTimeout = 0
	options.BypassRuleSet = nil
	options.BypassTUNDirect = nil
	return options
}

// Update implements the listener registry's in-place update. Rebuilding this
// inbound destroys every kernel map it owns -- the cgroup redirect table, the
// shared flow table, the TC assignment map, the UDP recovery table -- so every
// established redirect breaks for the sake of, in the common case, one changed
// number.
func (e *EBPF) Update(newConfig C.InboundConfig) (bool, error) {
	options, ok := newConfig.(*EBPFOption)
	if !ok || e.l == nil {
		return false, nil
	}
	if optionToString(withoutInPlaceUpdatableFields(*e.config)) !=
		optionToString(withoutInPlaceUpdatableFields(*options)) {
		return false, nil
	}
	next := ebpfListenerConfig(options)
	if err := e.l.Update(next); err != nil {
		// Not every refusal is a failure: the data planes know constraints this
		// layer cannot see -- which planes are even running -- and report them
		// by asking for the rebuild the caller would have done anyway.
		if errors.Is(err, sing_ebpf.ErrRebuildRequired) {
			return false, nil
		}
		return false, err
	}
	// The running listener stays registered, so it has to answer for the config
	// it is now running: the next reload compares against Config(), and a stale
	// answer would ask it to apply the same difference again on every reload.
	e.config = options
	e.ebpf = next
	return true, nil
}

// Config implements constant.InboundListener
func (e *EBPF) Config() C.InboundConfig {
	return e.config
}

// Address implements constant.InboundListener
func (e *EBPF) Address() string {
	if e.l == nil {
		return ""
	}
	return e.l.Address()
}

// RawAddress implements constant.InboundListener
func (e *EBPF) RawAddress() string {
	return ""
}

// Listen implements constant.InboundListener
func (e *EBPF) Listen(tunnel C.Tunnel) error {
	var err error
	e.l, err = sing_ebpf.New(context.Background(), e.ebpf, tunnel, e.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("EBPF[%s] proxy listening at: %s", e.Name(), e.Address())
	return nil
}

// Close implements constant.InboundListener
func (e *EBPF) Close() error {
	if e.l != nil {
		return e.l.Close()
	}
	return nil
}

var _ C.InboundListener = (*EBPF)(nil)
