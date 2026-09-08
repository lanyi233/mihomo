//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	CiliumEBPF "github.com/cilium/ebpf"
	"net/netip"
	"testing"
	"time"
)

const (
	sharedRewriteTestEthernetHeaderLength = 14
	sharedRewriteTestIPv4HeaderLength     = 20
	sharedRewriteTestIPv6HeaderLength     = 40
	sharedRewriteTestTCPHeaderLength      = 20
	sharedRewriteTestUDPHeaderLength      = 8
	sharedRewriteTestTCActOK              = uint32(0)
)

func TestSharedRewriteProgramRoundTripIntegration(t *testing.T) {
	requireEBPFIntegration(t, "run shared packet-rewrite eBPF programs in the kernel")
	policy, err := CompilePolicy(PolicyConfig{
		EnableTCP:     true,
		EnableUDP:     true,
		SharedDNSMode: DNSModeOff,
	})
	if err != nil {
		var verifier *CiliumEBPF.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("%+v", verifier)
		}
		t.Fatal(err)
	}
	redirectIPv4 := netip.MustParsePrefix("127.128.0.0/9")
	redirectIPv6 := netip.MustParsePrefix("fd53:696e:672d:626f::/64")
	backend, err := PrepareSharedNetwork(nil, SharedNetworkConfig{
		ListenerPort: 65531,
		EnableTCP:    true,
		EnableUDP:    true,
		RedirectIPv4: redirectIPv4,
		RedirectIPv6: redirectIPv6,
		Policy:       policy,
		MapCapacity:  SharedNetworkMapCapacities{Proxy: 64, Bypass: 64},
		UDPTimeout:   time.Minute,
	})
	if err != nil {
		var verifier *CiliumEBPF.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("%+v", verifier)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	if err = backend.Enable(); err != nil {
		var verifier *CiliumEBPF.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("%+v", verifier)
		}
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		protocol        uint8
		client          netip.AddrPort
		original        netip.AddrPort
		payload         []byte
		zeroUDPChecksum bool
	}{
		{
			name:            "udp4_zero_checksum",
			protocol:        ProtocolUDP,
			client:          netip.MustParseAddrPort("192.0.2.10:53000"),
			original:        netip.MustParseAddrPort("1.1.1.1:8443"),
			payload:         []byte("udp4-zero"),
			zeroUDPChecksum: true,
		},
		{
			name:     "udp4_checksum",
			protocol: ProtocolUDP,
			client:   netip.MustParseAddrPort("192.0.2.11:53001"),
			original: netip.MustParseAddrPort("8.8.8.8:8443"),
			payload:  []byte("udp4-checksum"),
		},
		{
			name:     "tcp4_checksum",
			protocol: ProtocolTCP,
			client:   netip.MustParseAddrPort("192.0.2.12:53002"),
			original: netip.MustParseAddrPort("9.9.9.9:443"),
			payload:  []byte("tcp4-checksum"),
		},
		{
			name:     "udp6_checksum",
			protocol: ProtocolUDP,
			client:   netip.MustParseAddrPort("[2001:db8::10]:53003"),
			original: netip.MustParseAddrPort("[2001:4860:4860::8888]:8443"),
			payload:  []byte("udp6-checksum"),
		},
		{
			name:     "tcp6_checksum",
			protocol: ProtocolTCP,
			client:   netip.MustParseAddrPort("[2001:db8::11]:53004"),
			original: netip.MustParseAddrPort("[2606:4700:4700::1111]:443"),
			payload:  []byte("tcp6-checksum"),
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			ingressPacket := sharedRewriteTestPacket(
				testCase.protocol,
				testCase.client,
				testCase.original,
				testCase.payload,
				testCase.zeroUDPChecksum,
			)
			action, rewrittenIngress := runTCProgram(t, backend.IngressProgram(), ingressPacket)
			if action != sharedRewriteTestTCActOK {
				t.Fatalf("ingress returned action %d, want TC_ACT_OK", action)
			}

			token := sharedRewriteTestDestination(rewrittenIngress, testCase.client.Addr().Is6())
			redirectPrefix := redirectIPv4
			if token.Is6() {
				redirectPrefix = redirectIPv6
			}
			if !redirectPrefix.Contains(token) {
				t.Errorf("ingress token %s is outside redirect prefix %s", token, redirectPrefix)
			}
			tokenDestination := netip.AddrPortFrom(token, backend.control.ListenerPort)
			wantIngress := sharedRewriteTestPacket(
				testCase.protocol,
				testCase.client,
				tokenDestination,
				testCase.payload,
				testCase.zeroUDPChecksum,
			)
			sharedRewriteTestAssertPacket(t, "ingress", rewrittenIngress, wantIngress, testCase.protocol, testCase.zeroUDPChecksum)

			egressPacket := sharedRewriteTestPacket(
				testCase.protocol,
				tokenDestination,
				testCase.client,
				testCase.payload,
				testCase.zeroUDPChecksum,
			)
			action, rewrittenEgress := runTCProgram(t, backend.EgressProgram(), egressPacket)
			if action != sharedRewriteTestTCActOK {
				t.Fatalf("egress returned action %d, want TC_ACT_OK", action)
			}
			wantEgress := sharedRewriteTestPacket(
				testCase.protocol,
				testCase.original,
				testCase.client,
				testCase.payload,
				testCase.zeroUDPChecksum,
			)
			sharedRewriteTestAssertPacket(t, "egress", rewrittenEgress, wantEgress, testCase.protocol, testCase.zeroUDPChecksum)
		})
	}
}

func sharedRewriteTestPacket(
	protocol uint8,
	source netip.AddrPort,
	destination netip.AddrPort,
	payload []byte,
	zeroUDPChecksum bool,
) []byte {
	transportHeaderLength := sharedRewriteTestTCPHeaderLength
	if protocol == ProtocolUDP {
		transportHeaderLength = sharedRewriteTestUDPHeaderLength
	}
	transportLength := transportHeaderLength + len(payload)
	ipHeaderLength := sharedRewriteTestIPv4HeaderLength
	if source.Addr().Is6() {
		ipHeaderLength = sharedRewriteTestIPv6HeaderLength
	}
	packet := make([]byte, sharedRewriteTestEthernetHeaderLength+ipHeaderLength+transportLength)
	copy(packet[0:6], []byte{0x02, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{0x02, 0, 0, 0, 0, 1})

	ip := packet[sharedRewriteTestEthernetHeaderLength:]
	if source.Addr().Is4() {
		binary.BigEndian.PutUint16(packet[12:14], 0x0800)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(ipHeaderLength+transportLength))
		binary.BigEndian.PutUint16(ip[4:6], 0x4242)
		binary.BigEndian.PutUint16(ip[6:8], 0x4000)
		ip[8] = 64
		ip[9] = protocol
		sourceAddress := source.Addr().As4()
		destinationAddress := destination.Addr().As4()
		copy(ip[12:16], sourceAddress[:])
		copy(ip[16:20], destinationAddress[:])
		binary.BigEndian.PutUint16(ip[10:12], sharedRewriteTestChecksum(ip[:ipHeaderLength]))
	} else {
		binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:6], uint16(transportLength))
		ip[6] = protocol
		ip[7] = 64
		sourceAddress := source.Addr().As16()
		destinationAddress := destination.Addr().As16()
		copy(ip[8:24], sourceAddress[:])
		copy(ip[24:40], destinationAddress[:])
	}

	transport := ip[ipHeaderLength:]
	binary.BigEndian.PutUint16(transport[0:2], source.Port())
	binary.BigEndian.PutUint16(transport[2:4], destination.Port())
	checksumOffset := 16
	if protocol == ProtocolTCP {
		binary.BigEndian.PutUint32(transport[4:8], 0x12345678)
		binary.BigEndian.PutUint32(transport[8:12], 0x87654321)
		transport[12] = 5 << 4
		transport[13] = 0x18
		binary.BigEndian.PutUint16(transport[14:16], 65535)
	} else {
		binary.BigEndian.PutUint16(transport[4:6], uint16(transportLength))
		checksumOffset = 6
	}
	copy(transport[transportHeaderLength:], payload)
	if protocol != ProtocolUDP || !zeroUDPChecksum {
		checksum := sharedRewriteTestTransportChecksum(source.Addr(), destination.Addr(), protocol, transport)
		if protocol == ProtocolUDP && checksum == 0 {
			checksum = 0xffff
		}
		binary.BigEndian.PutUint16(transport[checksumOffset:checksumOffset+2], checksum)
	}
	return packet
}

func sharedRewriteTestDestination(packet []byte, ipv6 bool) netip.Addr {
	ip := packet[sharedRewriteTestEthernetHeaderLength:]
	if ipv6 {
		return netip.AddrFrom16([16]byte(ip[24:40]))
	}
	return netip.AddrFrom4([4]byte(ip[16:20]))
}

func sharedRewriteTestAssertPacket(
	t *testing.T,
	direction string,
	got []byte,
	want []byte,
	protocol uint8,
	zeroUDPChecksum bool,
) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s rewrite mismatch:\n got %x\nwant %x", direction, got, want)
	}
	sharedRewriteTestAssertChecksums(t, direction, got, protocol, zeroUDPChecksum)
}

func sharedRewriteTestAssertChecksums(
	t *testing.T,
	direction string,
	packet []byte,
	protocol uint8,
	zeroUDPChecksum bool,
) {
	t.Helper()
	ip := packet[sharedRewriteTestEthernetHeaderLength:]
	ipHeaderLength := sharedRewriteTestIPv4HeaderLength
	var source, destination netip.Addr
	if ip[0]>>4 == 4 {
		if sharedRewriteTestChecksum(ip[:ipHeaderLength]) != 0 {
			t.Errorf("%s rewrite produced an invalid IPv4 header checksum", direction)
		}
		source = netip.AddrFrom4([4]byte(ip[12:16]))
		destination = netip.AddrFrom4([4]byte(ip[16:20]))
	} else {
		ipHeaderLength = sharedRewriteTestIPv6HeaderLength
		source = netip.AddrFrom16([16]byte(ip[8:24]))
		destination = netip.AddrFrom16([16]byte(ip[24:40]))
	}
	transport := ip[ipHeaderLength:]
	checksumOffset := 16
	if protocol == ProtocolUDP {
		checksumOffset = 6
	}
	checksum := binary.BigEndian.Uint16(transport[checksumOffset : checksumOffset+2])
	if zeroUDPChecksum {
		if checksum != 0 {
			t.Errorf("%s rewrite changed disabled IPv4 UDP checksum to %#04x", direction, checksum)
		}
		return
	}
	if checksum == 0 {
		t.Errorf("%s rewrite produced a zero transport checksum", direction)
		return
	}
	if sharedRewriteTestTransportChecksum(source, destination, protocol, transport) != 0 {
		t.Errorf("%s rewrite produced an invalid transport checksum", direction)
	}
}

func sharedRewriteTestTransportChecksum(source, destination netip.Addr, protocol uint8, transport []byte) uint16 {
	pseudoHeaderLength := 12
	if source.Is6() {
		pseudoHeaderLength = 40
	}
	data := make([]byte, pseudoHeaderLength+len(transport))
	if source.Is4() {
		sourceAddress := source.As4()
		destinationAddress := destination.As4()
		copy(data[0:4], sourceAddress[:])
		copy(data[4:8], destinationAddress[:])
		data[9] = protocol
		binary.BigEndian.PutUint16(data[10:12], uint16(len(transport)))
	} else {
		sourceAddress := source.As16()
		destinationAddress := destination.As16()
		copy(data[0:16], sourceAddress[:])
		copy(data[16:32], destinationAddress[:])
		binary.BigEndian.PutUint32(data[32:36], uint32(len(transport)))
		data[39] = protocol
	}
	copy(data[pseudoHeaderLength:], transport)
	return sharedRewriteTestChecksum(data)
}

func sharedRewriteTestChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = uint32(uint16(sum)) + sum>>16
	}
	return ^uint16(sum)
}

func TestSharedRewritePolicyIntegration(t *testing.T) {
	requireEBPFIntegration(t, "verify shared policy ordering and bypass-port guard")
	policy, err := CompilePolicy(PolicyConfig{EnableTCP: true, SharedDNSMode: DNSModeOff,
		SharedBypassPrivate: true, SharedBypassPort: []PortRange{{Start: 8443, End: 8443}},
		FakeIPIPv4: netip.MustParsePrefix("10.123.0.0/16"),
		FakeIPIPv6: netip.MustParsePrefix("fd12:3456::/32")})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := PrepareSharedNetwork(nil, SharedNetworkConfig{ListenerPort: 65531, EnableTCP: true,
		RedirectIPv4: netip.MustParsePrefix("127.128.0.0/9"), RedirectIPv6: netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		UDPTimeout: time.Minute, Policy: policy, MapCapacity: SharedNetworkMapCapacities{Proxy: 64, Bypass: 64}})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if err = backend.Enable(); err != nil {
		t.Fatal(err)
	}
	if backend.control.Flags&sharedNetworkFlagBypassFlowCache != 0 {
		t.Fatal("bypass-port-only policy unexpectedly enabled the bypass-flow cache")
	}
	if err = backend.UpdateHostAddresses([]netip.Addr{netip.MustParseAddr("10.123.0.1"), netip.MustParseAddr("fd12:3456::1")}); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, client, dest string
		bypass             bool
	}{
		{"private4", "192.0.2.10:53000", "192.168.1.5:443", true},
		{"fake4", "192.0.2.10:53001", "10.123.0.2:443", false},
		{"host_over_fake4", "192.0.2.10:53002", "10.123.0.1:443", true},
		{"port_after_host_update", "192.0.2.10:53003", "1.1.1.1:8443", true},
		{"private6", "[2001:db8::10]:53004", "[fd98::2]:443", true},
		{"fake6", "[2001:db8::10]:53005", "[fd12:3456::2]:443", false},
		{"host_over_fake6", "[2001:db8::10]:53006", "[fd12:3456::1]:443", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			packet := sharedRewriteTestPacket(ProtocolTCP, netip.MustParseAddrPort(tt.client), netip.MustParseAddrPort(tt.dest), nil, false)
			action, out := runTCProgram(t, backend.IngressProgram(), packet)
			if tt.bypass {
				if action != testTCActUnspec || !bytes.Equal(out, packet) {
					t.Fatalf("bypass action=%d changed=%v", action, !bytes.Equal(out, packet))
				}
			} else if action != 0 || bytes.Equal(out, packet) {
				t.Fatalf("proxy action=%d changed=%v", action, !bytes.Equal(out, packet))
			}
		})
	}
	bypassIterator := backend.runtime.maps["shared_bypass_flow"].Iterate()
	var bypassKey sharedNetworkOriginalKey
	var bypassValue [16]byte
	if bypassIterator.Next(&bypassKey, &bypassValue) {
		t.Fatalf("cache-disabled bypass-port policy wrote a bypass-flow entry: %+v", bypassKey)
	}
	if err = bypassIterator.Err(); err != nil {
		t.Fatal(err)
	}
}
