# eBPF transparent inbound

This document covers the Linux/Android eBPF transparent inbound: a local role
that intercepts the host's own sockets (cgroup socket-address programs by
default, or a TC egress program on the default interface) and a shared role
that intercepts traffic forwarded from downstream interfaces (TC packet rewrite
by default, or socket assignment). The feature is enabled only in builds with
the `with_ebpf` build tag on Linux or Android; cgo is not required because the
BPF objects are shipped pre-compiled. Other platforms compile with a stub that
returns an explicit unsupported error.

## Supported environments

- Operating systems: Linux, Android.
- Architectures built by CI: linux/amd64, linux/arm64, android/arm64.
- Make targets: `linux-amd64-ebpf`, `linux-arm64-ebpf`, `android-arm64-ebpf`, `all-ebpf`.
- Kernel: cgroup v2 with BPF support. The loader does not assume a fixed
  minimum kernel version; run the capability probe below on the target device.
- cgroup mode: v2 only. cgroup v1 is rejected with a clear error.

Required kernel features are detected at runtime:

- cgroup/sockaddr program types: connect4/connect6, sendmsg4/6, recvmsg4/6.
- BPF maps: hash, lpm_trie, array, and prog_array as used by the loader.
- Optional: cgroup inet sock release attach type and
  `BPF_MAP_LOOKUP_AND_DELETE_ELEM`. When either is missing the loader uses a
  compatibility path automatically.

## Capabilities and kernel configuration

The process must be privileged or hold the following effective capabilities:

- `CAP_BPF` or `CAP_SYS_ADMIN` for BPF syscalls and cgroup attach.
- `CAP_NET_ADMIN` for shared-network TC qdisc attachment and route/sysctl setup.
- `CAP_NET_RAW` for raw socket operations used by the data path.
- The ability to raise `RLIMIT_MEMLOCK` enough for configured BPF maps.

The kernel needs at least `CONFIG_BPF`, `CONFIG_BPF_SYSCALL`, and
`CONFIG_CGROUP_BPF`. `CONFIG_BPF_JIT` is strongly recommended for throughput.
The shared-network path additionally needs `CONFIG_NET_CLS_BPF`.

## Capability probe

Run the bundled probe before starting mihomo:

```bash
bash common/ebpf/check-kernel.sh --mode all
```

For a specific cgroup path and a shared-network downstream interface:

```bash
bash common/ebpf/check-kernel.sh --mode all --cgroup /sys/fs/cgroup --interface wlan0
```

The probe does not attach programs or change routes. With `bpftool` installed
it performs transient feature probes; without `bpftool` it reports
`UNKNOWN` for features that cannot be proven safely.

## Build

The eBPF build requires a Linux build host (or Android NDK for Android) and
clang for the BPF object:

```bash
make ebpf_generate
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -tags "with_gvisor with_ebpf" -o mihomo-ebpf .
```

Android ARM64 uses the NDK clang as `CC`; see
`.github/workflows/androidarm64.yml` and `.github/workflows/build-ebpf.yml`.

## Configuration

Add an `ebpf` listener to the `listeners` section. `mode` selects which roles
run; each role then carries its own policy block:

```yaml
listeners:
  - name: ebpf-inbound
    type: ebpf
    mode: hybrid              # local | shared | hybrid, default local
    network: [tcp, udp]
    udp-timeout: 300          # seconds
    tc-priority: 1            # TC filter priority; 1 also enables TCX
    bypass-rule-set: []       # rule providers (behavior: ipcidr) bypassed in kernel
    bypass-tun-direct: true   # see "Coexisting with TUN"
    local:
      data-plane: cgroup      # cgroup (default) | tc
      cgroup-path: ""         # cgroup v2 directory, empty = auto-detect (cgroup only)
      dns-mode: hijack        # hijack (default) | respect_policy | off
      ipv6: true
      bypass-private-address: true
      include-uid: []
      include-uid-range: []   # "start:end"
      exclude-uid: []
      exclude-uid-range: []
      include-android-user: []  # Android only
      include-package: []       # Android only
      exclude-package: []       # Android only
      bypass-port: []
      bypass-port-range: []   # "start:end"
    shared:
      data-plane: packet_rewrite  # packet_rewrite (default) | socket_assign
      dns-mode: hijack
      interface: [br0]        # downstream interfaces, required when shared runs
      ipv6: true
      bypass-private-address: true
      include-source-cidr: []
      exclude-source-cidr: []
      include-mac-address: []
      exclude-mac-address: []
      bypass-port: []
      bypass-port-range: []
```

Field behavior:

- `mode`: `local` intercepts sockets created on this host, `shared` intercepts
  traffic forwarded from the `shared.interface` list, `hybrid` runs both. The
  explicit `local.enabled` / `shared.enabled` booleans are accepted instead of
  `mode`, not together with it.
- `network`: `tcp`, `udp`, or both. Defaults to both when omitted.
- `udp-timeout`: UDP session timeout in seconds. Defaults to 300, floor 5.
- `tc-priority`: priority of the TC filters. With the default `1` the inbound
  attaches through TCX on kernels that support it and falls back to clsact
  filters otherwise; any other value always uses clsact filters.
- `bypass-rule-set`: rule provider tags whose CIDRs populate the bypass LPM
  maps. Only `behavior: ipcidr` providers contribute; others are skipped.
- `bypass-tun-direct`: whether a destination this inbound bypasses is
  connected directly when a TUN listener claims it anyway. Defaults to true.
- `local.data-plane`: `cgroup` attaches connect/sendmsg/recvmsg programs to the
  cgroup and rewrites destinations to an internal redirect address on
  loopback. `tc` attaches an egress program to the default interface and
  delivers selected packets to the internal listeners over a veth pair with
  `bpf_sk_assign`, which needs a newer kernel (5.6+) and policy routing.
- `local.cgroup-path`: absolute cgroup v2 directory for the cgroup data plane.
  Empty means auto-detect.
- `dns-mode` (per role): `hijack` intercepts every port-53 flow before any
  bypass policy, `respect_policy` applies the UID/source policy first, `off`
  leaves DNS alone. `respect_bypass` is accepted as an alias of
  `respect_policy`.
- `ipv6` (per role): whether IPv6 flows are intercepted. Defaults to true.
- `bypass-private-address` (per role): let private destinations (10/8,
  172.16/12, 192.168/16, 100.64/10, 169.254/16, fc00::/7, fe80::/10) past the
  redirect. Defaults to true. Turn it off on a gateway that should see LAN
  traffic in its connection list.
- `include-uid`, `include-uid-range`, `exclude-uid`, `exclude-uid-range`:
  UID-based interception policy for the local role. Ranges use `start:end`.
- Android only: `include-android-user`, `include-package`, `exclude-package`.
- `bypass-port`, `bypass-port-range` (per role): destination ports that are
  never intercepted.
- `shared.data-plane`: `packet_rewrite` rewrites the destination at ingress
  and restores it at egress and needs Ethernet framing; `socket_assign`
  preserves the original tuple and assigns packets to the listener with
  `bpf_sk_assign` (5.6+) plus policy routing, and also works on raw-IP links.
- `shared.interface`: downstream interfaces. An interface that is currently
  the default upstream is skipped until it returns to a downstream role.
- `include-source-cidr`, `exclude-source-cidr`, `include-mac-address`,
  `exclude-mac-address`: shared source policy. MAC policy needs Ethernet
  framing.

Keys from the previous configuration surface are still accepted and mapped to
the fields above: a top-level `dns-mode` or `bypass-private-address` applies
to every enabled role that does not set its own; `local.ipv6-mode` and
`shared.ipv6-mode` (`always`/`off`, and `auto` for local, which now means
enabled) map to `ipv6`; `local.state-capacity` and `shared.state-capacity`
size the kernel state maps; `shared.advanced.tc-priority` becomes
`tc-priority`. `tcp-splice` and `shared.advanced.routing-mark` /
`routing-table` no longer do anything and are reported once at startup.

## IPv4 and IPv6 behavior

The internal TCP and UDP listeners are created with explicit address families
(`tcp4`, `tcp6`, `udp4`, `udp6`) and IPv6 listeners set `IPV6_V6ONLY`. This
avoids implicit dual-stack listener behavior and keeps the BPF lookup keys
deterministic. `local.ipv6` and `shared.ipv6` decide per role whether IPv6
flows are intercepted at all; both default to on.

The cgroup and packet-rewrite data planes redirect to an internal address the
inbound picks itself: `127.128.0.0/9` (falling back to `127.64.0.0/10`) for
IPv4 and `fd53:696e:672d:626f::/64` (falling back to `fd53:696e:672d:6270::/64`)
for IPv6. A candidate that overlaps a local route, an interface address, or a
fake-ip range is skipped, and the routes the inbound adds for the chosen prefix
are removed again on shutdown.

## Android differences

Android uses the same cgroup v2 mechanism but the effective cgroup hierarchy
and permission model differ by vendor. The auto-detected cgroup path can be
overridden with `cgroup-path`. Package policy is resolved to Android UIDs and
`include-android-user` maps a user ID to its per-user UID range. The DNS
tethering UID is always excluded.

SELinux must permit BPF map/program creation, cgroup attach, and socket
operations for the mihomo domain. On restricted Android builds the feature is
usually only usable from a root or Magisk-provided service context. Run
`common/ebpf/check-kernel.sh` on the device before debugging startup failures.

## Containers

A container running the eBPF inbound needs:

- `/sys/fs/cgroup` mounted read-write and containing the target cgroup v2 hierarchy.
- `CAP_BPF` (or `CAP_SYS_ADMIN`) and `CAP_NET_ADMIN`.
- `RLIMIT_MEMLOCK` not blocked by the container runtime.
- No seccomp profile that filters `bpf`, `setsockopt`, `netlink`, or `tc`.

For shared-network TC mode the container also needs the downstream interface
inside its network namespace and the `net.ipv4.conf.<iface>.route_localnet`
sysctl set on that interface.

## Diagnostics

Start with the capability probe and the startup log line that lists the cgroup,
listener port, DNS mode, programs, and bypass CIDR counts.

- Verifier failure: the log includes the program name, errno, and verifier log.
  Check kernel config/helpers, map capacity, and `RLIMIT_MEMLOCK`.
- Permission denied: verify root or `CAP_BPF`/`CAP_SYS_ADMIN`/`CAP_NET_ADMIN`,
  seccomp, Android SELinux, and container device policy.
- Attach failed: verify the configured path is a cgroup v2 mount, is writable,
  and is not already attached by another instance.
- Port conflict: the internal listener set binds an ephemeral port shared
  across the enabled protocol/family listeners. Startup rolls back all
  listeners if any bind fails; check `ss -lntup` for the reported port.
- `cgroup_path` errors: the path must be absolute and inside the cgroup2 mount.

## Shutdown and cleanup

`Close()` is idempotent. It stops UDP sweeps, detaches BPF links, closes map and
program file descriptors, closes the internal listeners, removes shared-network
TC attachments and local routes, and unregisters the socket protect function.
No BPF objects are pinned by the implementation, so stopping mihomo should
leave no persistent program or map names. Verify with:

```bash
bpftool prog show
bpftool map show
bpftool link show
```

If an old process crashed, restart mihomo; it creates new file descriptors and
does not depend on stale pinned objects.

## Privileged integration tests

The `privileged-integration` job in `.github/workflows/build-ebpf.yml` probes
the runner with `common/ebpf/check-kernel.sh` and marks the job SKIP when
required BPF/cgroup features cannot be proven. GitHub-hosted runners are
expected to SKIP because the probe cannot distinguish cgroup sockaddr attach
subtypes without a real load. Run the real suite on a self-hosted Linux
runner with cgroup v2, root access, and bpftool:

```bash
bash common/ebpf/check-kernel.sh --mode all --cgroup /sys/fs/cgroup
SING_BOX_EBPF_INTEGRATION=1 CGO_ENABLED=1 go test -count=1 \
  -tags "with_gvisor with_ebpf ebpf_integration" \
  ./common/ebpf/... -run Integration
```

The suite creates temporary cgroups, loads programs, attaches traffic
helpers, and cleans up all state on completion. After stopping mihomo on the
same host, verify `bpftool prog show`, `bpftool map show`, and
`bpftool link show` report no leftover objects.

## Repository automation prerequisites

The sync workflow creates PRs and failure Issues. The target repository must
have:

- Issues enabled, otherwise the failure notification step exits with an
  actionable error instead of creating an Issue.
- GitHub Actions permitted to create and approve pull requests.
- The sync workflow present on the repository default branch so the
  `schedule` trigger is active.

## Relationship with TUN, TProxy, and Redir

The eBPF inbound intercepts sockets inside the selected cgroup; it is not a
full TUN device and does not route all host traffic by itself. The shared-network
mode uses TC on named downstream interfaces and can be used for hotspot
forwarding while the cgroup path handles local apps.

### Coexisting with TUN

A bypass decision and a route exclusion live at different layers. Bypassing a
destination here only means the socket keeps its original destination; the packet
still follows the routing table, and TUN `auto-route` points that table at the
TUN device. A bypassed destination TUN claims is therefore not direct: it enters
the TUN stack and is routed by the rule engine, which black-holes it whenever no
rule sends it direct and the matched proxy cannot reach the address.

`auto-route` is not the whole story on Linux: sing-tun gates only the IPv4 route
set on it, and builds the IPv6 route set for any device that has IPv6 addresses,
which `setRoute` then installs along with a matching `ip rule`. A device
configured with `auto-route: false` therefore still claims IPv6 destinations, and
the overlap report covers them.

Two mechanisms keep the bypass meaningful, split by set size:

| Bypass source | Mechanism | Where |
|---------------|-----------|-------|
| `bypass-private-address` | the fixed private prefixes are published for route exclusion, so `auto-route` never claims them | `listener/sing_tun` reads `resolver.EBPFRouteExcludePrefixes` while building `tun.Options` |
| `bypass-rule-set` | the destination is connected directly on arrival instead of being matched against the rules (`bypass-tun-direct`, default true) | `tunnel.resolveMetadata` consults `resolver.EBPFBypassedDirect` for `C.TUN` flows in rule mode |

A rule set cannot use route exclusion: it resolves after the TUN device already
baked its route set, and excluding a country-sized IP set would install tens of
thousands of routes. The fake-ip ranges and the TUN device's own addresses are
always kept on the routes.

With `bypass-tun-direct: false` the overlap is only reported, not handled. Both
listeners report it, because either one can be the second to start.

The exclusion is baked into the device's route set at build time, so a TUN
device that already exists has to be rebuilt when it changes -- an eBPF inbound
starting, stopping, or changing its bypass policy, none of which the `tun`
section describes. Both entry points handle it: `ReCreateTun` compares the
exclusion alongside the config, and a TUN declared under `listeners:` is
restarted by `rebuildStaleListeners`, which runs after every inbound has been
started. That ordering matters on startup as much as on reload, because the
patch loop walks a map and can otherwise build the device before the eBPF
inbound has published anything at all. A restart logs:

```
Listener tun-in restarting: the eBPF route exclusion changed under it
```

Direct handling applies in rule mode only. Global and direct mode are standing
instructions about where every flow goes, so the bypass leaves them to decide --
under global mode the connection would otherwise be dialled through `DIRECT`
while the log still named `GLOBAL`. Route exclusion is unaffected: it keeps the
destinations off the TUN device in every mode.

The gate governs this one handler, not the feature. Traffic that takes the eBPF
fast path never reaches the tunnel to be gated, so the kernel keeps bypassing it
under global mode, and the DNS middleware still answers a bypassed destination
with its real address rather than a fake one in every mode. What the gate buys is
that a flow arriving through TUN is routed by the mode the user selected.

Several eBPF inbounds can run at once -- the listener parser only rejects
duplicate names -- so the published state is a union keyed by publishing
inbound, and `bypass-tun-direct` stays per inbound: only the prefixes of the
inbounds that asked for it are connected directly. Closing one inbound removes
only its own contribution, which matters because an inbound whose start fails
closes itself.

Beyond that, avoid attaching multiple transparent inbound mechanisms to the same
cgroup or interface unless you intentionally split traffic with UID, CIDR, and
`bypass-rule-set` policies. In particular do not enable shared mode and TUN
`auto-redirect` on the same interface: TC ingress rewrites the destination
before netfilter sees the packet. `strict-route` is best left off, since it
reorders the policy routing the redirect address depends on.

### FakeIP

The fake-ip ranges are pushed into the kernel policy so a fake destination is
intercepted even when it would otherwise be bypassed -- the address only regains
meaning once the tunnel maps it back to its domain. This matters when the
configured range sits inside a bypassed range, as `fake-ip-range: 100.64.0.0/10`
does. The ranges follow `dns.fake-ip-range`/`fake-ip-range6` at runtime, so a
config reload that changes them reaches a running inbound.
