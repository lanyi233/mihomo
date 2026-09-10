# BPF optimization validation (2026-09-08)

Baseline: `72d70f10` on Alpha, following the smart and eBPF upstream merges.
Toolchain: Android NDK r29, Clang 21.0.0, existing `-mcpu=v1` build flags.
Device: ADB-connected U30 Air, arm64, Android kernel `5.4.254-android12-9-g1cf433218600`, Magisk root.

## Changes

- Preserve disabled IPv4 UDP checksums. Only IPv6 uses `BPF_F_MARK_ENFORCE`.
- Replace shared rewrite address/port `skb_store_bytes` calls with bounded packet stores. IPv4 also uses the address delta directly instead of `csum_diff`: three fewer helpers per IPv4 rewrite, two fewer per IPv6 rewrite.
- Reload packet pointers after checksum helpers. Keep the port-offset mask and pointer addition in one asm block: the 5.4 verifier loses scalar bounds if LLVM spills between them.
- Build the shared egress lookup key on the stack and read the map value directly, eliminating the scratch-map lookup and intermediate value copy.
- Evaluate private-address arithmetic before host-map lookup while preserving host-address precedence over fake-IP. Inline the three small shared policy functions.
- Skip shared bypass-port lookup when no ports are configured. Preserve its static flag across host/CIDR updates.
- Use one socket-cookie read per cgroup connect/sendmsg hook and constant-size address copies.
- Keep local TC IPv6 parsing in a separate BPF subprogram. The baseline's inlined extension-header paths produced invalid packet bounds on this kernel.
- Preserve verifier errors through the Go error wrapper. Correct integration map iteration's typed-nil key and end-of-iteration handling.

## Device results

Passed:

- Cgroup TCP4, UDP4, TCP6, UDP6, and dual-stack program loading, dedicated-cgroup attachment and map handoff.
- Map batch operations and fallback, bounded LRU fallback.
- Shared ingress/egress `BPF_PROG_TEST_RUN` with byte-for-byte expected packet comparison: IPv4 UDP with zero checksum, IPv4 UDP/TCP with checksums, IPv6 UDP/TCP with checksums.
- Shared policy: private-address bypass, interception of fake-IP within private ranges, host-address precedence over fake-IP, and bypass-port preservation after host updates, for both address families where applicable.
- All local TC classifier variants load independently of the socket-assignment programs.

Regression evidence: running the new tests against baseline objects reproduces both IPv4 UDP zero-checksum corruption (ingress and egress) and the local TC IPv6 verifier rejection. Both pass with the regenerated objects.

Three unified TC socket-assignment integration tests explicitly skip after the helper probe reports that `bpf_sk_assign` is unavailable. For TC programs this helper was introduced in [upstream Linux 5.7](https://github.com/torvalds/linux/blob/v5.7/include/uapi/linux/bpf.h) (or requires a backport); the shared packet-rewrite tests do not depend on it. A passing local classifier load does not imply the full socket-assignment data plane can operate on this device.

These are kernel loading, attachment and packet tests, not a router throughput benchmark or a deployment to 192.168.0.1. No production interfaces/routes were reconfigured. Non-linear skb parsing behavior is unchanged: replacing a parse failure with unconditional bypass needs separate non-linear skb coverage and must not leak token-address traffic or evade policy.

## Reproduction

Generate and verify the tracked objects with the same compiler:

```sh
make -C common/ebpf generate ANDROID_NDK_HOME=/path/to/android-ndk-r29
make -C common/ebpf check ANDROID_NDK_HOME=/path/to/android-ndk-r29
```

Build the privileged tests as a static Linux arm64 binary for Android:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c \
  -tags 'with_ebpf ebpf_integration' -o /tmp/mihomo-ebpf.test ./common/ebpf
adb push /tmp/mihomo-ebpf.test /data/local/tmp/mihomo-ebpf.test
```

Run from a root shell script on the device (raising memlock applies only to that process tree):

```sh
ulimit -l unlimited
export SING_BOX_EBPF_INTEGRATION=1
exec /data/local/tmp/mihomo-ebpf.test -test.v -test.run Integration -test.timeout 120s
```

Host checks: full `go test -tags with_ebpf ./...`; `go vet` and `go test -race` for `./common/ebpf ./listener/sing_ebpf`; Linux amd64, Android arm64 and Darwin arm64 builds with `with_ebpf`. The Android binary also executes successfully on the device.

## Follow-up: host coverage and remaining performance (2026-09-08)

Host kernel: NixOS `7.1.10-zen1`, Intel Core Ultra 9 275HX. Running the privileged test binary with `sudo -A` completed all integration tests, including the socket-assignment, IPv6 isolation, and fragment cases skipped on Android. The IPv6 isolation fixture previously selected a program for a disabled data plane; enabling both planes while varying only their IPv6 flags fixes the fixture. The packet runner now reports missing programs instead of panicking.

A bypass-port-only configuration disables the bypass-flow cache, but the BPF producer still wrote that cache on every bypassed packet. Guarding the producer with the same enable flag removes an unused timestamp helper and map update. The regression asserts that the disabled cache stays empty. All existing host integration tests pass five consecutive runs; Android 5.4 also passes its supported tests with the new objects.

`BenchmarkSharedBypassPortIntegration`, 100,000 kernel repetitions, five samples per binary:

| Objects | Kernel ns/packet |
| --- | --- |
| Before | 109, 110, 110, 117, 111 |
| After | 35, 36, 37, 38, 36 |

Median reduction: 110 to 36 ns (about 67%) for this bypass-only classifier path. This is not an end-to-end throughput measurement. Go forwarding baseline remains roughly 660–725 ns/packet with 2 allocations; OOB parsing is about 7 ns without allocations.

UDP receive rejection paths now return their pooled payloads on absent backend, invalid destination/control messages, and failed original-destination lookups. Successful forwarding and asynchronous DNS retain their existing ownership. Tests intercept the allocator to verify exactly one return for rejected packets; no extra hot-path wrapper or allocation was added.

Remaining audit findings, not changed in this follow-up:

- Userspace UDP client tables have no production caller for their per-client deletion helpers; the shared topology `purgeUDP` callback is empty. Client/binding/flow-reference accumulation and stale entries need a dedicated lifetime fix coordinated with tunnel NAT ownership. A timer that expires clients without observing downstream activity can interrupt valid UDP sessions.
- Transparent reply sockets are cached by remote address/port until reset/close. Many distinct destinations can increase descriptor usage; bounded idle eviction must synchronize with in-flight writes.
- DNS goroutines are not concurrency-bounded. Limits require an explicit overload policy so slow upstream DNS does not create either unlimited work or a blocked UDP read loop.
- Non-linear skb behavior and router throughput still require dedicated traffic tests.

## UDP lifetime and bounded DNS/socket resources

The three userspace resource findings above are addressed in the next change:

- UDP client state records monotonic activity and outstanding packet/DNS ownership. Successful forwarding keeps a reference until `Drop`; DNS keeps one until resolution/write-back completes. Replies refresh activity, so downstream-only sessions remain live. An inbound-owned janitor uses `udp-timeout` and expires at most 1024 idle clients per table each round. It releases shared flow references and cgroup redirect records. Active clients are not evicted to meet this cleanup budget.
- Shared topology reconciliation now excludes UDP ingress/replies while resetting client caches; stale writers cannot install aliases into a replacement client. Shutdown stops janitors before changing their backend pointers, cancels DNS, and clears client state.
- Transparent reply sockets use 16 shards with 64 live descriptors per shard (1024 total), including retired sockets still leased by writers. The key hash includes the IP address as well as the port. Capacity evicts the least recently used unleased socket; if the shard is entirely leased, admission returns an error. Idle sockets expire using `udp-timeout`. Reset/close defer closing a leased socket until its final writer releases it. Sendmsg runs outside the shard lock.
- Local and shared DNS, TCP and UDP, share a 256-task cap per inbound. Admission never waits for a task slot: excess UDP queries are dropped with their buffer returned, and excess TCP connections are closed. Upstream requests inherit inbound cancellation; shutdown closes idle TCP DNS readers and waits for accepted work before closing backends.

Tests cover 10,000-client churn, queued-packet and downstream activity retention, stale writer rejection, exactly-once Drop/release, DNS admission/cancellation/start-close races, idle TCP reader cancellation, socket capacity/idle eviction, leased writes during reset/close, and concurrent writes during sweeping. The listener suite also runs as a static arm64 test binary on the Android device.

This improves resource bounds, not the theoretical throughput of the same short session. Host forwarding microbenchmarks remain at 2 allocations per packet; the socket cache hit/lease/release benchmark has zero allocations (about 76–82 ns on the test host). Actively used UDP bindings can still grow with the number of destinations in an active session; the janitor bounds idle retention rather than imposing a hard cap on valid active traffic.

## Bounded UDP sweep follow-up

The userspace client sweep now keeps an intrusive ring cursor in each shard.
A pass examines at most 1024 clients per table, including active clients, and
releases the ingress/reply lifecycle lock after each batch of at most 32.
Large snapshots continue once per second; once covered, the janitor returns
to its normal interval. This prevents an active prefix from starving later
idle clients and avoids scanning an entire large table under one lock.

Regression tests cover a long active prefix in a single shard, exact scan
budgets, continuation completion, concurrent deletion/recreation, and full
purge. The listener suite passed three repeated race runs on the host and
three native arm64 runs on the Android 5.4 device. Forwarding still uses two
allocations per packet; an active-client sweep allocates no heap memory. BPF
source and objects are unchanged by this follow-up.
