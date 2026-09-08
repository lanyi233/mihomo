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

Three unified TC socket-assignment integration tests explicitly skip after the helper probe reports that `bpf_sk_assign` is unavailable. This helper requires Linux 5.9 or a backport; the shared packet-rewrite tests do not depend on it. A passing local classifier load does not imply the full socket-assignment data plane can operate on this device.

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
