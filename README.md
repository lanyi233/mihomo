<h1 align="center">
  <img src="Meta.png" alt="Meta Kernel" width="200">
  <br>mihomo · smart + eBPF + Tailscale + <a href="docs/template_config.yaml">Template Config</a><br>
</h1>

<p align="center">
  <a href="https://github.com/liuran001/mihomo/actions"><img src="https://img.shields.io/github/actions/workflow/status/liuran001/mihomo/build.yml?branch=Alpha&style=flat-square&label=build"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/liuran001/mihomo/Alpha?style=flat-square">
  <a href="https://github.com/liuran001/mihomo/releases"><img src="https://img.shields.io/github/release/liuran001/mihomo/all.svg?style=flat-square"></a>
</p>

一个 [mihomo](https://github.com/MetaCubeX/mihomo) 的三方合并分支，以 [vernesong](https://github.com/vernesong/mihomo) 的 smart 内核为底，合入 [TanakaLun](https://github.com/TanakaLun/mihomo/tree/ebpf-inbound) 的 eBPF 透明入站。主要面向**随身 WiFi / 手机热点 / 软路由当旁路网关**这个场景。

通用配置和用法请看[上游官方文档](https://wiki.metacubex.one/)，这里只写和原版不一样的地方。

## 和原版相比多了什么

**一、eBPF 入站，国内 IP 可以完全不过核心。** 和 dae 一样的做法：国内 IP 的判定放进内核里，命中的包在内核网络栈里直接放行，不进 mihomo 进程。延迟和 CPU 都省下来，机器越弱越明显。同时它是透明代理，下联设备什么都不用配。

**二、自动选择能挑出真正支持 UDP / IPv6 的节点。** 原版 url-test 只比 HTTP 延迟，一个 UDP 被黑洞的中转（IEPL 线路很常见）在面板上延迟一片绿，实际 QUIC、游戏、通话全部静默失败。这里会主动探测节点转不转 UDP、能不能走 IPv6，优先选能用的。

**三、Tailscale 可以接受入站，能当 Subnet Router 和 Exit Node。** 原版 `type: tailscale` 只能出站。这里可以反过来，让 tailnet 里的其他设备访问进来，而且进来的流量会走一遍你的分流规则。

赶时间的话直接跳到[完整配置示例](#完整配置示例)。

---

# 一、eBPF 入站

- **透明代理**：下联设备不用改任何配置，接上就走代理。
- **国内流量不过核心**：命中 CN IP 的包直接在内核放行。
- **不需要 iptables / nftables**：不写防火墙规则，也不需要策略路由。
- **能管本机，也能管下联**：`local` 管本机应用，`shared` 管转发流量，`hybrid` 两个都管。

## 最小配置

```yaml
listeners:
  - name: ebpf-in
    type: ebpf
    mode: hybrid
    dns-mode: hijack
    shared:
      interface: [br0]        # 换成你的下联网卡名

tun:
  enable: false               # 只用 eBPF 的话关掉；一起开见「和 TUN 共存」
```

## 让国内 IP 不过核心

这是这个分支最主要的功能，两步。

**一、准备一个 CN IP 规则集**，必须 `behavior: ipcidr`，域名规则集在这里没有用：

```yaml
rule-providers:
  CN-IP:
    type: http
    behavior: ipcidr          # 必须 ipcidr，写成 domain 会被静默忽略
    format: mrs
    interval: 86400
    path: ./rule_provider/cn-ip.mrs
    url: "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/cn.mrs"
```

**二、在 listener 里引用它：**

```yaml
listeners:
  - name: ebpf-in
    type: ebpf
    mode: hybrid
    dns-mode: hijack
    bypass-rule-set:
      - CN-IP                 # 写 rule-providers 里的名字
    shared:
      interface: [br0]
```

配好之后这些网段的 TCP / UDP 包在内核里直接放行，mihomo 的连接列表里看不到它们——这是正常的，说明生效了。上面那个 `cn.mrs` 同时含 IPv4 和 IPv6 网段。规则集内容变化后每 3 秒自动同步进内核，不用重启。

## 注意事项（这几条不看会踩坑）

- **DNS 永远走核心，不受 bypass 影响。** `dns-mode: hijack` 时 53 端口无条件劫持进核心，内核里 DNS 判断排在所有 CIDR 判断之前。所以基于 DNS 的广告拦截（`nameserver-policy` 配 `rcode://success` 那种）照常工作，不会因为开了 CN IP 直连就失效。
- **fake-ip 段永远不会被放行。** 就算你把 `fake-ip-range` 设成落在私网表里的 `100.64.0.0/10`，这些地址也照样进核心。改了热重载即可生效。
- **只有 `behavior: ipcidr` 的规则集会被采纳。** 写成 `domain` 不报错，会被安静跳过。
- **下联网卡要填对。** `shared.interface` 填下联那张卡（热点 `wlan0`、桥接 `br0`），填成上联网卡不会生效。

## 和 TUN 共存

TUN 和 eBPF 可以一起开，bypass 靠两个机制按集合大小分工，默认都是开的：

- **私网地址走路由排除。** `bypass-private-address: true` 时，eBPF 会把私网网段报给 TUN，TUN 建设备时就把它们从 auto-route 里摘掉，流量根本不进 TUN，是真正的直连。fake-ip 段和 TUN 自己的地址会被排除在外。
- **`bypass-rule-set` 走到达即直连。** 上万条前缀灌不进路由表，所以这些目标被 TUN 抓进来之后不进规则引擎，直接按直连处理（`bypass-tun-direct`，默认开，仅 rule 模式生效）。代价是多一次用户态转发。想彻底零开销就别开 TUN，或者把网段手写进 `tun.route-exclude-address`。

要关掉后者（比如你就是想让 TUN 处理某些网段）：

```yaml
listeners:
  - name: ebpf-in
    type: ebpf
    bypass-tun-direct: false
```

关掉之后被 TUN 接管的 bypass 网段会在日志里报出来，让你自己决定怎么处理。

两条同开时的注意：

- **`strict-route: true` 建议关掉。** 它会重排策略路由并阻断绕过 TUN 的流量，和 eBPF 的 lo 重定向、核心自己的直连出站都可能互斥。
- **同一张网卡不要同时开 `shared` 和 TUN 的 `auto-redirect`。** 两套透明代理叠在一张网卡上顺序难保证，用 `shared.interface` 和 TUN 的 `include-interface` / `exclude-interface` 把网卡分开。

## 完整参数表

```yaml
listeners:
  - name: ebpf-in
    type: ebpf

    # ---- 顶层 ----

    # local  = 只管本机进程发出的连接
    # shared = 只管从下联网卡转发过来的连接（旁路网关用这个）
    # hybrid = 两个都管
    # 默认 local
    mode: hybrid

    # 要接管的协议，默认两个都接管
    network: [tcp, udp]

    # UDP 会话保活时间，单位秒。默认 300，最小 5
    udp-timeout: 300

    # TC filter 优先级，默认 1。为 1 时内核支持就用 TCX 挂载，否则退回 clsact
    tc-priority: 1

    # 命中这些规则集的目标 IP 直接在内核放行，不进核心
    # 只认 behavior: ipcidr 的规则集
    bypass-rule-set:
      - CN-IP

    # TUN 也开着时，被 TUN 的 auto-route 抓进来的 bypass 目标是否直接直连，
    # 不再进规则引擎。默认 true。见上面「和 TUN 共存」
    bypass-tun-direct: true

    # dns-mode 和 bypass-private-address 写在顶层会套用到所有启用的角色上，
    # 角色自己写了的以自己的为准

    # ---- local：本机进程 ----
    local:
      # 数据面，默认 cgroup
      #   cgroup = connect()/sendmsg() 时改写目的地址，5.4 内核就能跑
      #   tc     = 默认网卡 egress 选包 + veth + bpf_sk_assign，需要 5.7+ 内核及实际 helper 支持
      data-plane: cgroup

      # cgroup v2 挂载点，一般不用填，会自动找（只对 data-plane: cgroup 有意义）
      cgroup-path: /sys/fs/cgroup

      # DNS 处理方式，默认 hijack
      #   hijack         = 所有 53 端口无条件劫持进核心（推荐，广告拦截/分流都靠它）
      #   respect_policy = 先过 UID 策略再劫持（旧名 respect_bypass 也认）
      #   off            = 完全不管 DNS
      dns-mode: hijack

      # 是否接管 IPv6，默认 true
      ipv6: true

      # 是否放行私网地址（10/8、192.168/16 等），默认 true
      bypass-private-address: true

      # 只接管这些 UID 的流量（不填 = 全部接管）
      include-uid: [0, 1000]
      include-uid-range: ["10000:19999"]   # 注意分隔符是冒号，不是连字符

      # 排除这些 UID，优先级高于 include
      exclude-uid: [1052]
      exclude-uid-range: ["20000:20100"]

      # 以下三个是 Android 专用，会自动解析成 UID
      include-android-user: [0]                 # 只接管主用户
      include-package: [com.android.chrome]     # 只接管这些应用
      exclude-package: [com.tencent.mm]         # 排除这些应用

      # 这些目标端口不接管
      bypass-port: [22]
      bypass-port-range: ["6000:6100"]

    # ---- shared：下联转发 ----
    shared:
      # 数据面，默认 packet_rewrite
      #   packet_rewrite = ingress 改写目的地址、egress 还原，要以太网帧，5.4 内核就能跑
      #   socket_assign  = 保留原始五元组，bpf_sk_assign + 策略路由，需要 5.7+ 内核及实际 helper 支持，
      #                    支持 rmnet / PPP 这类没有以太头的网卡
      data-plane: packet_rewrite

      # 下联网卡，必填。可以填多个；正在当上联出口的那张会自动跳过，等它变回下联再挂上
      interface: [br0]

      dns-mode: hijack
      ipv6: true

      # 做旁路网关时通常设 false，否则下联互访会被放行、拿不到统计
      bypass-private-address: false

      # 只接管来自这些网段的客户端（不填 = 全部）
      include-source-cidr: [192.168.0.0/24]
      exclude-source-cidr: [192.168.0.100/32]

      # 按 MAC 过滤客户端，优先级高于 CIDR
      include-mac-address: ["aa:bb:cc:dd:ee:ff"]
      exclude-mac-address: ["11:22:33:44:55:66"]

      bypass-port: []
      bypass-port-range: []
```

旧版参数仍可解析：`ipv6-mode`（`always` / `off`）映射成 `ipv6`，`state-capacity` 仍决定内核状态表容量（上限 1048576），`shared.advanced.tc-priority` / `data-plane` 映射到对应新键。`tcp-splice` 和 `shared.advanced.routing-mark` / `routing-table` 已无作用，启动时会提示一次。

## 对内核版本的要求

版本号只能作为参考，实际还取决于内核配置、厂商回移补丁、权限及所选数据面：

| 内核 | 影响 |
| --- | --- |
| 5.4 及以上 | 默认数据面（local 走 cgroup、shared 走 packet_rewrite）的目标兼容范围 |
| 5.5 及以上 | 可提供 `sock_release` 关闭回收能力 |
| 5.7 及以上 | `local.data-plane: tc` 和 `shared.data-plane: socket_assign` 需要的 `bpf_sk_assign` |
| 5.14 及以上 | hash map 支持 `BPF_MAP_LOOKUP_AND_DELETE_ELEM`，缺失时走兼容路径 |
| 6.6 及以上 | 可用 TCX 挂载，不能用则退回 clsact |

缺少可选能力时会降级；缺少所选数据面的必需能力时会启动失败，不会自动换成另一种数据面。

**Linux 6.6.0 ～ 6.6.46 另有 LPM trie 保护。** 这段内核可能触发 UBSAN 缺陷，未在 BTF 中识别到修复时核心会拒绝写入非空 LPM 策略（bypass CIDR、UID、源网段）。升级到 6.6.47+ 即可。

已连接的 Android 5.4 设备通过了 cgroup 和 shared packet_rewrite 的测试，但不支持 `bpf_sk_assign`。完整结果见[验证记录](docs/ebpf-validation.md)。

---

# 二、自动选择支持 UDP / IPv6 的节点

在策略组里加开关就行，对 `url-test` / `smart` / `load-balance` 生效：

```yaml
proxy-groups:
  - name: 自动选择
    type: url-test
    use: [机场A, 机场B]
    prefer-udp: true          # 优先选真的能转发 UDP 的节点
    prefer-ipv6: true         # 优先选真的能走 IPv6 出站的节点
    penalize-unstable: true   # 经常断流的节点自动降权
```

UDP 用 STUN 探测，IPv6 用一个只有 v6 的端点探连通性。探测走独立通道，不污染面板上的延迟和存活状态。

## 它是降权，不是过滤

节点不会被踢出候选池，只是在排序时加一笔罚时：

| 探测结果 | 加多少 |
| --- | --- |
| 确认支持 | 0 ms |
| 还没探测 | 50 ms |
| 确认不支持 | 600 ms |

两个开关都开时罚时累加，最多 1200 ms。所以一个 100 ms 但不支持 IPv6 的节点（算 700 ms）仍然赢过一个 900 ms 的 IPv6 节点；延迟差不多的时候，能用的那个总是排前面。

之所以不做成过滤：探测本身不可靠（IPv6 探测目标只有在你自己的 IPv6 通的时候才能到达，失败率上六成很正常），踢节点会让一个组因为和"能不能转发流量"无关的原因被削光。

`penalize-unstable` 针对另一类节点：延迟探测永远合格，真实流量一进去就死（握手成功、发出去几个字节、一个字节都没回来）。这类连接记进 10 分钟滑动窗口，每次加 150 ms、最多 1.5 秒，窗口过期后自己恢复。

各组类型的行为：

| 组类型 | 怎么起作用 |
| --- | --- |
| `url-test` / `smart` | 罚时计入排序延迟 |
| `load-balance` | 优先在满足条件的节点里分流量，全挂了才用其他的 |
| `select` / `fallback` | 不介入 |

`select` 和 `fallback` 刻意不动：手动选的节点、显式写好的优先级顺序，不该被一次探测结果改掉。

探测结果按节点身份缓存在内存里，成功 30 分钟、失败 10 分钟。**核心重启后要重新探测**，这段收敛期里所有节点都按"还没探测"算。

## 两个容易配错的地方

**健康检查参数是同级的 `url` / `interval` / `lazy`。** 嵌套的 `health-check: {...}` 属于 `proxy-providers`，写在 smart 策略组里不会生效。用 `use` 引用订阅时也要检查 provider 自己的健康检查配置，组级 `lazy` 不会覆盖它。

**`sample-rate` 不是省电开关。** 它只控制开启 `collectdata` 后的训练样本采集比例（默认 1，有效值 0～1），不控制连接统计、节点测速或后台探测。`collectdata` 和 `uselightgbm` 默认关闭。后台任务在闲置和断网时会自动收敛，没有也不需要额外的省电参数。

## DNS 连接复用

普通 UDP、TCP 和 DoT DNS 默认使用有界连接池，无需改配置。若某个上游或代理不适合复用，在服务器后加 `#disable-reuse=true`：

```yaml
dns:
  nameserver:
    - 'tls://1.1.1.1:853#disable-reuse=true'
```

---

# 三、Tailscale 入站 / Subnet Router / Exit Node

```yaml
proxies:
  - name: TS
    type: tailscale
    hostname: my-gateway              # 在 tailnet 里显示的机器名
    auth-key: tskey-auth-xxxxx
    udp: true
    accept-routes: true               # 接受其他 Subnet Router 通告的路由

    listen-port: 41641                # 固定 magicsock 端口，配 TUN 时需要，见下

    advertise-routes:                 # 通告成 Subnet Router
      - 192.168.0.0/24
    advertise-exit-node: true         # 通告成 Exit Node
```

配好后要去 tailnet 管理后台批准路由（或在 ACL 里配 autoApprovers），和 Tailscale 官方流程一样。

从 tailnet 进来的连接会经过 mihomo 的规则引擎（新增了 `TAILSCALE` 入站类型）。当 Exit Node 用的时候出口流量按你的规则走——国内直连、国外走代理，比原版 Tailscale 的 Exit Node 灵活。

## 如果你还在用 TUN

只用 eBPF 可以跳过这节。TUN 模式下 magicsock 的 UDP socket 出站源地址不定，会被 auto-route 抓走导致流量绕回 mihomo 自己。两种解法选一个：

**解法一，固定端口 + sing-tun 原生豁免**（推荐，纯配置）：

```yaml
proxies:
  - name: TS
    type: tailscale
    listen-port: 41641
tun:
  exclude-src-port: [41641]
```

**解法二，打 routing-mark**，自己写策略路由绕开 TUN：

```yaml
proxies:
  - name: TS
    type: tailscale
    routing-mark: 0x2333
```

另外规则里 tailnet 的网段要排在所有 GEOIP / 私网 DIRECT 规则**前面**，否则会被提前匹配走：

```yaml
rules:
  - IP-CIDR,100.64.0.0/10,TS,no-resolve
  - IP-CIDR6,fd7a:115c:a1e0::/48,TS,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,自动选择
```

---

# 完整配置示例

一台随身 WiFi，同时做透明网关、CN IP 直连、Tailscale Subnet Router 和 Exit Node：

```yaml
mode: rule

# 各地区组共用的锚点
use: &use
  type: smart
  use: [机场A, 机场B, 备用机场]
  prefer-udp: true
  prefer-ipv6: true
  policy-priority: '\[备用机场\]:0.3'    # smart 内核原生选项，<1 降权
  url: https://cp.cloudflare.com
  interval: 300
  lazy: true

proxies:
  - name: TS
    type: tailscale
    hostname: my-gateway
    auth-key: tskey-auth-xxxxx
    udp: true
    accept-routes: true
    advertise-routes: [192.168.0.0/24]
    advertise-exit-node: true

proxy-groups:
  - {name: 香港, <<: *use, filter: "(?i)港|hk"}
  - {name: 日本, <<: *use, filter: "(?i)日本|jp"}
  - {name: 自动选择, <<: *use, type: url-test, tolerance: 2, penalize-unstable: true}

rule-providers:
  CN-IP:
    type: http
    behavior: ipcidr              # eBPF bypass 只认 ipcidr
    format: mrs
    interval: 86400
    path: ./rule_provider/cn-ip.mrs
    url: "https://github.com/MetaCubeX/meta-rules-dat/raw/meta/geo/geoip/cn.mrs"
  广告规则:
    type: http
    behavior: domain              # 广告拦截在 DNS 层做，用域名规则集
    format: mrs
    interval: 86400
    path: ./rule_provider/ads.mrs
    url: "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Clash.mrs"

listeners:
  - name: ebpf-in
    type: ebpf
    mode: hybrid
    dns-mode: hijack                # 顶层写法会套用到 local 和 shared 两个角色
    bypass-rule-set: [CN-IP]        # 国内 IP 不过核心
    bypass-private-address: false   # 旁路网关：下联互访也进核心，拿得到统计
    shared:
      interface: [br0]

# 只用 eBPF 的话关掉 TUN；一起开见「和 TUN 共存」
tun:
  enable: false

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: redir-host
  nameserver-policy:
    "rule-set:广告规则": rcode://success   # DNS 层拦广告，不受 bypass 影响
  nameserver: [223.5.5.5, 119.29.29.29]

rules:
  - IP-CIDR,100.64.0.0/10,TS,no-resolve
  - IP-CIDR6,fd7a:115c:a1e0::/48,TS,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,自动选择
```

---

# 构建

不需要 NDK，不需要 clang，不需要 cgo，BPF 对象已随仓库提供：

```bash
# Android / arm64（随身 WiFi、手机）
CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
  go build -tags "with_gvisor with_ebpf" -trimpath \
  -ldflags '-w -s -buildid=' -o mihomo .

# Linux / amd64
CGO_ENABLED=0 GOARCH=amd64 go build -tags "with_gvisor with_ebpf" -o mihomo .
```

必须带 `with_ebpf` 才会编入 eBPF 入站。

实现细节和改动记录见 [docs/internals.md](docs/internals.md)，英文完整规格见 [docs/ebpf-inbound.md](docs/ebpf-inbound.md)。

---

# 上游与致谢

代码来自这三处，通用配置和用法请优先看它们的文档：

- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) — 上游本体，[官方文档](https://wiki.metacubex.one/)
- [vernesong/mihomo](https://github.com/vernesong/mihomo) — smart 内核（`type: smart` 策略组、LightGBM 权重模型、`policy-priority` 等）
- [TanakaLun/mihomo](https://github.com/TanakaLun/mihomo/tree/ebpf-inbound) — eBPF 透明入站的 mihomo 适配层
- [CHIZI-0618/sing-box](https://github.com/CHIZI-0618/sing-box/tree/testing-ebpf-tc-rewrite) — eBPF 后端本体（`common/ebpf`，统一 TC + cgroup 数据面）

以及 mihomo 自身所站立的项目：

- [Dreamacro/clash](https://github.com/Dreamacro/clash)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
- [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
- [yaling888/clash-plus-pro](https://github.com/yaling888/clash)

# 许可

GPL-3.0，与上游一致。
