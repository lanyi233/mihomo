# 性能与省电检查记录

两轮检查覆盖后台调度、订阅更新、健康检查、DNS 缓存与查询、Smart 存储与统计、日志/API 流、eBPF 用户态维护和传输层。以消除无效工作和减少分配为主，不调整用户配置的探测频率，也不改变协议保活和重传参数。

## 已实施

| 位置 | 问题与修改 | 行为边界 |
| --- | --- | --- |
| `transport/sudoku/obfs/httpmask` | poll/stream 上传循环原先每 5 ms 空唤醒；改为首条待发送数据到达时启动可复用定时器，发送后停止。 | 空闲时该循环不再产生周期唤醒；首条待发送数据仍使用 5 ms 批处理窗口，满批立即发送，保留重试和 CloseWrite 排空。 |
| `component/resource/fetcher.go` | 自动更新接入已有电源/网络暂停通知；停止暂停期定时器，恢复时对到期任务错峰。修复过期缓存强制更新后立即重复下载、初次下载失败绕过退避。 | 暂停阻止新的自动下载，不中断已经开始的下载；手动更新可用。恢复错峰最多 30 秒，也不超过更新周期。 |
| `adapter/provider/healthcheck.go` | 按不可变配置快照缓存过滤正则，避免每轮健康检查重复编译。 | 添加过滤条件时生成新快照，缓存自动失效。 |
| `adapter/outboundgroup/smart_tasks.go` | 正在执行的任务不再参与下一次定时器截止时间计算；结束后一次跳过遗漏周期。 | 慢任务不会重复启动或阻塞其他任务，保留原调度相位。 |
| `dns/resolver.go`、`dns/util.go` | 关闭调试日志且没有日志订阅者时，跳过 DNS 结果和时间格式化；使用紧凑 name/class/type 缓存键；避免 RR 临时拼接与多余 goroutine/channel。 | 保留日志订阅、消息复制隔离、TTL、OPT 移除、主/备用 DNS 查询策略。 |
| `component/smart/cachefile.go` | 蓄水池抽样在数据库只读事务内保留候选引用，最终样本才复制。 | 引用不会逃出事务，保留抽样分布、数量限制和返回结果独立所有权。 |
| `component/smart/memory.go` | unwrap 缓存命中时不再遍历代理并构造名称切片。 | 缓存过期和空结果仍会正常刷新。 |
| `tunnel/statistic/manager.go` | 多个面板共享一秒内的按需内存采样；失败查询同样限频，RSS 改为原子读写。 | 内存指标可能缓存约一秒；没有新增后台采样定时器。 |
| `log`、`common/observable`、`tunnel` | 无输出和订阅者的 Info 日志跳过格式化与通道交接；订阅状态改为原子读取，连接日志在生成地址字符串前判断是否需要输出。 | 静默模式下的已建立日志订阅仍正常接收，订阅增删保持锁内同步。 |
| `transport/mkcp` | 完全空闲的连接等待原有 ping/失联截止时间；报文编码复用缓冲并预留 nonce 空间。 | 有数据、ACK 或正在关闭时保留配置 TTI；写入/接收事件立即唤醒。保留 3 秒 ping、30 秒失联和重传语义。 |
| `transport/kcptun` | Close 清理当前及退休会话、socket，取消在途拨号；回收列表原地复用，空表停表。 | 关闭后不再接受新流，迟到的拨号结果也会被关闭；待回收会话仍按原周期检查。 |
| `listener/hysteria2_realm` | 按最近会话到期时间回收，空表不启动定时器，首次注册唤醒。 | 保留 TTL、续期及过期配额回收；忙时扫描间隔至少一秒。 |
| `listener/sing_ebpf`、`common/ebpf` | UDP socket 扫描遇到新鲜 LRU 条目即停止；重复流引用及不提前截止时间的释放不再重复通知回收器。 | 未改变内核程序、orphan 扫描周期、socket 租约保护或释放宽限期。 |
| `hub/route` | API 流响应取消，WebSocket 读取控制帧并关闭 hijack 连接；断开的日志订阅及时释放。 | HTTP/WS 写入限制为 10 秒，HTTP 取消可中断阻塞写入/刷新，结束后清除 deadline；保留 ping/pong/close，非法刷新间隔返回 400。 |
| `component/dialer` | 双栈 fallback 使用单次截止定时器，截止后到达的可用 fallback 立即返回。 | 仍优先使用截止前返回的主地址连接，并清理未采用的连接。 |
| `component/power`、`component/updater`、`ntp` | GEO/模型/NTP 后台任务接入暂停事件；下载恢复错峰；GEO 更新锁改为 CAS 防止重复更新。 | NTP 在线初次和逾期恢复仍立即同步；下载与 NTP 的后续周期从任务完成后计算，避免慢任务积压后连发。 |

## 本机微基准

Windows amd64，Intel Core i7-12700H，Go 1.27.0。DNS 数据取三轮中位数；其他结果为本轮基准观测值。时间会受机器负载影响，分配量更便于复核。

| 场景 | 修改前 | 修改后 |
| --- | --- | --- |
| DNS 缓存命中 | 3045 ns，520 B，18 allocs | 620 ns，288 B，6 allocs |
| DNS 入缓存 | 979 ns，328 B，8 allocs | 541 ns，288 B，6 allocs |
| 无 fallback 的本地 rcode 查询 | 4183 ns，712 B，19 allocs | 1159 ns，385 B，7 allocs |
| Smart 一万条记录抽样一百条 | 约 793 µs，162 KB，1135 allocs | 约 716 µs，38 KB，216 allocs |
| 已缓存的内存指标读取 | 3.95–5.14 µs，1 alloc | 约 39 ns，0 allocs |
| 健康检查过滤片段 | 38353 ns，7120 B，89 allocs | 730 ns，48 B，1 alloc |
| 无订阅者的静默 Info 日志 | 约 973 ns，32 B，1 alloc | 约 7 ns，0 B，0 allocs |
| mKCP 1200B simple 编码 | 5631 ns，2560 B，2 allocs | 3626 ns，0 B，0 allocs |
| mKCP 1200B AES 编码 | 3244 ns，5632 B，4 allocs | 1155 ns，0 B，0 allocs |

WSL/Linux 同机基准：UDP 回复 socket 的新鲜条目扫描从 4075 降至 237 ns/op；TCP 后续释放登记从 72.7 降至 42.5 ns/op，两者均零分配。它们衡量对应维护操作，不代表整条 UDP/TCP 数据路径的加速比。

HTTP 隧道上传定时器的空闲唤醒从理论约 200 次/秒/连接降至零；这里仅指本次修改的上传批处理定时器，不包含网络栈、其他维护任务或整机唤醒。

上述数据说明 CPU 工作与分配减少，不能直接换算为整机吞吐或电池续航提升。目标路由器/Android 设备上的功耗尚未实测。

复测命令：

```sh
go test ./dns -run '^$' -bench 'Benchmark(ResolverCacheHit|PutMsgToCache|IPExchangeNoFallback)$' -benchmem -count=3
go test ./component/smart -run '^$' -bench BenchmarkDBViewPrefixScanSample -benchmem
go test ./tunnel/statistic -run '^$' -bench BenchmarkManagerMemory -benchmem
go test ./adapter/provider -run '^$' -bench BenchmarkHealthCheckFilter -benchmem
go test ./log -run '^$' -bench BenchmarkDisabledInfo -benchmem
go test ./transport/mkcp -run '^$' -bench BenchmarkPacketWriter -benchmem
# 下列命令需要 Linux/WSL：
go test -tags with_ebpf ./listener/sing_ebpf -run '^$' -bench BenchmarkReplySocketSweepRecentlyUsed -benchmem
go test -tags with_ebpf ./common/ebpf -run '^$' -bench BenchmarkSharedNetworkTCPReleaseLaterDeadline -benchmem
```

## 验证与限制

新增回归覆盖 DNS 缓存隔离及 TTL 边界、抽样所有权、内存采样并发、自动更新暂停恢复与退避，以及隧道批量发送和半关闭。第二轮另覆盖日志订阅、HTTP/WS 断开与阻塞 I/O、双栈 fallback、会话/socket 清理、mKCP 保活/重传、Realm 续期和 eBPF 唤醒合并。隧道及协议计时测试使用虚拟时间；阻塞 HTTP 流同时验证请求取消、10 秒超时和后续连接复用。

验证结果：

- 首轮 Windows `go test ./...` 通过。首次运行仅 `hub/executor` 出现 Windows 临时目录清理失败，功能断言未失败；该包单独重跑及全仓重跑均通过。
- 最终代码在 WSL 下 `CGO_ENABLED=1 go test -tags with_gvisor,with_ebpf -timeout 10m ./...` 全仓通过，包含协议互通测试。
- 所有改动包的 `go vet` 通过；provider/resource/power/outboundgroup 相关测试连续三轮通过。
- Linux ARM64 的 `go build -tags 'with_gvisor with_ebpf'` 交叉构建通过。
- 已通过 WinGet 安装 Windows WinLibs GCC 16.2（POSIX/UCRT）；首轮改动包，以及第二轮的日志、路由、拨号、后台维护、mKCP/kcptun 包在 Windows 下启用 CGO 通过 race 检测。
- WSL Arch Linux 的 Go 1.27/GCC 工具链已验证，涉及改动的包通过 Linux race 检测，eBPF 包带 `with_ebpf` 标签执行。
- 在 WSL root 的隔离网络命名空间内，带 race 的 8 类内核集成测试通过：MapBatch、LRUFallbackBounded、TCProgramRun、TCIPv6PathIsolation、TCFragmentPolicy、SharedRewriteProgramRoundTrip、SharedRewritePolicy、FakeIPICMPPassThrough。
- `git diff --check` 通过。

原有 `Fetcher.Close` 只发出取消信号，不等待在途更新完成，本轮未改变其生命周期约定。WSL 内核测试不等同于真实路由器/Android 的设备兼容性和电池测试。

后续目标设备评估应分别测量空闲、DNS 缓存命中、小流量长连接和持续传输，固定配置与网络条件，对比 CPU 时间、分配/GC、唤醒次数和电量消耗。mKCP 仅合并完全空闲时的唤醒，没有延长协议保活或重传参数。
