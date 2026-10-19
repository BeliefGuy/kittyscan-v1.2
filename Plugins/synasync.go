package Plugins

// synasync.go — masscan 风格的异步无状态 SYN 端口扫描引擎（平台无关核心）。
//
// 设计要点（与既有实现的关系）：
//   - 仅在 `-syn` 且平台后端探测成功时启用（EngineActive()），portscan.go 顶部
//     分流；否则一切行为与旧路径完全一致（Linux 逐端口 raw socket / TCP connect）。
//   - 无状态收发：固定 asyncSenders 个 sender 协程从 sendQ 取探测，限速发 SYN；
//     单个 dispatch 协程收包，按 (目标IP, 目标端口) 查在途表判定——masscan/zmap
//     同款模型，不再"每端口一个 socket/一次阻塞等待"。
//   - 超时与重传由 100ms 桶扫描器集中调度；首发后补发一次（修掉旧 -syn 实现
//     "丢一包干等满超时"的漏报短板）。
//   - 在途探测总数有上限（asyncMaxInflight），大网段扫描内存有界。
//   - 本地/回环目标 pcap 抓不到回包，自动回落既有 PortConnect（含 SetLinger(0)
//     的 RST 关闭路径），与不加 -syn 时行为一致。
//   - 二层细节（路由选源/ARP/网卡句柄/链路层头）全部在平台后端内完成；后端由
//     synasync_windows.go（Npcap, amd64/arm64）与 synasync_other.go（桩）提供。
//
// 2026-10-19 用户批准改造（"开始改造吧"），变更明细见 mnemon《配置文件与源码修改日志》。

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shadow1ng/fscan/common"
)

// ---------------- 常量 ----------------

const (
	thSYN = 0x02
	thACK = 0x10
	thRST = 0x04

	protoTCP = 6

	// 调度桶粒度：超时/重传按 100ms 对齐扫描
	asyncTickMs = 100
	// 首发后重传一次，延迟 = clamp(超时/2, 500ms, 1000ms)
	asyncRetryMinMs = 500
	asyncRetryMaxMs = 1000
	// 每个探测最多实际发包次数（首发 + 1 次重传）
	asyncMaxAttempts = 2

	// 发送队列容量（生产者背压边界之一）
	asyncSendQCap = 8192
	// 在途探测（已登记未判定）总数上限，防止 /16 级目标把内存打爆
	asyncMaxInflight = 300000
	// sender 协程数（收发无状态，该值不等于并发判定能力）
	asyncSenders = 4
	// 响应通道缓冲
	asyncRespQCap = 4096
	// 邻居(ARP)解析并发上限
	asyncArpWorkers = 16

	// -synrate 未指定(0)时的自动发包速率（包/秒）；负数 = 不限速。
	// 2026-10-19 由 20000 下调至 3000：20kpps 突发经公网链路（家用 NAT 会话表/
	// 运营商 QoS/目标抗扫描限速）实测会丢包漏报（112.28.218.37 扫 1-10000 漏端口）；
	// 3000 是公网安全线，局域网全端口段约 22s，追求速度可显式 -synrate 拉高。
	asyncAutoRate = 3000
)

// 后端可返回的可恢复错误
var (
	errNeedARP  = fmt.Errorf("synasync: neighbor missing, arp needed")
	errNoRoute  = fmt.Errorf("synasync: neighbor dead or unreachable")
	errEngineNA = fmt.Errorf("synasync: async SYN engine not available on this platform/arch")
)

// ---------------- 类型 ----------------

// probeKey 在途探测表键：目标 IPv4（大端序 uint32）+ 目标端口。
type probeKey struct {
	ip   uint32
	port uint16
}

// asyncProbe 一次端口探测的全部状态。deadline 只在"首次把包送上网（或进入
// ARP 等待）"时启动，纯排队不计超时。dst/dstPort/srcPort/addr 创建后只读。
type asyncProbe struct {
	key      probeKey
	dst      [4]byte
	dstPort  uint16
	srcPort  uint16
	addr     string // "ip:port"，判定开放时直接作为结果行
	deadline int64  // unix ms；0 = 时钟未启动
	attempts int    // 已成功交给后端发出的次数
	done     bool   // 已判定（开放/关闭/超时），由 engine.mu 保护
}

// synDatagram 后端剥掉链路层头后交来的完整 IPv4 包（≥40 字节）。
type synDatagram struct {
	ip []byte
}

// synBackend 平台后端契约。实现必须保证 send/neighborGate/sourceIP 可被多个
// sender 并发调用（内部自行加锁），resolveARP 按 dst 去重。
type synBackend interface {
	// sourceIP 返回访问 dst 时本机路由选用的源 IPv4（内部缓存，同步快路径）。
	sourceIP(dst [4]byte) ([4]byte, error)
	// neighborGate 二层就绪预检（不消耗发包令牌）：nil=可发送，
	// errNeedARP=邻居未知（应 park 并触发 resolveARP），errNoRoute=负缓存期内。
	neighborGate(dst [4]byte) error
	// send 发送完整 IPv4 包（后端封装链路层并选择设备句柄）。
	// 与预检同样可能返回 errNeedARP / errNoRoute（缓存竞态兜底）。
	send(pkt []byte, dst [4]byte) error
	// resolveARP 异步解析 dst 的二层地址，完成回调 ok（负缓存也由后端记录）。
	// 接收循环由后端构造时自行启动并推入 newSynBackend 传入的通道。
	resolveARP(dst [4]byte, cb func(ok bool))
}

// newSynBackend 由平台文件提供（synasync_windows.go 与 synasync_other.go
// 各恰好一个定义，构建标签保证互斥）。

// ---------------- 引擎全局状态 ----------------

var (
	// engine 由 tryStartAsyncEngine 创建；EngineActive 是 portscan.go 的分流判据。
	engine      *asyncEngine
	engineOn    bool
	synFailHint string // -syn 不可用时的具体原因（Npcap errbuf 等），scanner.go 打印
	asyncLogAt  int64  // 限流日志时间戳（秒）

	// synDebug 调试开关：环境变量 KITTYSYN_DEBUG=1 时解除日志限流并输出
	// 引擎关键路径细节（设备选择/校准/收发计数/邻居解析），用于现场排查
	// "引擎激活但结果不对"类问题；默认关闭，不影响正常使用。
	synDebug = os.Getenv("KITTYSYN_DEBUG") == "1"

	// 调试计数（synDebug 模式下辅助观察收发是否发生）
	synSendOk  int64
	synRecvTcp int64
)

// EngineActive 返回异步 SYN 引擎是否已就绪（-syn 且后端初始化成功）。
func EngineActive() bool { return engineOn && engine != nil }

// tryStartAsyncEngine 初始化引擎与后端。失败时返回的字符串会由 scanner.go
// 打印为回退原因，便于定位"为什么没走 SYN"。
func tryStartAsyncEngine() (string, error) {
	e := newAsyncEngine()
	b, err := newSynBackend(e.respCh)
	if err != nil {
		return err.Error(), err
	}
	e.backend = b
	engine = e
	engineOn = true
	return "", nil
}

// asyncLogf 限流打印（每秒至多一条），避免故障场景刷屏；
// KITTYSYN_DEBUG=1 时不限流全量输出。
func asyncLogf(format string, args ...interface{}) {
	if synDebug {
		fmt.Printf("[d] synasync: "+format+"\n", args...)
		return
	}
	now := time.Now().Unix()
	last := atomic.LoadInt64(&asyncLogAt)
	if now <= last || !atomic.CompareAndSwapInt64(&asyncLogAt, last, now) {
		return
	}
	fmt.Printf("[-] synasync: "+format+"\n", args...)
}

// traceLogf 仅 KITTYSYN_DEBUG=1 时输出的追踪日志：正式模式下引擎保持静默
// （开放端口只出 [port] 等正式标签行，不刷内部判定碎片），诊断细节留给
// 调试开关。告警类（发送失败/邻居解析失败等）仍走 asyncLogf 常驻输出。
func traceLogf(format string, args ...interface{}) {
	if !synDebug {
		return
	}
	fmt.Printf("[d] synasync: "+format+"\n", args...)
}

func be32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

// srcPortFor 与 Linux 既有实现同款的源端口派生（30000~39999）。
func srcPortFor(port int) uint16 { return uint16(30000 + (port*7)%10000) }

// ---------------- 引擎主体 ----------------

type asyncEngine struct {
	backend synBackend
	respCh  chan synDatagram
	sendQ   chan *asyncProbe
	slots   chan struct{} // 在途上限信号量（生产者放入、判定时取走）

	// 以下共用 mu，临界区都很短；禁止在持锁时调用 resolve()。
	mu        sync.Mutex
	inflight  map[probeKey]*asyncProbe // 在途（已登记）
	parked    map[uint32][]*asyncProbe // 因邻居缺失按目标 IP 暂存的探测
	resolving map[uint32]bool          // 正在做邻居解析的目标 IP
	expB      map[int64][]*asyncProbe  // 超时桶：slot -> probes
	retB      map[int64][]*asyncProbe  // 重传桶：slot -> probes

	// start() 注入；写入先于其启动的所有协程，构成 happens-before
	started   bool
	results   chan string
	wg        *sync.WaitGroup
	timeoutMs int64

	// 限速
	rate   int64 // 包/秒；<0 = 不限速
	tokens chan struct{}
}

func newAsyncEngine() *asyncEngine {
	return &asyncEngine{
		respCh:    make(chan synDatagram, asyncRespQCap),
		sendQ:     make(chan *asyncProbe, asyncSendQCap),
		slots:     make(chan struct{}, asyncMaxInflight),
		inflight:  make(map[probeKey]*asyncProbe),
		parked:    make(map[uint32][]*asyncProbe),
		resolving: make(map[uint32]bool),
		expB:      make(map[int64][]*asyncProbe),
		retB:      make(map[int64][]*asyncProbe),
	}
}

func slotOf(ms int64) int64 { return ms / asyncTickMs }

// start 注入本次扫描的结果通道与 WaitGroup，启动全部引擎协程。
// 字段写入发生在协程创建之前，后续经通道同步，无数据竞争。
func (e *asyncEngine) start(results chan string, wg *sync.WaitGroup, timeoutMs int64) {
	e.results = results
	e.wg = wg
	e.timeoutMs = timeoutMs
	e.started = true

	rate := common.SynRate
	if rate == 0 {
		rate = asyncAutoRate
	}
	e.rate = rate
	if rate > 0 {
		e.tokens = make(chan struct{}, capTokens(rate))
		go e.tokenLoop(rate)
	}
	for i := 0; i < asyncSenders; i++ {
		go e.sendLoop()
	}
	go e.dispatchLoop()
	go e.expiryLoop()
	go e.retryLoop()
}

func capTokens(rate int64) int {
	c := int(rate / 10)
	if c < 100 {
		c = 100
	}
	if c > 100000 {
		c = 100000
	}
	return c
}

// tokenLoop 每 5ms 补充 rate/200 个发包令牌，实现 -synrate 限速。
// 缓冲满时跳过本轮补充（发送侧已饱和），循环继续。
func (e *asyncEngine) tokenLoop(rate int64) {
	per := rate / 200
	if per < 1 {
		per = 1
	}
	t := time.NewTicker(5 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		for i := int64(0); i < per; i++ {
			select {
			case e.tokens <- struct{}{}:
			default:
				i = per // 缓冲满：已达限速上界，跳过本轮剩余补充
			}
		}
	}
}

// takeToken 取一个发包令牌；不限速（rate<0）时直接返回。
func (e *asyncEngine) takeToken() {
	if e.tokens == nil {
		return
	}
	<-e.tokens
}

// isDone 在锁内读取探测判定状态（done 写侧持有 mu）。
func (e *asyncEngine) isDone(p *asyncProbe) bool {
	e.mu.Lock()
	d := p.done
	e.mu.Unlock()
	return d
}

// startClock 幂等地启动探测超时时钟（首次送网或进入 ARP 等待时调用）。
func (e *asyncEngine) startClock(p *asyncProbe) bool {
	e.mu.Lock()
	if p.deadline != 0 {
		e.mu.Unlock()
		return false
	}
	p.deadline = time.Now().UnixMilli() + e.timeoutMs
	slot := slotOf(p.deadline)
	e.expB[slot] = append(e.expB[slot], p)
	e.mu.Unlock()
	return true
}

// register 登记在途探测（时钟尚未启动）。同一 (ip,port) 重复登记（-hf 重复
// 行 / 重叠 CIDR）时，旧探测立即按无响应收尾——否则它被覆盖出在途表后
// 永远无法判定，会把 wg.Wait 挂死；同一个 ip:port 的探测结果不受损失。
func (e *asyncEngine) register(p *asyncProbe) {
	e.mu.Lock()
	old := e.inflight[p.key]
	e.inflight[p.key] = p
	e.mu.Unlock()
	if old != nil {
		e.resolve(old, false) // 幂等：已判定的直接跳过
	}
}

// resolve 判定一个探测并收尾：置 done、移出在途表、释放槽位；开放时先
// wg.Add 再推送结果（与旧 PortConnect 记账顺序一致，保证 wg.Wait 不会在
// 结果尚未入队时提前返回）。重复调用被 done 标志幂等拦截。
func (e *asyncEngine) resolve(p *asyncProbe, open bool) {
	e.mu.Lock()
	if p.done {
		e.mu.Unlock()
		return
	}
	p.done = true
	delete(e.inflight, p.key)
	e.mu.Unlock()

	<-e.slots // 释放生产者放入的在途槽位

	if open {
		traceLogf("OPEN %s", p.addr)
	}
	if open && e.wg != nil && e.results != nil {
		e.wg.Add(1)
		e.results <- p.addr
	}
	if e.wg != nil {
		e.wg.Done()
	}
}

// park 把探测挂到目标 IP 的邻居等待队列；首次挂起触发一次异步解析。
// 解析成功后整批冲回发送队列；失败则挂到超时正常收尾（不做假关闭判定）。
func (e *asyncEngine) park(p *asyncProbe) {
	e.startClock(p) // 等待也启动时钟：保证一定有判定，不泄漏槽位
	dip := p.key.ip
	dst := p.dst
	e.mu.Lock()
	e.parked[dip] = append(e.parked[dip], p)
	needResolve := !e.resolving[dip]
	if needResolve {
		e.resolving[dip] = true
	}
	e.mu.Unlock()
	if !needResolve {
		return
	}
	traceLogf("park %s: resolving neighbor/ARP", p.addr)
	go e.backend.resolveARP(dst, func(ok bool) {
		e.mu.Lock()
		delete(e.resolving, dip)
		flush := e.parked[dip]
		delete(e.parked, dip)
		e.mu.Unlock()
		if !ok || len(flush) == 0 {
			asyncLogf("neighbor resolve FAILED for %s (parked=%d), probes wait for timeout", p.addr, len(flush))
			return // 解析失败：探测留在 inflight/expB，按超时收尾
		}
		traceLogf("neighbor resolved for %s, flushing %d parked probes", p.addr, len(flush))
		// 单独协程冲回队列，避免阻塞后端解析池
		go func(list []*asyncProbe) {
			for _, q := range list {
				if e.isDone(q) {
					continue
				}
				select {
				case e.sendQ <- q:
				case <-time.After(200 * time.Millisecond):
					return // 队列持续拥塞：放弃本次重排，靠超时兜底
				}
			}
		}(flush)
	})
}

// retryDelayMs 重传延迟：clamp(超时/2, 500ms, 1000ms)。
func (e *asyncEngine) retryDelayMs() int64 {
	d := e.timeoutMs / 2
	if d < asyncRetryMinMs {
		d = asyncRetryMinMs
	}
	if d > asyncRetryMaxMs {
		d = asyncRetryMaxMs
	}
	return d
}

// sendLoop 固定数量发送协程：取探测 → 邻居预检 → 路由选源 → 构造 → 限速 → 发送。
func (e *asyncEngine) sendLoop() {
	for p := range e.sendQ {
		if e.isDone(p) {
			continue
		}
		// 邻居预检（无令牌消耗）：未知 → park；负缓存 → 挂到超时
		switch gerr := e.backend.neighborGate(p.dst); gerr {
		case errNeedARP:
			e.park(p)
			continue
		case errNoRoute:
			asyncLogf("gate: %s neighbor dead/no route", p.addr)
			e.startClock(p)
			continue
		default:
			if gerr != nil {
				asyncLogf("gate: %s error: %v", p.addr, gerr)
			}
		}
		src, err := e.backend.sourceIP(p.dst)
		if err != nil {
			asyncLogf("route lookup for %s failed: %v (treated as closed)", p.addr, err)
			e.startClock(p)
			continue
		}
		pkt := craftTCP4(src, p.dst, p.srcPort, p.dstPort, thSYN, 0, 0, 65535)

		e.takeToken() // 限速：令牌在真正交给后端前获取
		if err := e.backend.send(pkt, p.dst); err != nil {
			if err == errNeedARP {
				e.park(p)
				continue
			}
			if err == errNoRoute {
				e.startClock(p)
				continue
			}
			// 其它发送错误（设备异常等）：不计尝试、不重排，等超时收尾
			asyncLogf("send to %s failed: %v", p.addr, err)
			e.startClock(p)
			continue
		}
		// attempts 在 mu 内更新（同一探测理论上可能被重排进队列两次，
		// 避免无锁写与 retryLoop 读产生数据竞争）
		e.mu.Lock()
		p.attempts++
		n := p.attempts
		e.mu.Unlock()
		if n == 1 {
			e.startClock(p) // 首次真正发出：超时时钟从这里开始
			e.mu.Lock()
			slot := slotOf(time.Now().UnixMilli() + e.retryDelayMs())
			e.retB[slot] = append(e.retB[slot], p)
			e.mu.Unlock()
		}
		if tot := atomic.AddInt64(&synSendOk, 1); tot <= 8 || tot%500 == 0 {
			traceLogf("sent %s sport=%d (total=%d)", p.addr, p.srcPort, tot)
		}
	}
}

// dispatchLoop 收包判定：SYN-ACK → 开放(+补发 RST 清理半开)，RST → 关闭。
func (e *asyncEngine) dispatchLoop() {
	for d := range e.respCh {
		srcIP, ourIP, targetPort, ourPort, flags, synAck, ok := parseTCPResp(d.ip)
		if !ok {
			continue
		}
		key := probeKey{ip: be32(srcIP[:]), port: targetPort}
		e.mu.Lock()
		p := e.inflight[key]
		if p == nil || p.done || p.srcPort != ourPort {
			e.mu.Unlock()
			if synDebug {
				asyncLogf("resp unmatched: %v:%d flags=%02x ourPort=%d", srcIP, targetPort, flags, ourPort)
			}
			continue
		}
		e.mu.Unlock()

		switch {
		case flags&thSYN != 0 && flags&thACK != 0:
			e.sendRSTBestEffort(ourIP, srcIP, p.srcPort, targetPort, synAck)
			e.resolve(p, true)
		case flags&thRST != 0:
			e.resolve(p, false)
		}
	}
}

// sendRSTBestEffort 发 RST 关闭目标上的半开连接。seq 取 SYN-ACK 的 ack
// （= 戲方 ISN+1 = 对方 rcv_nxt，RFC793 可接受序列），发送失败仅忽略
// （目标会自行按半开超时清理）。
func (e *asyncEngine) sendRSTBestEffort(ourIP, dstIP [4]byte, ourPort, dstPort uint16, seq uint32) {
	pkt := craftTCP4(ourIP, dstIP, ourPort, dstPort, thRST, seq, 0, 0)
	_ = e.backend.send(pkt, dstIP) // 邻居必然已解析（刚收到其回包）
}

// expiryLoop 100ms 扫一次超时桶，把到期探测判为无响应（关闭）。
func (e *asyncEngine) expiryLoop() {
	t := time.NewTicker(asyncTickMs * time.Millisecond)
	defer t.Stop()
	for range t.C {
		nowSlot := slotOf(time.Now().UnixMilli())
		var due []*asyncProbe
		e.mu.Lock()
		for s, ps := range e.expB {
			if s <= nowSlot {
				due = append(due, ps...)
				delete(e.expB, s)
			}
		}
		e.mu.Unlock()
		for _, p := range due {
			e.resolve(p, false) // resolve 内部幂等，已判定的直接跳过
		}
	}
}

// retryLoop 100ms 扫一次重传桶，把到期探测（未判定期、尝试未用尽）重发。
func (e *asyncEngine) retryLoop() {
	t := time.NewTicker(asyncTickMs * time.Millisecond)
	defer t.Stop()
	for range t.C {
		nowSlot := slotOf(time.Now().UnixMilli())
		var due []*asyncProbe
		e.mu.Lock()
		for s, ps := range e.retB {
			if s <= nowSlot {
				due = append(due, ps...)
				delete(e.retB, s)
			}
		}
		e.mu.Unlock()
		for _, p := range due {
			e.mu.Lock()
			skip := p.done || p.attempts >= asyncMaxAttempts
			e.mu.Unlock()
			if skip {
				continue
			}
			e.sendQ <- p // sendQ 满时阻塞本协程（expiryLoop 独立，超时判定不受影响）
		}
	}
}

// ---------------- 报文构造与解析 ----------------

// craftTCP4 构造一个 40 字节的 IPv4+TCP 包（无负载）。
// tcpCsum 大端写入 [16:18]；IP 头校验和由本函数补全（Windows 上没有内核代填）。
func craftTCP4(srcIP, dstIP [4]byte, srcPort, dstPort uint16, flags byte, seq, ack uint32, window uint16) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 0x50 // data offset = 5 (20B)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], window)
	c := tcpChecksum4(srcIP, dstIP, tcp)
	tcp[16] = byte(c >> 8)
	tcp[17] = byte(c)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40) // total length
	ip[8] = 64                              // TTL
	ip[9] = protoTCP
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	ic := ipChecksum4(ip)
	ip[10] = byte(ic >> 8)
	ip[11] = byte(ic)

	return append(ip, tcp...)
}

// tcpChecksum4 TCP 校验和（含 12 字节伪头部，协议号用字面量 6 保持平台无关）。
func tcpChecksum4(srcIP, dstIP [4]byte, tcp []byte) uint16 {
	tcpLen := uint16(len(tcp))
	pseudo := make([]byte, 12+tcpLen)
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[9] = protoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], tcpLen)
	copy(pseudo[12:], tcp)
	pseudo[12+16] = 0
	pseudo[12+17] = 0

	var sum uint32
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(pseudo[i])<<8 + uint32(pseudo[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// ipChecksum4 IPv4 头校验和（调用时头内 [10:12] 应为 0）。
func ipChecksum4(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(hdr[i])<<8 + uint32(hdr[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// parseTCPResp 解析完整 IPv4 包中的 TCP 响应，返回：
// srcIP(目标)、ourIP(本机, 取自包的目的地址)、targetPort(响应源端口)、
// ourPort(响应目的端口=我们发出的源端口)、flags、SYN-ACK 的 ack 号。
// 非 IPv4/非 TCP/分片非首片/过短一律 ok=false。
func parseTCPResp(pkt []byte) (srcIP, ourIP [4]byte, targetPort, ourPort uint16, flags byte, synAck uint32, ok bool) {
	if len(pkt) < 40 || pkt[0]>>4 != 4 || pkt[9] != protoTCP {
		return
	}
	if binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return // 非首片分片，不含 TCP 头
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return
	}
	copy(srcIP[:], pkt[12:16])
	copy(ourIP[:], pkt[16:20])
	tcp := pkt[ihl:]
	targetPort = binary.BigEndian.Uint16(tcp[0:2])
	ourPort = binary.BigEndian.Uint16(tcp[2:4])
	synAck = binary.BigEndian.Uint32(tcp[8:12])
	flags = tcp[13]
	ok = true
	return
}

// ---------------- 端口扫描入口（供 portscan.go 分流调用） ----------------

// localAddrSet 本机已配置的 IPv4 地址集合（含回环判断辅助）。
func localAddrSet() map[[4]byte]struct{} {
	set := make(map[[4]byte]struct{})
	if ifs, err := net.Interfaces(); err == nil {
		for _, in := range ifs {
			addrs, err2 := in.Addrs()
			if err2 != nil {
				continue
			}
			for _, a := range addrs {
				if ip4 := addrIPv4(a); ip4 != nil {
					var k [4]byte
					copy(k[:], ip4)
					set[k] = struct{}{}
				}
			}
		}
	}
	return set
}

// addrIPv4 从 net.Addr（*net.IPNet / *net.IPAddr）取出 IPv4，其它类型返回 nil。
func addrIPv4(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP.To4()
	case *net.IPAddr:
		return v.IP.To4()
	}
	return nil
}

// portScanAsync 异步引擎版 PortScan：与旧实现保持完全相同的契约——
// 串行回调 onFound（含 happens-before），返回按到达顺序的存活地址。
// 本地/回环/解析失败目标走既有 PortConnect 路径。
func portScanAsync(hostslist []string, probePorts []int, timeout int64, onFound func(address string)) []string {
	e := engine
	AliveAddress := make([]string, 0, len(hostslist)*20)
	results := make(chan string, common.Threads)
	var wg sync.WaitGroup

	// 与旧 PortScan 相同的收集器：append → onFound → wg.Done（配对 PortConnect
	// / resolve 侧的 wg.Add），wg.Wait 返回时所有 onFound 必然已完成。
	go func() {
		for found := range results {
			AliveAddress = append(AliveAddress, found)
			if onFound != nil {
				onFound(found)
			}
			wg.Done()
		}
	}()

	e.start(results, &wg, timeout*1000)

	localAddrs := localAddrSet()
	localSem := make(chan struct{}, common.Threads)

	for _, port := range probePorts {
		for _, host := range hostslist {
			ip := net.ParseIP(host)
			ip4 := ip.To4()
			if ip4 == nil || isLocalTarget(ip4, localAddrs) {
				// 回环/本机地址/域名解析失败：pcap 抓不到回包，回落既有 connect
				a := Addr{ip: host, port: port}
				wg.Add(1)
				go func() {
					localSem <- struct{}{}
					PortConnect(a, results, timeout, &wg)
					wg.Done()
					<-localSem
				}()
				continue
			}
			var dst [4]byte
			copy(dst[:], ip4)
			p := &asyncProbe{
				key:     probeKey{ip: be32(ip4), port: uint16(port)},
				dst:     dst,
				dstPort: uint16(port),
				srcPort: srcPortFor(port),
				addr:    ip4.String() + ":" + strconv.Itoa(port),
			}
			e.slots <- struct{}{} // 在途上限背压
			wg.Add(1)
			e.register(p)
			e.sendQ <- p // 发送队列背压（仅队列排队，不计超时）
		}
	}

	wg.Wait()
	close(results)
	return AliveAddress
}

// isLocalTarget 判断目标是否为本机/回环（这些路径 pcap 方案拿不到回包）。
func isLocalTarget(ip net.IP, local map[[4]byte]struct{}) bool {
	if ip[0] == 127 {
		return true
	}
	var k [4]byte
	copy(k[:], ip)
	_, ok := local[k]
	return ok
}
