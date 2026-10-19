//go:build windows && (amd64 || arm64)

package Plugins

// synasync_windows.go — 异步 SYN 引擎的 Windows Npcap 后端。
//
// 关键实现决策（2026-10-19 实测结论驱动）：
//   - 纯 Go P/Invoke（syscall.LazyDLL + SyscallN），不引入 cgo，保持
//     build.py 的 CGO_ENABLED=0 与六平台交叉编译不变。
//   - wpcap.dll 加载：候选路径 System32\Npcap → System32 → 裸名，绝对路径
//     用 LOAD_WITH_ALTERED_SEARCH_PATH(0x8)。实测本机（未开 WinPcap 兼容
//     模式、PATH 未含 Npcap 目录）裸 LoadLibrary 与默认全路径加载均报
//     win32=126，只有 0x8 标志能解析同目录的 packet.dll。
//   - 可用性探测 = pcap_open_live：非管理员 / Npcap 未装时此处失败，
//     返回具体 errbuf 供 scanner.go 打印，随后整链路回退 TCP connect。
//   - 二层：源IP(UDP路由查询缓存) → 设备句柄(pcap dev 地址匹配, 惰性打开) →
//     下一跳(GetBestRoute, 缓存) → 邻居 MAC(SendARP, 正/负缓存带 TTL) →
//     源 MAC(net.Interfaces 按源IP匹配)。邻居缺失不阻塞发送协程：核心
//     park + resolveARP 异步解析后整批冲回。
//   - 收包：每句柄一个 recvLoop；pcap_pkthdr 的 caplen 偏移(8/16)用
//     IP total-length ≤ caplen-l2（以太网帧有 <60B 填充，必须允许大于）
//     自校验探测，只按 8→16 顺序尝试，两侧都不会越界读。
//   - 仅 TCP、IPv4、首片过滤在收包侧完成，减少核心压力。
//   - DLT_RAW(101) 网卡无链路层：直接发裸 IP 包、跳过 ARP；DLT_LOOPBACK
//     路径在核心侧已由本地目标 connect 回退覆盖。

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	loadWithAlteredSearchPath = 0x8

	// 邻居缓存 TTL（毫秒）：正缓存 5 分钟，负缓存 5 秒
	asyncMacTTLMs    = 300000
	asyncMacNegTTLMs = 5000

	pcapErrbufSize = 256
	dltRAW         = 101
)

// ---------------- 基础 P/Invoke 工具 ----------------

var (
	procKernel32LoadLibEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryExW")

	iphlpapiDLL       = syscall.NewLazyDLL("iphlpapi.dll")
	procGetBestRoute  = iphlpapiDLL.NewProc("GetBestRoute")
	procSendARP       = iphlpapiDLL.NewProc("SendARP")
	procGetIpNetTable = iphlpapiDLL.NewProc("GetIpNetTable")
)

// loadLibraryEx 加载 DLL。flags=0x8(LOAD_WITH_ALTERED_SEARCH_PATH) 要求绝对
// 路径（依赖从 DLL 所在目录取）；裸名传 0 走默认搜索（含 PATH）。
func loadLibraryEx(path string, flags uint32) (syscall.Handle, error) {
	if err := procKernel32LoadLibEx.Find(); err != nil {
		return 0, fmt.Errorf("LoadLibraryExW: %v", err)
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	r1, _, callErr := procKernel32LoadLibEx.Call(uintptr(unsafe.Pointer(p)), 0, uintptr(flags))
	if r1 == 0 {
		if callErr != syscall.Errno(0) {
			return 0, fmt.Errorf("LoadLibraryEx(%s): %v", path, callErr)
		}
		return 0, fmt.Errorf("LoadLibraryEx(%s): unknown error", path)
	}
	return syscall.Handle(r1), nil
}

// ptrFromUintptr uintptr → unsafe.Pointer 的 vet 友好转换（FFI 场景：指向
// C 运行时分配的稳定内存，非 Go 堆对象，转换安全；直接写 unsafe.Pointer(u)
// 会被 go vet unsafeptr 启发式误报，项目约定 vet 必须干净）。
func ptrFromUintptr(u uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&u))
}

// cstr 把 C 字符串指针转为 Go 字符串（上限 4096 字节防呆）。
func cstr(p uintptr) string {
	if p == 0 {
		return ""
	}
	var out []byte
	for i := 0; i < 4096; i++ {
		c := *(*byte)(ptrFromUintptr(p + uintptr(i)))
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(out)
}

// ---------------- wpcap 模块 ----------------

type wpcapModule struct {
	h           syscall.Handle
	findalldevs uintptr
	freealldevs uintptr
	openlive    uintptr
	closepcap   uintptr
	datalink    uintptr
	sendpacket  uintptr
	nextex      uintptr
	geterr      uintptr
}

func loadWpcapModule() (*wpcapModule, error) {
	windir := os.Getenv("WINDIR")
	if windir == "" {
		windir = `C:\Windows`
	}
	cands := []struct {
		path  string
		flags uint32
	}{
		{windir + `\System32\Npcap\wpcap.dll`, loadWithAlteredSearchPath},
		{windir + `\System32\wpcap.dll`, loadWithAlteredSearchPath},
		{`wpcap.dll`, 0}, // PATH / WinPcap 兼容模式安装兜底
	}
	var h syscall.Handle
	var lastErr error
	for _, c := range cands {
		hh, err := loadLibraryEx(c.path, c.flags)
		if err == nil {
			h = hh
			break
		}
		lastErr = err
	}
	if h == 0 {
		return nil, fmt.Errorf("wpcap.dll 加载失败（未安装 Npcap？）: %v", lastErr)
	}
	m := &wpcapModule{h: h}
	exports := []struct {
		name string
		dst  *uintptr
	}{
		{"pcap_findalldevs", &m.findalldevs},
		{"pcap_freealldevs", &m.freealldevs},
		{"pcap_open_live", &m.openlive},
		{"pcap_close", &m.closepcap},
		{"pcap_datalink", &m.datalink},
		{"pcap_sendpacket", &m.sendpacket},
		{"pcap_next_ex", &m.nextex},
		{"pcap_geterr", &m.geterr},
	}
	for _, e := range exports {
		p, err := syscall.GetProcAddress(m.h, e.name)
		if err != nil {
			return nil, fmt.Errorf("pcap 导出缺失 %s: %v", e.name, err)
		}
		*e.dst = p
	}
	return m, nil
}

// callC 调用 cdecl 函数。windows/amd64 与 arm64 上 SyscallN 调用约定统一；
// 386 因 stdcall/cdecl 差异被排除在本文件构建标签之外。
func callC(fn uintptr, args ...uintptr) (uintptr, uintptr) {
	r1, r2, _ := syscall.SyscallN(fn, args...)
	return r1, r2
}

// ---------------- pcap_if / pcap_addr 布局（与 npcap SDK 一致，x64） ----------------

// struct pcap_if { pcap_if *next; char *name; char *description;
//
//	pcap_addr *addresses; bpf_u_int32 flags; }  ← flags 在最后
type rawPcapIf struct {
	Next        uintptr
	Name        uintptr
	Description uintptr
	Addresses   uintptr
	Flags       uint32
}

// struct pcap_addr { pcap_addr *next; sockaddr *addr; *netmask; *broadaddr; *dstaddr; }
type rawPcapAddr struct {
	Next    uintptr
	Addr    uintptr
	Netmask uintptr
	Broad   uintptr
	Dst     uintptr
}

type devAddr struct {
	ip   [4]byte
	mask [4]byte
}

type pcapDev struct {
	name  string
	addrs []devAddr
}

// ---------------- 设备句柄 ----------------

type pcapHandle struct {
	dev string
	p   uintptr
	dl  int
	mu  sync.Mutex // pcap_sendpacket 发送互斥（recv 由独占 recvLoop 处理）

	// 仅 recvLoop goroutine 读写
	calibrated bool
	capOff     int
	calibTries int
}

// ---------------- Npcap 后端 ----------------

type npcapBackend struct {
	lib *wpcapModule
	out chan<- synDatagram

	arpSem chan struct{}

	mu       sync.Mutex
	devs     []pcapDev
	handles  map[string]*pcapHandle
	srcCache map[uint32][4]byte    // dstIP -> 源IP（UDP 路由查询缓存）
	routeC   map[uint32][4]byte    // dstIP -> 下一跳
	neigh    map[uint32]neighEntry // 下一跳IP -> MAC（正/负缓存）
	macCache map[uint32][6]byte    // 源IP -> 本机MAC
	osArp    map[uint32][6]byte    // 系统 ARP 表快照（GetIpNetTable）
	osArpAt  int64                 // 快照时间（unix ms）
}

type neighEntry struct {
	mac    [6]byte
	alive  bool
	expire int64 // unix ms
}

func nowMs() int64 { return time.Now().UnixMilli() }

// newSynBackend：加载 wpcap → 枚举设备 → 打开探测句柄（=管理员/驱动可用性
// 探测）→ 该句柄的收包循环随之启动。任何一步失败都返回带原因的 error，
// scanner.go 打印后整链路回退 TCP connect。
func newSynBackend(out chan<- synDatagram) (synBackend, error) {
	if err := procGetBestRoute.Find(); err != nil {
		return nil, fmt.Errorf("GetBestRoute: %v", err)
	}
	if err := procSendARP.Find(); err != nil {
		return nil, fmt.Errorf("SendARP: %v", err)
	}
	if err := procGetIpNetTable.Find(); err != nil {
		return nil, fmt.Errorf("GetIpNetTable: %v", err)
	}
	lib, err := loadWpcapModule()
	if err != nil {
		return nil, err
	}
	devs, err := lib.listDevs()
	if err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return nil, fmt.Errorf("Npcap 未发现可用网卡")
	}
	probeDev := pickProbeDev(devs)

	b := &npcapBackend{
		lib:      lib,
		out:      out,
		arpSem:   make(chan struct{}, asyncArpWorkers),
		devs:     devs,
		handles:  make(map[string]*pcapHandle),
		srcCache: make(map[uint32][4]byte),
		routeC:   make(map[uint32][4]byte),
		neigh:    make(map[uint32]neighEntry),
		macCache: make(map[uint32][6]byte),
		osArp:    make(map[uint32][6]byte),
	}
	h, err := b.openHandle(probeDev.name)
	if err != nil {
		return nil, err // 非管理员时 Npcap 驱动拒绝打开，errbuf 说明原因
	}
	traceLogf("npcap ready: %d devices, probe=%s dl=%d", len(devs), probeDev.name, h.dl)
	return b, nil
}

// pickProbeDev 选非回环且带 IPv4 的设备做可用性探测（找不到就用第一个）。
func pickProbeDev(devs []pcapDev) pcapDev {
	for _, d := range devs {
		if !strings.Contains(strings.ToLower(d.name), "loopback") && len(d.addrs) > 0 {
			return d
		}
	}
	return devs[0]
}

// listDevs 枚举设备与其 IPv4 地址/掩码。
func (m *wpcapModule) listDevs() ([]pcapDev, error) {
	var devsPtr uintptr
	errbuf := make([]byte, pcapErrbufSize)
	r1, _ := callC(m.findalldevs, uintptr(unsafe.Pointer(&devsPtr)), uintptr(unsafe.Pointer(&errbuf[0])))
	if r1 != 0 || devsPtr == 0 {
		return nil, fmt.Errorf("pcap_findalldevs 失败: %s", cstr(uintptr(unsafe.Pointer(&errbuf[0]))))
	}
	defer callC(m.freealldevs, devsPtr)

	var out []pcapDev
	for p := devsPtr; p != 0; {
		pi := (*rawPcapIf)(ptrFromUintptr(p))
		d := pcapDev{name: cstr(pi.Name)}
		for ap := pi.Addresses; ap != 0; {
			pa := (*rawPcapAddr)(ptrFromUintptr(ap))
			if pa.Addr != 0 {
				fam := *(*uint16)(ptrFromUintptr(pa.Addr))
				if fam == 2 { // AF_INET
					var a devAddr
					copy(a.ip[:], unsafe.Slice((*byte)(ptrFromUintptr(pa.Addr)), 16)[4:8])
					if pa.Netmask != 0 {
						copy(a.mask[:], unsafe.Slice((*byte)(ptrFromUintptr(pa.Netmask)), 16)[4:8])
					}
					d.addrs = append(d.addrs, a)
				}
			}
			ap = pa.Next
		}
		out = append(out, d)
		p = pi.Next
	}
	return out, nil
}

// openHandle 打开（或复用）一个设备句柄，并启动其收包循环。
func (b *npcapBackend) openHandle(dev string) (*pcapHandle, error) {
	b.mu.Lock()
	if h, ok := b.handles[dev]; ok {
		b.mu.Unlock()
		return h, nil
	}
	b.mu.Unlock()

	nameZ := append([]byte(dev), 0)
	errbuf := make([]byte, pcapErrbufSize)
	r1, _ := callC(b.lib.openlive,
		uintptr(unsafe.Pointer(&nameZ[0])),
		65535, // snaplen
		0,     // promisc=0：半开扫描只收本机流量，旁路会引入不必要的生产环境噪音
		100,   // to_ms
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("打开 Npcap 网卡 %q 失败（需管理员权限）: %s",
			dev, cstr(uintptr(unsafe.Pointer(&errbuf[0]))))
	}
	dl, _ := callC(b.lib.datalink, r1)
	h := &pcapHandle{dev: dev, p: r1, dl: int(int32(dl)), capOff: -1}

	b.mu.Lock()
	if exist, ok := b.handles[dev]; ok { // 并发打开同句柄的兜底
		b.mu.Unlock()
		callC(b.lib.closepcap, r1)
		return exist, nil
	}
	b.handles[dev] = h
	b.mu.Unlock()

	go b.recvLoop(h)
	return h, nil
}

// ---------------- 路由 / 邻居 / 源地址 ----------------

// sourceIP 用不发数据的 UDP 路由查询确定访问 dst 的源地址（与 Linux 版
// localIPv4 同款思路），按目标缓存。
func (b *npcapBackend) sourceIP(dst [4]byte) ([4]byte, error) {
	key := be32(dst[:])
	b.mu.Lock()
	if s, ok := b.srcCache[key]; ok {
		b.mu.Unlock()
		return s, nil
	}
	b.mu.Unlock()

	var out [4]byte
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(dst[:]), Port: 9})
	if err != nil {
		return out, err
	}
	defer conn.Close()
	u, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return out, fmt.Errorf("local addr type: %T", conn.LocalAddr())
	}
	v4 := u.IP.To4()
	if v4 == nil {
		return out, fmt.Errorf("no ipv4 source for %v", dst)
	}
	copy(out[:], v4)
	b.mu.Lock()
	b.srcCache[key] = out
	b.mu.Unlock()
	return out, nil
}

// routeFor 查下一跳（on-link 时即目标本身），按目标缓存。
func (b *npcapBackend) routeFor(dst, src [4]byte) ([4]byte, error) {
	key := be32(dst[:])
	b.mu.Lock()
	if nh, ok := b.routeC[key]; ok {
		b.mu.Unlock()
		return nh, nil
	}
	b.mu.Unlock()

	// MIB_IPFORWARDROW 实测布局（2026-10-19 本机 GetBestRoute 逐字节 dump 验证）：
	//   dwForwardDest@0, dwForwardMask@4, dwForwardPolicy@8, dwForwardNextHop@12,
	//   dwForwardIndex@16, dwForwardType@20, dwForwardProto@24, dwForwardAge@28 ...
	// 注意 NextHop 不在 offset 4（那是 Mask！初版读错导致 ARP 目标=255.255.255.0）。
	// 字段为 inet_addr 网络序字节，内存字节即 IP 字节序，直接拷贝。
	var row [128]byte
	r1, _ := callC(procGetBestRoute.Addr(),
		uintptr(binary.LittleEndian.Uint32(dst[:])),
		uintptr(binary.LittleEndian.Uint32(src[:])),
		uintptr(unsafe.Pointer(&row[0])),
	)
	if uint32(r1) != 0 {
		return [4]byte{}, fmt.Errorf("GetBestRoute(%v): %d", dst, uint32(r1))
	}
	var nh [4]byte
	copy(nh[:], row[12:16])
	if nh == [4]byte{} {
		nh = dst // on-link 目标：下一跳为 0.0.0.0，二层直达目标本身
	}
	b.mu.Lock()
	b.routeC[key] = nh
	b.mu.Unlock()
	return nh, nil
}

// sendARPFor 执行一次 SendARP（可能阻塞至 ARP 超时，仅在解析协程池内调用）。
func sendARPFor(src, dst [4]byte) ([6]byte, error) {
	var mac [8]byte
	length := uint32(len(mac))
	r1, _ := callC(procSendARP.Addr(),
		uintptr(binary.LittleEndian.Uint32(src[:])),
		uintptr(binary.LittleEndian.Uint32(dst[:])),
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&length)),
	)
	if uint32(r1) != 0 {
		return [6]byte{}, fmt.Errorf("SendARP(%v): %d", dst, uint32(r1))
	}
	if length < 6 {
		return [6]byte{}, fmt.Errorf("SendARP(%v): mac len %d", dst, length)
	}
	var out [6]byte
	copy(out[:], mac[:6])
	return out, nil
}

// neighborGate 二层就绪预检（缓存快路径，不消耗发包令牌）。
// 顺带保证目标源地址对应的设备句柄已打开（拿到 dl 判定是否需要 ARP）。
func (b *npcapBackend) neighborGate(dst [4]byte) error {
	src, err := b.sourceIP(dst)
	if err != nil {
		return errNoRoute
	}
	h, err := b.openHandle(b.devForSrc(src))
	if err != nil {
		return err // 记日志并按超时收尾（多半是权限/设备异常）
	}
	if h.dl == dltRAW {
		return nil // 点对点/裸 IP 网卡：无链路层、无 ARP
	}
	nh, err := b.routeFor(dst, src)
	if err != nil {
		return errNoRoute
	}
	return b.neighState(nh)
}

// fetchOsArpTable 读取系统 ARP 表（arp.exe 同源）。MIB_IPNETROW 布局：
// dwIndex@0, dwPhysAddrLen@4, bPhysAddr[8]@8, dwAddr@16, dwType@20，行宽 24；
// 表头为 DWORD 条目数。dwType=3(invalid) 跳过。
// 实测背景（2026-10-19 本机）：SendARP 全线返回 1168（ERROR_ELEMENT_NOT_FOUND，
// 与当前沙箱环境有关），而系统 ARP 表读取正常——读表兜底可覆盖绝大多数目标。
func fetchOsArpTable() map[uint32][6]byte {
	out := make(map[uint32][6]byte, 64)
	var size uint32
	callC(procGetIpNetTable.Addr(), 0, uintptr(unsafe.Pointer(&size)), 0)
	if size < 4 {
		return out
	}
	size += 8192 // 表在两次调用间可能增长，留余量
	buf := make([]byte, size)
	r1, _ := callC(procGetIpNetTable.Addr(), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if uint32(r1) != 0 {
		return out
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	if n > 65536 {
		return out // 防呆：条目数异常则放弃本次快照
	}
	if synDebug {
		asyncLogf("os arp table: %d entries, size=%d", n, size)
	}
	for i := uint32(0); i < n; i++ {
		o := 4 + i*24
		if int(o)+24 > len(buf) {
			break
		}
		// 不按 dwType 过滤：实测（2026-10-19 本机 dump）在线动态条目 dwType=3，
		// 与文档"3=INVALID"语义不符；dwPhysAddrLen<6 已足以排除组播/无效占位行。
		if binary.LittleEndian.Uint32(buf[o+4:o+8]) < 6 {
			continue
		}
		var mac [6]byte
		copy(mac[:], buf[o+8:o+14])
		out[be32(buf[o+16:o+20])] = mac
	}
	return out
}

// osArpLookup 查系统 ARP 快照中 nh 的 MAC（快照缓存 3 秒）。
func (b *npcapBackend) osArpLookup(nh [4]byte) ([6]byte, bool) {
	key := be32(nh[:])
	b.mu.Lock()
	if nowMs()-b.osArpAt < 3000 {
		tab := b.osArp
		b.mu.Unlock()
		m, ok := tab[key]
		return m, ok
	}
	b.mu.Unlock()
	tab := fetchOsArpTable() // 锁外执行（毫秒级）
	b.mu.Lock()
	b.osArp = tab
	b.osArpAt = nowMs()
	b.mu.Unlock()
	m, ok := tab[key]
	return m, ok
}

// neighState 邻居解析状态：正缓存 → nil；负缓存有效 → errNoRoute；
// 未命中 → 先查系统 ARP 表快照兜底，仍无 → errNeedARP（触发异步解析）。
func (b *npcapBackend) neighState(nh [4]byte) error {
	nhKey := be32(nh[:])
	now := nowMs()
	b.mu.Lock()
	ne, ok := b.neigh[nhKey]
	if ok && now > ne.expire {
		delete(b.neigh, nhKey)
		ok = false
	}
	b.mu.Unlock()
	if ok && ne.alive {
		return nil
	}
	if ok && !ne.alive {
		return errNoRoute
	}
	if mac, found := b.osArpLookup(nh); found {
		b.mu.Lock()
		b.neigh[nhKey] = neighEntry{mac: mac, alive: true, expire: nowMs() + asyncMacTTLMs}
		b.mu.Unlock()
		return nil
	}
	return errNeedARP
}

// resolveARP 异步解析下一跳 MAC 并写入正/负缓存，恰好回调一次。
func (b *npcapBackend) resolveARP(dst [4]byte, cb func(bool)) {
	go func() {
		b.arpSem <- struct{}{}
		defer func() { <-b.arpSem }()
		ok := false
		defer func() { cb(ok) }()
		src, err := b.sourceIP(dst)
		if err != nil {
			asyncLogf("resolveARP sourceIP(%v): %v", dst, err)
			return
		}
		h, err := b.openHandle(b.devForSrc(src))
		if err != nil {
			asyncLogf("resolveARP openHandle: %v", err)
			return
		}
		if h.dl == dltRAW {
			ok = true // 无需 ARP：视作就绪，parked 探测冲回后直发
			return
		}
		nh, err := b.routeFor(dst, src)
		if err != nil {
			asyncLogf("resolveARP GetBestRoute(%v): %v", dst, err)
			return
		}
		// 1) 先查系统 ARP 表快照（arp.exe 同源；本环境 SendARP 不可用而系统表正常）
		if mac, found := b.osArpLookup(nh); found {
			b.mu.Lock()
			b.neigh[be32(nh[:])] = neighEntry{mac: mac, alive: true, expire: nowMs() + asyncMacTTLMs}
			b.mu.Unlock()
			traceLogf("resolveARP %v via %v -> mac %v (os arp table)", dst, nh, mac)
			ok = true
			return
		}
		// 2) SendARP 主动解析（正常机器上顺带填充系统缓存）
		mac, err := sendARPFor(src, nh)
		if err != nil {
			asyncLogf("resolveARP SendARP(%v via %v): %v", dst, nh, err)
		} else {
			traceLogf("resolveARP %v via %v -> mac %v (SendARP)", dst, nh, mac)
		}
		nhKey := be32(nh[:])
		b.mu.Lock()
		if err == nil {
			b.neigh[nhKey] = neighEntry{mac: mac, alive: true, expire: nowMs() + asyncMacTTLMs}
		} else {
			b.neigh[nhKey] = neighEntry{alive: false, expire: nowMs() + asyncMacNegTTLMs}
		}
		b.mu.Unlock()
		ok = err == nil
	}()
}

// macFor 按源 IP 从 net.Interfaces 取本机网卡 MAC（含缓存）。
func (b *npcapBackend) macFor(srcIP [4]byte) ([6]byte, error) {
	key := be32(srcIP[:])
	b.mu.Lock()
	if m, ok := b.macCache[key]; ok {
		b.mu.Unlock()
		return m, nil
	}
	b.mu.Unlock()

	ifs, err := net.Interfaces()
	if err != nil {
		return [6]byte{}, err
	}
	want := net.IP(srcIP[:])
	for _, in := range ifs {
		addrs, err2 := in.Addrs()
		if err2 != nil {
			continue
		}
		for _, a := range addrs {
			if ip4 := addrIPv4(a); ip4 != nil && ip4.Equal(want) {
				if len(in.HardwareAddr) == 6 {
					var mac [6]byte
					copy(mac[:], in.HardwareAddr)
					b.mu.Lock()
					b.macCache[key] = mac
					b.mu.Unlock()
					return mac, nil
				}
				return [6]byte{}, fmt.Errorf("接口 %s 无以太网 MAC", in.Name)
			}
		}
	}
	return [6]byte{}, fmt.Errorf("本机无接口持有源地址 %v", srcIP)
}

// devForSrc 按源 IP 匹配 pcap 设备（设备地址含该源），兜底第一个设备。
func (b *npcapBackend) devForSrc(srcIP [4]byte) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, d := range b.devs {
		for _, a := range d.addrs {
			if a.ip == srcIP {
				return d.name
			}
		}
	}
	return b.devs[0].name
}

// ---------------- 收发 ----------------

// send 封装链路层（目的 MAC=下一跳、源 MAC=本机网卡）交给 pcap 发送；
// DLT_RAW 网卡直接发裸 IP。邻居缺失/死亡返回可恢复哨兵错误。
func (b *npcapBackend) send(pkt []byte, dst [4]byte) error {
	if len(pkt) < 40 {
		return fmt.Errorf("short packet %d", len(pkt))
	}
	src, err := b.sourceIP(dst)
	if err != nil {
		return errNoRoute
	}
	h, err := b.openHandle(b.devForSrc(src))
	if err != nil {
		return err
	}

	var frame []byte
	if h.dl == dltRAW {
		frame = pkt
	} else {
		nh, err := b.routeFor(dst, src)
		if err != nil {
			return errNoRoute
		}
		nhKey := be32(nh[:])
		now := nowMs()
		b.mu.Lock()
		ne, ok := b.neigh[nhKey]
		if ok && now > ne.expire {
			delete(b.neigh, nhKey)
			ok = false
		}
		b.mu.Unlock()
		if !ok {
			return errNeedARP
		}
		if !ne.alive {
			return errNoRoute
		}
		srcMac, err := b.macFor(src)
		if err != nil {
			return err
		}
		frame = make([]byte, 14+len(pkt))
		copy(frame[0:6], ne.mac[:])
		copy(frame[6:12], srcMac[:])
		frame[12] = 0x08
		frame[13] = 0x00
		copy(frame[14:], pkt)
	}

	h.mu.Lock()
	r1, _ := callC(b.lib.sendpacket, h.p, uintptr(unsafe.Pointer(&frame[0])), uintptr(len(frame)))
	h.mu.Unlock()
	if int32(r1) != 0 {
		return fmt.Errorf("pcap_sendpacket(%s): %d", h.dev, int32(r1))
	}
	return nil
}

// l2len 链路层头长：DLT_EN10MB(1) 按 EtherType（含单层 VLAN），
// DLT_RAW(101)=0，DLT_LINUX_SLL(113)=16；非 IP 返回 -1。
func (h *pcapHandle) l2len(data []byte) int {
	switch h.dl {
	case dltRAW:
		return 0
	case 113:
		if len(data) >= 16 {
			return 16
		}
		return -1
	default: // DLT_EN10MB 及未知链路类型按以太网处理
		if len(data) < 14 {
			return -1
		}
		switch binary.BigEndian.Uint16(data[12:14]) {
		case 0x0800:
			return 14
		case 0x8100:
			if len(data) >= 18 {
				return 18
			}
			return -1
		default:
			return -1
		}
	}
}

// recvLoop 单句柄收包：自校验 caplen 偏移 → 过滤 IPv4/TCP → 拷贝推入核心。
func (b *npcapBackend) recvLoop(h *pcapHandle) {
	var hdrPtr, dataPtr uintptr
	for {
		r1, _ := callC(b.lib.nextex, h.p, uintptr(unsafe.Pointer(&hdrPtr)), uintptr(unsafe.Pointer(&dataPtr)))
		switch int32(r1) {
		case 1:
			if hdrPtr == 0 || dataPtr == 0 {
				continue
			}
			b.handlePacket(h, hdrPtr, dataPtr)
		case 0:
			continue // 超时无包
		case -2:
			return // EOF
		default:
			msg := "unknown"
			if rp, _ := callC(b.lib.geterr, h.p); rp != 0 {
				msg = cstr(rp)
			}
			asyncLogf("pcap_next_ex(%s): %s", h.dev, msg)
			time.Sleep(100 * time.Millisecond) // 防错误路径空转
		}
	}
}

// readCaplen 按已校准偏移读 pcap_pkthdr.caplen（x86/x64 小端）。
func readCaplen(hdr uintptr, off int) int {
	if off == 8 {
		return int(binary.LittleEndian.Uint32(unsafe.Slice((*byte)(ptrFromUintptr(hdr)), 16)[8:12]))
	}
	full := unsafe.Slice((*byte)(ptrFromUintptr(hdr)), 24)
	return int(binary.LittleEndian.Uint32(full[16:20]))
}

// handlePacket 解析一个到达的 pcap 包并（仅 IPv4 TCP）推给核心。
func (b *npcapBackend) handlePacket(h *pcapHandle, hdrPtr, dataPtr uintptr) {
	// 数据缓冲按 snaplen(65535) 分配，读取 ≤65535 字节不会越界。
	data0 := unsafe.Slice((*byte)(ptrFromUintptr(dataPtr)), 65535)

	if !h.calibrated {
		// caplen 偏移自校验：先试 8（WinPcap 经典 timeval=8B），再试 16
		// （time64 布局）。顺序保证安全：偏移 8 通过时绝不读 hdr[16:20]；
		// 只有偏移 8 失败（真实布局即 24B）才读，读取仍在结构体内。
		// 校验条件：IP total-length ≤ caplen-l2（以太网帧 <60B 会填充，
		// 必须用 ≤ 而不是 ==），且 total ≥40。
		for _, off := range []int{8, 16} {
			caplen := readCaplen(hdrPtr, off)
			if caplen < 40 || caplen > 65535 || caplen > len(data0) {
				continue
			}
			d := data0[:caplen]
			l2 := h.l2len(d)
			if l2 < 0 || caplen < l2+40 {
				continue
			}
			ip := d[l2:]
			if ip[0]>>4 != 4 {
				continue
			}
			total := int(binary.BigEndian.Uint16(ip[2:4]))
			if total < 40 || total > caplen-l2 {
				continue
			}
			h.capOff = off
			h.calibrated = true
			break
		}
		if !h.calibrated {
			h.calibTries++
			if h.calibTries > 500 {
				// 长期校验不了（异常链路）：退回经典 WinPcap 布局
				h.capOff = 8
				h.calibrated = true
			}
			return // 本包丢弃，从下个包按定型偏移处理
		}
		traceLogf("calibrated dev=%s capOff=%d dl=%d", h.dev, h.capOff, h.dl)
	}

	caplen := readCaplen(hdrPtr, h.capOff)
	if caplen < 40 || caplen > 65535 || caplen > len(data0) {
		return
	}
	d := data0[:caplen]
	l2 := h.l2len(d)
	if l2 < 0 || caplen < l2+40 {
		return
	}
	ip := d[l2:]
	if ip[0]>>4 != 4 || ip[9] != protoTCP { // 只放行 IPv4 TCP，减少核心压力
		return
	}
	total := int(binary.BigEndian.Uint16(ip[2:4]))
	if total < 40 || total > caplen-l2 {
		total = caplen - l2
	}
	pkt := make([]byte, total)
	copy(pkt, ip[:total])
	if n := atomic.AddInt64(&synRecvTcp, 1); n <= 8 || n%500 == 0 {
		traceLogf("recv tcp %dB dl=%d (total=%d)", total, h.dl, n)
	}
	b.out <- synDatagram{ip: pkt} // 阻塞式背压：核心积压时由驱动缓冲兜底
}
