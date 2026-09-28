package Plugins

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// TCP 标志位常量
const (
	TH_SYN = 0x02
	TH_ACK = 0x10
	TH_RST = 0x04
)

var synAvailable = false

// synErrLogAt 上次打印 SYN 错误日志的 unix 秒。每端口独立 socket 后创建
// 失败会按 端口数×主机数 量级重复发生，限流为每秒至多一条，防止刷屏。
var synErrLogAt int64

// logSynErr 限流打印 SYN 扫描的 socket 级错误（每秒至多一条，CAS 保证并发安全）。
func logSynErr(msg string) {
	now := time.Now().Unix()
	last := atomic.LoadInt64(&synErrLogAt)
	if now <= last || !atomic.CompareAndSwapInt64(&synErrLogAt, last, now) {
		return
	}
	fmt.Printf("[-] synscan: %s\n", msg)
}

// TrySYNScan 尝试创建原始套接字，测试是否有 SYN 扫描权限
func TrySYNScan() bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	synAvailable = true
	return true
}

// SYNPortSend 发送 SYN 包并判断端口状态
func SYNPortSend(host string, port int, timeout time.Duration) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	// 创建原始套接字。
	// 收发共用同一个 protocol=IPPROTO_TCP 的 socket：Linux raw(7) 规定
	// IPPROTO_RAW socket 是 send only（入向 TCP 不会投递给 protocol=255
	// 的 socket，Recvfrom 只会等到 EAGAIN）。IPPROTO_TCP socket 配合
	// IP_HDRINCL 既可发送自构造的包，入向 SYN-ACK/RST 也会投递到它。
	// 权限探测仍由 TrySYNScan 完成，拿不到权限时 synAvailable 保持 false，
	// portscan.go 依旧走 TCP connect 回退，语义不变。
	//
	// 每端口独立 socket：socket 生命周期完全收敛在本函数内（函数内创建、
	// defer 关闭），并发 goroutine 不共享 fd。Linux raw socket 按 protocol
	// 向**每个**匹配的 socket 各投递一份包副本（不是单份被抢走），所以
	// 每个端口的接收队列里都会混入其他端口（多主机时还有其他目标主机）
	// 的回包——收包必须循环过滤，见下方接收逻辑。
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		// 创建失败（如 fd 耗尽）优雅降级：记日志并按 closed 处理，不 panic；
		// defer 无需注册（没有 fd 可关）。
		logSynErr(fmt.Sprintf("socket(AF_INET,SOCK_RAW,IPPROTO_TCP) create failed for %s:%d: %v (treated as closed)", host, port, err))
		return false
	}
	defer syscall.Close(fd)

	// 允许自己构造 IP 头
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		logSynErr(fmt.Sprintf("setsockopt(IP_HDRINCL) failed for %s:%d: %v (treated as closed)", host, port, err))
		return false
	}

	srcPort := 30000 + (port*7)%10000

	// 本机真实源 IP：内核对 IP 头里为 0 的 saddr 会按路由表选源地址，
	// 但不会重算 TCP 校验和，所以必须先确定真实源地址，同时用于
	// IP 头和 TCP 伪头部，保证两者与线上包一致。
	srcIP := localIPv4(ip4)

	// 构造 TCP SYN 包
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(port))
	tcpHeader[12] = 0x50
	tcpHeader[13] = TH_SYN
	binary.BigEndian.PutUint16(tcpHeader[14:16], 65535)
	tcpHeader[16], tcpHeader[17] = calcTCPChecksum(srcIP, ip4, uint16(srcPort), uint16(port), tcpHeader)

	// 构造 IP 头
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	binary.BigEndian.PutUint16(ipHeader[2:4], 40)
	ipHeader[8] = 64
	ipHeader[9] = syscall.IPPROTO_TCP
	copy(ipHeader[12:16], srcIP.To4())
	copy(ipHeader[16:20], ip4)

	packet := append(ipHeader, tcpHeader...)

	dst := syscall.SockaddrInet4{Port: port}
	copy(dst.Addr[:], ip4)

	// 发送 SYN
	err = syscall.Sendto(fd, packet, 0, &dst)
	if err != nil {
		return false
	}

	// 接收响应：循环读取直到判定或超时。
	//
	// 为什么必须循环：本端口独立 socket 的接收队列里混有其他端口（多主机
	// 扫描时还有其他目标主机）的回包——raw socket 按 protocol 向每个匹配
	// 的 socket 各投递一份副本。旧逻辑单次 Recvfrom、端口不匹配就返回
	// false，读到别人的 SYN-ACK 即把本端口误判 closed，这就是并发多端口
	// 稳定漏报的根因。跳过不匹配的包不会饿死其他 goroutine：它们的
	// socket 各有自己的一份副本。
	//
	// 终止条件（三者之一，循环必然有界）：
	//  1. 收到源 IP+端口都匹配的包 → 按 flags 判定（SYN-ACK=开放 / RST=关闭）
	//  2. Recvfrom 超时（EAGAIN，靠已设的 SO_RCVTIMEO）→ return false
	//  3. 绝对 deadline 到期（time.Now().Add(timeout) 兜底，防 SO_RCVTIMEO
	//     被改动失效，同时限制外来流量风暴下读包的总时长）
	buf := make([]byte, 65535)
	deadline := time.Now().Add(timeout)
	var ip4arr [4]byte
	copy(ip4arr[:], ip4)

	for {
		// 绝对 deadline 作为每轮硬边界：按剩余时间重设 SO_RCVTIMEO，
		// 单轮最多阻塞 remaining，总耗时不会越过 deadline+一包处理时间，
		// 也兜住 SO_RCVTIMEO 被别处改动失效的情形（到期即停）。
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		// 设置接收超时
		// 用 NsecToTimeval 构造, 跨架构字段类型由 syscall 自行确定
		// (linux/amd64 的 Timeval.Sec/Usec 是 int64, 而 386/arm 是 int32, 手写 int32 会在 amd64 下编译失败)
		// NsecToTimeval 向上取整到微秒，remaining>0 时不会产生 {0,0}
		// （{0,0} 在 Linux 表示永不超时，会破坏 deadline 语义）。
		tv := syscall.NsecToTimeval(remaining.Nanoseconds())
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR && time.Now().Before(deadline) {
				continue // 被信号打断且未到期 → 重读
			}
			// EAGAIN/EWOULDBLOCK（SO_RCVTIMEO 超时）或其它错误 → 无响应
			return false
		}
		// 源地址过滤（一）：sockaddr 源地址不是目标 IP → 跳过
		if sa, ok := from.(*syscall.SockaddrInet4); ok && sa.Addr != ip4arr {
			continue
		}
		// 畸形/短包跳过（短于最小 IPv4 头 20 + TCP 头 20），
		// 不能因畸形包把端口误判 closed
		if n < 40 {
			continue
		}
		if buf[0]>>4 != 4 {
			continue // 非 IPv4 包
		}
		// 非首片分片不含 TCP 头，端口字段无意义 → 跳过
		if binary.BigEndian.Uint16(buf[6:8])&0x1fff != 0 {
			continue
		}
		// 解析 IP 头（头长非法 → 跳过）
		ipHdrLen := int(buf[0]&0x0f) * 4
		if ipHdrLen < 20 || n < ipHdrLen+20 {
			continue
		}
		// 源地址过滤（二）：IP 头源地址必须是目标 IP（与 sockaddr 双重校验）
		if !net.IP(buf[12:16]).Equal(ip4) {
			continue
		}

		// 解析 TCP 头
		tcpBuf := buf[ipHdrLen:]
		respSrcPort := binary.BigEndian.Uint16(tcpBuf[0:2])
		respDstPort := binary.BigEndian.Uint16(tcpBuf[2:4])
		flags := tcpBuf[13]

		if respSrcPort != uint16(port) || respDstPort != uint16(srcPort) {
			// 其他端口/其他连接的回包 → 跳过继续读，绝不判 closed
			continue
		}

		switch {
		case flags&TH_SYN != 0 && flags&TH_ACK != 0:
			// 端口开放 → 用本端口自己的 fd 发 RST 关闭半开连接
			sendRST(fd, ip4, srcIP.To4(), port, srcPort)
			return true
		case flags&TH_RST != 0:
			return false
		default:
			// 端口匹配但 flags 无法判定（如残留 ACK 包）→ 继续等真正的响应
			continue
		}
	}
}

// sendRST 发送 RST 包关闭半开连接
func sendRST(fd int, dstIP, srcIP net.IP, dstPort, srcPort int) {
	tcpHeader := make([]byte, 20)
	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(dstPort))
	tcpHeader[12] = 0x50
	tcpHeader[13] = TH_RST
	tcpHeader[16], tcpHeader[17] = calcTCPChecksum(srcIP, dstIP, uint16(srcPort), uint16(dstPort), tcpHeader)

	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	binary.BigEndian.PutUint16(ipHeader[2:4], 40)
	ipHeader[8] = 64
	ipHeader[9] = syscall.IPPROTO_TCP
	copy(ipHeader[12:16], srcIP.To4())
	copy(ipHeader[16:20], dstIP.To4())

	packet := append(ipHeader, tcpHeader...)
	dst := syscall.SockaddrInet4{Port: dstPort}
	copy(dst.Addr[:], dstIP.To4())
	_ = syscall.Sendto(fd, packet, 0, &dst)
}

// calcTCPChecksum 计算 TCP 校验和（含伪头部）
// 伪头部布局（RFC 793，共 12 字节，全部按网络字节序/大端）：
//
//	[0:4]   源 IP      [4:8] 目的 IP
//	[8]     全零       [9]   协议号(IPPROTO_TCP=6)
//	[10:12] TCP 长度
//
// net.IP.To4() 已是网络字节序（大端）的 4 字节，直接 copy 即可，勿再换序。
func calcTCPChecksum(srcIP, dstIP net.IP, srcPort, dstPort uint16, tcpHeader []byte) (byte, byte) {
	tcpLen := uint16(len(tcpHeader))
	pseudo := make([]byte, 12+tcpLen)
	// 之前只填了 protocol 和 TCP 长度，pseudo[0:8] 恒为全零，
	// 校验和按"全零 IP"计算与真实伪头部不符，目标会丢弃该包。
	if v4 := srcIP.To4(); v4 != nil {
		copy(pseudo[0:4], v4)
	}
	if v4 := dstIP.To4(); v4 != nil {
		copy(pseudo[4:8], v4)
	}
	pseudo[8] = 0
	pseudo[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], tcpLen)
	copy(pseudo[12:], tcpHeader)
	pseudo[12+16] = 0
	pseudo[12+17] = 0

	var sum uint32
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(pseudo[i])<<8 + uint32(pseudo[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	result := ^uint16(sum)
	return byte(result >> 8), byte(result)
}

// localIPv4 通过一次不发数据的 UDP 路由查询，获取访问 dst 时本机选用的
// IPv4 源地址（与内核给 IP_HDRINCL 包填充 saddr 时的选路结果一致）。
// 查询失败时退回 IPv4zero，行为与修复前一致。
func localIPv4(dst net.IP) net.IP {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dst, Port: 9})
	if err != nil {
		return net.IPv4zero
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if v4 := addr.IP.To4(); v4 != nil {
			return v4
		}
	}
	return net.IPv4zero
}
