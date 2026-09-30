package Plugins

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/shadow1ng/fscan/common"
)

// ---------------------------------------------------------------------------
// 服务识别层 (2026-09-28 重构)
//
// 背景: 原派发逻辑(scanner.go onPortFound)对每个开放端口无条件 AddScan(web)
// 盲发 HTTP, 再按写死的 ServicePorts 端口表决定是否跑爆破插件。非标端口上的
// MySQL/MSSQL/Redis 等永远不派发, 而 HTTP 类误报噪音大。
//
// 本文件把"端口爆破的固定端口"重构成"先识别服务, 再按服务派发":
//  1. 每个开放端口(135/445 特殊分支除外)先跑 IdentifyScan 做一次低成本识别;
//  2. 识别出具体服务(含非标端口) → 打印 [info], 直接调用对应爆破/未授权插件,
//     不再对该端口盲发 HTTP;
//  3. 识别为 Web 或识别不出 → 走原 WebTitle(指纹+POC, 利用逻辑零改动) +
//     ServicePorts 端口表兜底(2026-09-29 精简后每服务仅 1 个兜底端口,
//     非标端口的派发完全依赖本文件的识别, 识别失败时不再有端口表兜底)。
//
// 识别策略(两阶段, 总预算 3×Timeout, 超时即回退):
//  - 阶段1 单连接: 立即发 HTTP GET, 同时收取"先发 banner"型服务的应答,
//    一次连接同时完成 Web 判定与 SSH/FTP/MySQL/VNC/rsync/Telnet/SMTP 被动识别;
//  - 阶段2 协议主动探测: redis/memcached/mongodb/mssql/postgres/kafka/rdp/amqp
//    各自独立连接, 响应特征严格匹配, 失败快速关闭, 由下一轮探测接管;
//  - 阶段3 TLS: 明文探测被 TLS 告警拒绝, 或握手成功且 TLS 上是 HTTP → web。
// ---------------------------------------------------------------------------

// IdentifyKey 是服务识别任务在 PluginMap 中的键。
// 1000001-1000005 已被 MS17010/SmbGhost/WebTitle/Smb2/WmiExec 占用。
const IdentifyKey = "1000006"

// init 注册服务识别调度入口。必须放在 init() 而非 PluginMap 初始化表达式:
// IdentifyScan 经 ScanFunc 查 PluginMap, 直接写进初始化表达式会构成
// PluginMap → IdentifyScan → ScanFunc → PluginMap 的初始化环(go vet 报错)。
func init() {
	PluginMap[IdentifyKey] = IdentifyScan
	PluginList[IdentifyKey] = IdentifyScan
}

// ServicePluginKey 服务识别结果 → PluginMap 派发键。
// 识别命中的服务直接走对应爆破/未授权插件, 跳过 HTTP 盲测。
// smtp/amqp 无对应利用插件, 识别后仅记录 [info](见 IdentifyScan)。
var ServicePluginKey = map[string]string{
	"ssh":       "22",
	"ftp":       "21",
	"telnet":    "23",
	"vnc":       "5900",
	"rsync":     "873",
	"mysql":     "3306",
	"mssql":     "1433",
	"postgres":  "5432",
	"mongodb":   "27017",
	"redis":     "6379",
	"memcached": "11211",
	"kafka":     "9092",
	"rdp":       "3389",
}

// IdentifyScan 服务识别调度入口(scanner.go all/main 分支的 default 情况派发)。
// 在任务 goroutine 内联执行识别与后续插件, 不再嵌套 AddScan —— AddScan 的
// 并发槽 ch 容量=Threads, 嵌套派发会在槽位占满时互相等待造成死锁。
func IdentifyScan(info *common.HostInfo) {
	svc := IdentifyService(info.Host, info.Ports)
	// 2026-09-29 输出格式: [port] 行与服务识别合并为一行(用户要求),
	// 识别结果以 (svc) 后缀追加在端口后; 原独立服务行 "[info] ip:port svc" 取消,
	// 指纹类 [info](InfoScan)与 [web] 不受影响。未识别时不带后缀(等同原 [port] 行)。
	// web 归一显示为 http(用户示例: [port] ip:8080(http))。
	addr := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	switch {
	case svc == "web":
		common.LogSuccess("[port] " + addr + "(http)")
	case svc != "":
		common.LogSuccess("[port] " + addr + "(" + svc + ")")
	default: // 未识别: 与原扫描期 [port] 行一致
		common.LogSuccess("[port] " + addr)
	}
	if svc != "" && svc != "web" {
		if key, ok := ServicePluginKey[svc]; ok {
			k := key
			ScanFunc(&k, info)
			return
		}
		// 识别出无对应插件的服务(如 smtp/amqp): 不盲发 HTTP;
		// 端口仍在精简后的端口表内(每服务 1 个兜底端口)则保留兜底派发。
		if ServicePorts[info.Ports] {
			k := info.Ports
			ScanFunc(&k, info)
		}
		return
	}
	// svc == "web" 或 未识别出具体服务 → WebTitle(指纹+POC, 利用逻辑不变)
	// + ServicePorts 端口表兜底插件(2026-09-29 精简: 每服务仅 1 个兜底端口)。
	webKey := strconv.Itoa(common.PORTList["web"])
	ScanFunc(&webKey, info)
	if ServicePorts[info.Ports] {
		k := info.Ports
		ScanFunc(&k, info)
	}
}

// IdentifyService 识别 addr 上运行的服务。
// 返回值: "web" | 服务名(ServicePluginKey/日志用) | ""(未识别, 交由调用方兜底)。
func IdentifyService(host, port string) string {
	addr := net.JoinHostPort(host, port)
	timeout := time.Duration(common.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	// 整体识别预算: 3×Timeout。开放但持续不应答的端口不会无限拖住任务,
	// 超预算直接判未识别 → 调用方走 WebTitle+端口表兜底(与重构前等价)。
	deadline := time.Now().Add(3 * timeout)
	probeTimeout := func() time.Duration {
		d := timeout
		if r := time.Until(deadline); r < d {
			d = r
		}
		return d
	}

	// 阶段1: 单连接 —— 先发 HTTP GET, 同时收取先发 banner 型服务的应答。
	if d := probeTimeout(); d > 0 {
		svc, tlsAlert := probeBannerHTTP(addr, d)
		if svc != "" {
			return svc
		}
		if tlsAlert {
			// 明文被 TLS 拒绝 → 直接在 TLS 上做 HTTP 探测
			if d := probeTimeout(); d > 0 && probeTLSWeb(addr, d) {
				return "web"
			}
			return ""
		}
	}
	// 阶段2: 协议主动探测(每协议独立连接, 失败快速失败)
	for _, p := range protocolProbes {
		d := probeTimeout()
		if d < 300*time.Millisecond {
			break
		}
		if p.fn(addr, d) {
			return p.name
		}
	}
	// 阶段3: TLS 探测(明文阶段静默的端口可能是 TLS-only Web)
	if d := probeTimeout(); d >= 300*time.Millisecond && probeTLSWeb(addr, d) {
		return "web"
	}
	return ""
}

// probeBannerHTTP 阶段1: 连接后立即发送 HTTP GET, 读取对端任何应答。
//   - HTTP 服务回状态行 → "web";
//   - 先发 banner 的服务(SSH/FTP/MySQL/VNC/...)的 banner 会先于/伴随到达,
//     GET 对它们无害(协议错误在 banner 之后才被处理);
//   - TLS 端口对明文返回 alert 记录(0x15 0x03) → tlsAlert=true。
func probeBannerHTTP(addr string, d time.Duration) (svc string, tlsAlert bool) {
	conn, err := common.WrapperTcpWithTimeout("tcp", addr, d)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d))
	get := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr)
	_, _ = conn.Write([]byte(get))
	data, _ := ReadBytes(conn)
	if len(data) == 0 {
		return "", false
	}
	if len(data) >= 2 && data[0] == 0x15 && data[1] == 0x03 {
		return "", true
	}
	return classifyBanner(data, conn), false
}

// classifyBanner 按首字节特征分类阶段1读到的数据。
// conn 仅用于 SMTP/FTP 歧义消解的二次探测(220 无关键字时发 EHLO 区分)。
func classifyBanner(data []byte, conn net.Conn) string {
	switch {
	case bytes.HasPrefix(data, []byte("HTTP/")):
		return "web"
	case bytes.HasPrefix(data, []byte("SSH-")):
		return "ssh"
	case mysqlGreeting(data):
		return "mysql"
	case bytes.HasPrefix(data, []byte("RFB ")):
		return "vnc"
	case bytes.HasPrefix(data, []byte("@RSYNCD:")):
		return "rsync"
	case len(data) >= 2 && data[0] == 0xff && (data[1] == 0xfb || data[1] == 0xfd || data[1] == 0xfa):
		// Telnet IAC WILL/DO/SUBNEGOTIATION
		return "telnet"
	case bytes.HasPrefix(data, []byte("220 ")) || bytes.HasPrefix(data, []byte("220-")):
		head := data
		if len(head) > 300 {
			head = head[:300]
		}
		low := strings.ToLower(string(head))
		if strings.Contains(low, "ftp") {
			return "ftp"
		}
		if strings.Contains(low, "esmtp") || strings.Contains(low, "smtp") {
			return "smtp"
		}
		// "220" 但无关键字: 发 EHLO 区分 FTP(5xx/530) 与 SMTP(250)
		_, _ = conn.Write([]byte("EHLO ident\r\n"))
		resp, _ := ReadBytes(conn)
		if bytes.HasPrefix(resp, []byte("250")) {
			return "smtp"
		}
		if len(resp) > 0 {
			return "ftp"
		}
		return ""
	}
	return ""
}

// mysqlGreeting 判定 MySQL/MariaDB 服务端握手包:
// [3字节 len LE][1字节 seq=0][协议版本 0x0a/0x09][可打印版本串\0...]
func mysqlGreeting(data []byte) bool {
	if len(data) < 6 || data[3] != 0 {
		return false
	}
	if data[4] != 0x0a && data[4] != 0x09 {
		return false
	}
	pktLen := int(data[0]) | int(data[1])<<8 | int(data[2])<<16
	// 长度字段须与实际读到的字节数自洽(允许 greet 后服务端追加的错误包),
	// 防止把随机二进制流量误判成 MySQL 而跳过 Web 探测。
	if pktLen < 5 || pktLen > 4096 || len(data) < pktLen+4 {
		return false
	}
	end := bytes.IndexByte(data[5:], 0)
	if end < 1 {
		return false
	}
	for _, c := range data[5 : 5+end] {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// serviceProbe 协议主动探测项: 独立连接, 写入探测包, 按响应特征判定。
type serviceProbe struct {
	name string
	fn   func(addr string, d time.Duration) bool
}

// protocolProbes 阶段2探测顺序: 响应快、特征强的在前。
// 各协议对错误输入大多直接关闭连接, 单次探测成本≈1 RTT。
var protocolProbes = []serviceProbe{
	{"redis", probeRedisService},
	{"memcached", probeMemcachedService},
	{"mongodb", probeMongoService},
	{"mssql", probeMssqlService},
	{"postgres", probePostgresService},
	{"kafka", probeKafkaService},
	{"rdp", probeRdpService},
	{"amqp", probeAmqpService},
}

// svcWriteRead 建连→写探测包→读应答(ReadBytes 收满后按静默 300ms 收尾)。
// 失败返回 nil。
func svcWriteRead(addr string, d time.Duration, payload []byte) []byte {
	conn, err := common.WrapperTcpWithTimeout("tcp", addr, d)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d))
	if _, err := conn.Write(payload); err != nil {
		return nil
	}
	data, _ := ReadBytes(conn)
	return data
}

// probeRedisService: PING → +PONG / -NOAUTH / -DENIED。
func probeRedisService(addr string, d time.Duration) bool {
	data := svcWriteRead(addr, d, []byte("PING\r\n"))
	if len(data) == 0 {
		return false
	}
	return bytes.HasPrefix(data, []byte("+PONG")) ||
		bytes.HasPrefix(data, []byte("-NOAUTH")) ||
		bytes.HasPrefix(data, []byte("-DENIED"))
}

// probeMemcachedService: stats → STAT 行。
func probeMemcachedService(addr string, d time.Duration) bool {
	data := svcWriteRead(addr, d, []byte("stats\r\n"))
	return bytes.HasPrefix(data, []byte("STAT "))
}

// mongoIsMasterPacket OP_QUERY admin.$cmd {isMaster:1}(58字节)。
// 无认证握手命令, 各版本 MongoDB(含 5.x/6.x 对 OP_QUERY 的握手白名单)均应答。
var mongoIsMasterPacket = []byte{
	0x3a, 0x00, 0x00, 0x00, // messageLength = 58
	0x01, 0x00, 0x00, 0x00, // requestID
	0x00, 0x00, 0x00, 0x00, // responseTo
	0xd4, 0x07, 0x00, 0x00, // opCode = 2004 (OP_QUERY)
	0x00, 0x00, 0x00, 0x00, // flags
	0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // "admin.$cmd\0"
	0x00, 0x00, 0x00, 0x00, // numberToSkip
	0x01, 0x00, 0x00, 0x00, // numberToReturn
	// query BSON {isMaster: 1}
	0x13, 0x00, 0x00, 0x00, 0x10, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
}

// probeMongoService: 发 OP_QUERY isMaster, 校验应答帧长度与操作码(OP_REPLY/OP_MSG)。
func probeMongoService(addr string, d time.Duration) bool {
	data := svcWriteRead(addr, d, mongoIsMasterPacket)
	if len(data) < 16 {
		return false
	}
	msgLen := binary.LittleEndian.Uint32(data[0:4])
	if msgLen < 16 || msgLen > 4*1024*1024 || uint64(msgLen) > uint64(len(data)) {
		return false
	}
	op := binary.LittleEndian.Uint32(data[12:16])
	return op == 1 /* OP_REPLY */ || op == 2013 /* OP_MSG */
}

// mssqlPreloginPacket TDS PRELOGIN(20字节): VERSION 选项 + 结束符。
var mssqlPreloginPacket = []byte{
	0x12, 0x01, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, // TDS头: PRELOGIN / EOM / 长度20
	0x00, 0x00, 0x06, 0x00, 0x06, // VERSION选项: type=0 offset=6 len=6
	0xff,                               // 选项表结束
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // version 数据
}

// probeMssqlService: PRELOGIN → TDS 应答包(type=0x04 且 EOM 位置位)。
func probeMssqlService(addr string, d time.Duration) bool {
	data := svcWriteRead(addr, d, mssqlPreloginPacket)
	if len(data) < 8 || data[0] != 0x04 {
		return false
	}
	return data[1]&0x01 != 0 // EOM: 单包应答
}

// pgSSLRequest PostgreSQL SSLRequest(8字节)。
var pgSSLRequest = []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}

// probePostgresService: SSLRequest → 单字节 'S'/'N'/'G'。
func probePostgresService(addr string, d time.Duration) bool {
	data := svcWriteRead(addr, d, pgSSLRequest)
	if len(data) < 1 || len(data) > 3 {
		return false
	}
	return data[0] == 'S' || data[0] == 'N' || data[0] == 'G'
}

// probeKafkaService: Metadata 请求 → 长度前缀合法且回显 correlation id=1。
func probeKafkaService(addr string, d time.Duration) bool {
	request := []byte{
		0x00, 0x03, // API Key: Metadata
		0x00, 0x00, // API Version: 0
		0x00, 0x00, 0x00, 0x01, // Correlation ID: 1
		0x00, 0x05, // Client ID length: 5
		'k', 'i', 't', 't', 'y',
		0x00, 0x00, 0x00, 0x00, // Topics: 空数组
	}
	pkt := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(pkt[:4], uint32(len(request)))
	copy(pkt[4:], request)
	data := svcWriteRead(addr, d, pkt)
	if len(data) < 12 {
		return false
	}
	respLen := binary.BigEndian.Uint32(data[0:4])
	if respLen < 8 || respLen > 65536 {
		return false
	}
	return binary.BigEndian.Uint32(data[4:8]) == 1
}

// rdpX224ConnectRequest X.224 Connection Request + RDP_NEG_REQ(requestedProtocols=SSL|HYBRID)。
// 与 grdp 库(tomatome/grdp x224.go Serialize)在无 cookie 情况下发出的报文一致。
var rdpX224ConnectRequest = []byte{
	0x03, 0x00, 0x00, 0x13, // TPKT v3, 长度 19
	0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 CR: LI=14, code=0xE0
	0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, // RDP_NEG_REQ, protocols=3
}

// probeRdpService: TPKT + X.224 Connection Confirm(code=0xDx)。
func probeRdpService(addr string, d time.Duration) bool {
	data := svcWriteRead(addr, d, rdpX224ConnectRequest)
	if len(data) < 6 || data[0] != 0x03 || data[1] != 0x00 {
		return false
	}
	return data[5]&0xf0 == 0xd0
}

// amqpHeader AMQP 0-9-1 协议头。
var amqpHeader = []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}

// probeAmqpService: 协议头 → 服务端回协议头("AMQP...")或 Connection.Start 方法帧
// (frame type=1, class=10 connection, method=10 start)。
func probeAmqpService(addr string, d time.Duration) bool {
	data := svcWriteRead(addr, d, amqpHeader)
	if len(data) == 0 {
		return false
	}
	if bytes.HasPrefix(data, []byte("AMQP")) {
		return true
	}
	return len(data) >= 11 && data[0] == 0x01 &&
		data[7] == 0x00 && data[8] == 0x0a && data[9] == 0x00 && data[10] == 0x0a
}

// probeTLSWeb 阶段3: TLS 握手成功且其上为 HTTP → true。
// 对 IP 目标不设 SNI; 对域名目标带上 SNI 以兼容虚拟主机。
func probeTLSWeb(addr string, d time.Duration) bool {
	conn, err := common.WrapperTcpWithTimeout("tcp", addr, d)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d))
	cfg := &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true}
	if host, _, e := net.SplitHostPort(addr); e == nil && net.ParseIP(host) == nil {
		cfg.ServerName = host
	}
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		return false
	}
	get := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr)
	if _, err := tc.Write([]byte(get)); err != nil {
		return false
	}
	data, _ := ReadBytes(tc)
	return bytes.HasPrefix(data, []byte("HTTP/"))
}
