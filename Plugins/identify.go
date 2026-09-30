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
		svc, tlsAlert, silent := probeBannerHTTP(addr, d)
		if svc != "" {
			return svc
		}
		// TLS 路径(web/redis): 明文被 TLS 拒绝(alert) 时的原有语义。
		if tlsAlert {
			if d := probeTimeout(); d > 0 && probeTLSWeb(addr, d) {
				return "web"
			}
			if d := probeTimeout(); d > 0 && probeTLSRedis(addr, d) {
				return "redis"
			}
			if d := probeTimeout(); d > 0 && probeTLSAmqp(addr, d) {
				return "amqp"
			}
			// 明文已被 TLS 拒绝, 阶段2 明文协议探测无意义(历史语义保留)
			return ""
		}
		// 阶段1b 纯读 banner(新连接、不发数据): 救 server-first banner 型服务
		// (VNC/MySQL/FTP...)在阶段1 "先发GET"竞态中对端 RST 截断缓冲 banner
		// 的情形 —— 含"读到残缺数据非空"的变体(2026-09-29 实测: 真 MySQL
		// 5.5.62@2012 与 FileZilla FTP@990 因残截漏识别, 静默与残截统一触发)。
		// 上限 1s(2026-09-29 并发化配套优化, 原 1.5s)。
		d1b := probeTimeout()
		if max := 1000 * time.Millisecond; d1b > max {
			d1b = max
		}
		if d1b >= 300*time.Millisecond {
			if svc := probeBannerOnly(addr, d1b); svc != "" {
				return svc
			}
		}
		if silent {
			// 明文完全静默 → 可能 TLS-only(6380 资产 65% 为此类):
			// TLS 上试 web/redis。明文有数据但不识别的目标跳过 TLS(2026-09-29
			// 配套优化: 明文已响应=非 TLS-only, 省 ~2s 给阶段2)。
			// 单次上限 1.5s(正常 TLS 握手 <1s): 对"纯静默明文"目标 ClientHello
			// 无响应时不让 TLS 吃满超时, 给阶段2 并发探测留足预算。
			dTw := probeTimeout()
			if max := 1500 * time.Millisecond; dTw > max {
				dTw = max
			}
			if dTw > 0 && probeTLSWeb(addr, dTw) {
				return "web"
			}
			dTr := probeTimeout()
			if max := 1500 * time.Millisecond; dTr > max {
				dTr = max
			}
			if dTr > 0 && probeTLSRedis(addr, dTr) {
				return "redis"
			}
			dTa := probeTimeout()
			if max := 1500 * time.Millisecond; dTa > max {
				dTa = max
			}
			if dTa > 0 && probeTLSAmqp(addr, dTa) {
				return "amqp"
			}
		}
		// → 阶段2 明文协议探测
	}
	// 阶段2: 协议主动探测 —— 并发执行(2026-09-29 用户批准): 每协议独立连接、
	// 各自 probeTimeout() deadline, 总耗时 max 而非 sum; buffered channel
	// 容量=探测数, 提前 return 后余下 goroutine 写入不阻塞、由自身 deadline
	// 兜底退出, 无泄漏。根治串行版静默目标逐个吃满 3s、总预算 9s 内
	// postgres(第5)/rdp(第7) 永远轮不到的结构性问题(实测 13389 真 RDP
	// X.224 有响应却 0/60 识别)。
	type probeOutcome struct {
		name string
		ok   bool
	}
	ch := make(chan probeOutcome, len(protocolProbes))
	for _, p := range protocolProbes {
		go func(p serviceProbe) {
			d := probeTimeout()
			if d < 300*time.Millisecond {
				ch <- probeOutcome{p.name, false}
				return
			}
			ch <- probeOutcome{p.name, p.fn(addr, d)}
		}(p)
	}
	for i := 0; i < len(protocolProbes); i++ {
		r := <-ch
		if r.ok {
			return r.name
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
//   - TLS 端口对明文返回 alert 记录(0x15 0x03) → tlsAlert=true;
//   - silent=true 表示对端完全无应答(TLS-only 丢弃明文/白名单静默),
//     调用方据此优先尝试 TLS 探测(2026-09-29 redis 诊断新增)。
func probeBannerHTTP(addr string, d time.Duration) (svc string, tlsAlert bool, silent bool) {
	conn, err := common.WrapperTcpWithTimeout("tcp", addr, d)
	if err != nil {
		return "", false, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d))
	get := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", addr)
	_, _ = conn.Write([]byte(get))
	data, _ := ReadBytes(conn)
	if len(data) == 0 {
		return "", false, true
	}
	if len(data) >= 2 && data[0] == 0x15 && data[1] == 0x03 {
		return "", true, false
	}
	return classifyBanner(data, conn), false, false
}

// classifyBanner 按首字节特征分类阶段1读到的数据。
// conn 仅用于 SMTP/FTP 歧义消解的二次探测(220 无关键字时发 EHLO 区分)。

// probeBannerOnly 阶段1b: 新连接纯读, 不发任何数据 —— server-first banner
// 型服务(VNC/MySQL/SSH...)不受 "先发GET" 干扰, 专救阶段1竞态 RST 丢包场景。
func probeBannerOnly(addr string, d time.Duration) string {
	conn, err := common.WrapperTcpWithTimeout("tcp", addr, d)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d))
	data, _ := ReadBytes(conn)
	if len(data) == 0 {
		return ""
	}
	if len(data) >= 2 && data[0] == 0x15 && data[1] == 0x03 {
		return "" // TLS alert: 交给调用方的 TLS 分支
	}
	return classifyBanner(data, conn)
}

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
	case mysqlErrPacket(data):
		// MySQL ERR 包(如白名单拦截的 code 1130 "Host is not allowed to
		// connect to this MySQL server"): 服务器不发 greeting 直接回 ERR,
		// mysqlGreeting(只认 0x0a 握手包)不匹配 —— 2026-09-29 mysql 3306
		// Quake 资产 14/60 失败样本全部为此类
		return "mysql"
	case bytes.HasPrefix(data, []byte("@RSYNCD:")):
		return "rsync"
	case bytes.Contains(data, []byte{0xff, 0xfb}) ||
		bytes.Contains(data, []byte{0xff, 0xfd}) ||
		bytes.Contains(data, []byte{0xff, 0xfa}):
		// Telnet IAC WILL/DO/SUBNEGOTIATION —— 从"首字节"放宽为"含 IAC 序列":
		// 阶段1 发 GET 后服务器回显与 IAC 协商混合时 IAC 不在首位
		// (2026-09-29 实测 181.119.185.49 纯读 \xff\xfb\x01 却漏识别)
		return "telnet"
	case bytes.Contains(bytes.ToLower(data), []byte("telnet")):
		// telnet 文本 banner(如 "Warning: Telnet is not a secure protocol...",
		// 2026-09-29 实测 112.30.50.111 漏)。HTTP/ 状态行 case 在最前, HTML 页面
		// 必带状态行先行拦截; 非 HTTP 文本含 telnet 即 telnet 类设备 banner
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

// mysqlErrPacket 判定 MySQL ERR 包: [3B len LE][1B seq][0xff=ERR][2B errcode LE]...
// 双条件防误报: 0xff 包类型 + 消息含 mysql 关键字。典型场景是白名单拦截的
// MySQL(code 1130 Host is not allowed to connect)不发 greeting 直接回 ERR。
func mysqlErrPacket(data []byte) bool {
	return len(data) >= 7 && data[4] == 0xff &&
		bytes.Contains(bytes.ToLower(data), []byte("mysql"))
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

// probeRedisService: PING → +PONG / -NOAUTH / -DENIED / -NOPERM(ACL) /
// -LOADING(主从加载) / -ERR operation not permitted(云代理干扰, 2026-09-29
// 实测 36.137.x 该响应确认为 redis 系)。
func probeRedisService(addr string, d time.Duration) bool {
	return redisRespMatch(svcWriteRead(addr, d, []byte("PING\r\n")))
}

// redisRespMatch 判定 redis RESP 错误/成功前缀(明文与 TLS 探测共用)。
func redisRespMatch(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return bytes.HasPrefix(data, []byte("+PONG")) ||
		bytes.HasPrefix(data, []byte("-NOAUTH")) ||
		bytes.HasPrefix(data, []byte("-DENIED")) ||
		bytes.HasPrefix(data, []byte("-NOPERM")) ||
		bytes.HasPrefix(data, []byte("-LOADING")) ||
		bytes.HasPrefix(data, []byte("-ERR operation not permitted"))
}

// probeTLSRedis: TLS 握手后发 PING, 按 RESP 前缀判定(2026-09-29 redis 诊断:
// 6380 资产约 65% 为 TLS-only, 明文被静默丢弃, 必须在 TLS 上探测)。
func probeTLSRedis(addr string, d time.Duration) bool {
	dialer := &net.Dialer{Timeout: d}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // 识别探测, 不校验证书
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return false
	}
	data, _ := ReadBytes(conn)
	return redisRespMatch(data)
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
	return amqpRespMatch(svcWriteRead(addr, d, amqpHeader))
}

// amqpRespMatch AMQP 应答判定(明文与 TLS 探测共用)。
func amqpRespMatch(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.HasPrefix(data, []byte("AMQP")) {
		return true
	}
	return len(data) >= 11 && data[0] == 0x01 &&
		data[7] == 0x00 && data[8] == 0x0a && data[9] == 0x00 && data[10] == 0x0a
}

// probeTLSAmqp: TLS 握手后发 AMQP 协议头, 按应答判定(2026-09-29 补: 5673 资产
// 实测回 TLS alert 的 AMQPS 端口, 与 probeTLSRedis 同构——TLS-only 协议族
// 需要在 TLS 上探测, 明文协议头被静默丢弃)。
func probeTLSAmqp(addr string, d time.Duration) bool {
	dialer := &net.Dialer{Timeout: d}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // 识别探测, 不校验证书
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d))
	if _, err := conn.Write(amqpHeader); err != nil {
		return false
	}
	data, _ := ReadBytes(conn)
	return amqpRespMatch(data)
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
