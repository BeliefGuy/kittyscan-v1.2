package Plugins

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net"
	"time"

	"github.com/shadow1ng/fscan/common"
)

var PluginList = map[string]interface{}{
	"21":      FtpScan,
	"22":      SshScan,
	"23":      TelnetScan,
	"135":     Findnet,
	"139":     NetBIOS,
	"445":     SmbScan,
	"873":     RsyncScan,
	"161":     SnmpScan,
	"1433":    MssqlScan,
	"1521":    OracleScan,
	"2181":    ZookeeperScan,
	"3306":    MysqlScan,
	"3389":    RdpScan,
	"3690":    SvnScan,
	"5000":    LdapScan,
	"5432":    PostgresScan,
	"5900":    VncScan,
	"5985":    WinrmScan, // WinRM 是 HTTP/WS-Management：存在性检测 + NTLM 口令爆破（原误映射 LdapScan 已移除）
	"61616":   ActivemqScan,
	"6379":    RedisScan,
	"7001":    WeblogicScan,
	"8080":    TomcatScan,
	"9000":    FcgiScan,
	"9092":    KafkaScan,
	"9200":    ElasticsearchScan,
	"11211":   MemcachedScan,
	"15672":   RabbitmqScan,
	"27017":   MongodbScan,
	"554":     RtspScan,
	"8554":    RtspScan,
	"1000001": MS17010,
	"1000002": SmbGhost,
	"1000003": WebTitle,
	"1000004": SmbScan2,
	"1000005": WmiExec,
	// "1000006" IdentifyScan 在 identify.go 的 init() 中注册:
	// IdentifyScan 内部经 ScanFunc 查 PluginMap, 若直接写在初始化表达式里
	// 会形成 PluginMap → IdentifyScan → ScanFunc → PluginMap 的初始化环(vet 报错)。
}

// PluginMap 类型化函数 map，避免反射调用
var PluginMap = map[string]interface{}{
	"21":      FtpScan,
	"22":      SshScan,
	"23":      TelnetScan,
	"135":     Findnet,
	"139":     NetBIOS,
	"445":     SmbScan,
	"873":     RsyncScan,
	"161":     SnmpScan,
	"1433":    MssqlScan,
	"1521":    OracleScan,
	"2181":    ZookeeperScan,
	"3306":    MysqlScan,
	"3389":    RdpScan,
	"3690":    SvnScan,
	"5000":    LdapScan,
	"5432":    PostgresScan,
	"5900":    VncScan,
	"5985":    WinrmScan,
	"61616":   ActivemqScan,
	"6379":    RedisScan,
	"7001":    WeblogicScan,
	"8080":    TomcatScan,
	"9000":    FcgiScan,
	"9092":    KafkaScan,
	"9200":    ElasticsearchScan,
	"11211":   MemcachedScan,
	"15672":   RabbitmqScan,
	"27017":   MongodbScan,
	"554":     RtspScan,
	"8554":    RtspScan,
	"1000001": MS17010,
	"1000002": SmbGhost,
	"1000003": WebTitle,
	"1000004": SmbScan2,
	"1000005": WmiExec,
}

// ServicePorts 服务兜底端口 map（用于 O(1) 查找）。
// 2026-09-29 精简(双轨制): identify 识别驱动派发已在公网验证(SSH@2022 映射表外端口
// 39/39 触发爆破), 按服务是否被 identify 覆盖分两轨:
//   - identify 已覆盖的 13 服务(ssh/ftp/telnet/vnc/rsync/mysql/mssql/postgres/
//     mongodb/redis/memcached/kafka/rdp): 非标端口由 ServicePluginKey 识别后直接
//     派发, 本表仅留 1 个兜底端口(识别失败/判 web 时的回退);
//   - identify 永远测不出的服务(无对应探针): 非标端口兜底**必须保留完整集合**,
//     否则扫描表(DefaultPorts/main)扫了这些端口却无插件派发=白扫
//     (2026-09-29 用户批准恢复)。
//
// 扫描端口范围(PortGroup/DefaultPorts)不受本表影响, 始终按原列表全扫。
var ServicePorts = map[string]bool{
	// FTP / SSH / Telnet (identify banner 覆盖 → 各留 1 兜底)
	"21": true, "22": true, "23": true,
	// RPC/NetBIOS/SMB (135/445 走 scanner.go 特殊分支; SMB identify 无探针 → 保留 1445/4445)
	"135": true, "139": true, "445": true, "1445": true, "4445": true,
	// Rsync / SNMP
	"873": true, "161": true,
	// SQL Server / MySQL / PostgreSQL / MongoDB / RDP / VNC (identify 覆盖 → 各留 1)
	"1433": true, "3306": true, "5432": true, "27017": true, "3389": true, "5900": true,
	// Oracle (identify 无 TNS 探针 → 非标端口兜底全保留)
	"1521": true, "1522": true, "1523": true, "1524": true, "1525": true,
	"1526": true, "2483": true, "2484": true,
	// Zookeeper / SVN / Kafka / RabbitMQ / Memcached / Redis (标准端口服务, 各留 1)
	"2181": true, "3690": true, "9092": true, "15672": true, "11211": true, "6379": true,
	// LDAP (identify 无探针 → 5000/636 保留; 389 经 PortToPlugin 桥接)
	"389": true, "5000": true, "636": true,
	// WinRM (HTTP/TLS 判 web 后靠兜底 → 5986 保留, 5985 本体)
	"5985": true, "5986": true,
	// ActiveMQ (identify 无 OpenWire 探针 → 61616 保留; 8161=Web控制台)
	"61616": true, "8161": true,
	// WebLogic (HTTP 判 web 靠兜底 → 非标 7002/9060 保留)
	"7001": true, "7002": true, "9060": true,
	// Tomcat (HTTP 判 web 靠兜底 → 非标 8081-8090/8443/9080/9443 保留)
	"8080": true, "8081": true, "8082": true, "8083": true, "8084": true,
	"8085": true, "8086": true, "8087": true, "8088": true, "8089": true,
	"8090": true, "8443": true, "9080": true, "9443": true,
	// Fcgi / Elasticsearch (es 无探针 → 9201/9300 保留)
	"9000": true, "9200": true, "9201": true, "9300": true,
	// RTSP (identify 无探针 → 8554 保留)
	"554": true, "8554": true,
}

// PortToPlugin 端口 → 插件注册键的必要桥接（2026-09-29 双轨制）。
//   - identify 已覆盖服务: 非标端口映射已随识别驱动派发删除(识别后经
//     ServicePluginKey 直接派发, 不经过本表);
//   - identify 永远测不出的服务: 非标→标准映射全部保留(兜底派发依赖它, 用户批准恢复)。
//
// 保留的固定桥接: activemq 8161(Web控制台, -m activemq 也扫它)、ldap 389(标准端口)。
var PortToPlugin = map[string]string{
	// LDAP (插件注册键 5000, 标准端口 389/636)
	"389": "5000", "636": "5000",
	// Oracle (identify 无探针)
	"1522": "1521", "1523": "1521", "1524": "1521", "1525": "1521",
	"1526": "1521", "2483": "1521", "2484": "1521",
	// SMB (identify 无探针)
	"1445": "445", "4445": "445",
	// WebLogic / Tomcat / Elasticsearch (HTTP 判 web 靠兜底)
	"7002": "7001", "9060": "7001",
	"8081": "8080", "8082": "8080", "8083": "8080", "8084": "8080",
	"8085": "8080", "8086": "8080", "8087": "8080", "8088": "8080",
	"8089": "8080", "8090": "8080", "8443": "8080", "9080": "8080", "9443": "8080",
	"9201": "9200", "9300": "9200",
	// WinRM 5986(HTTPS) / RTSP 8554 / ActiveMQ Web控制台 8161
	"5986": "5985",
	"8554": "554",
	"8161": "61616",
}

// WinrmScan WinRM(WS-Management) 扫描入口。
//  1. 先做存在性指纹检测（WinrmDetect，见 Plugins/winrm.go）：向 /wsman 发一次
//     带 Negotiate(NTLM Type1) 的请求，按 401 + WWW-Authenticate 判定 WinRM 存在；
//  2. 检测通过且未指定 -nobr 时，执行完整 NTLM Type1/2/3 握手口令爆破
//     （WinrmBruteForce，见 Plugins/winrm.go）。
//
// -nobr（common.IsBrute=true）语义与其他爆破插件一致：保留检测、只跳过爆破。
func WinrmScan(info *common.HostInfo) {
	if !WinrmDetect(info) {
		return
	}
	if common.IsBrute {
		return
	}
	WinrmBruteForce(info)
}

// ReadBytes 尽量完整地读取一次协议响应，签名与调用方式保持不变：
//  1. 先保留已读字节再判断错误：n>0 时数据立即入缓冲，之后才看 rerr，
//     EOF/超时/其他错误都不会再丢弃本次已读到的数据；
//  2. 单次未读满一块(响应可能还有分片在途)时，设一次性 300ms 读 deadline
//     短等剩余分片：读到更多就继续拼，EOF/超时即收尾——有 deadline 封顶，
//     绝不无界阻塞扫描主循环；首字节前仍沿用调用方自己的 deadline，快速失败不变；
//  3. 若进入过短等待，退出前把读 deadline 恢复为全局超时：残留的 300ms 会截断
//     调用方在同一 conn 上的下一次读取(NetBIOS 对同一 conn 连续多次调用本函数)。
//
// 返回语义不变：读到任何数据返回 err=nil；一个字节都没读到返回最后一次读错误。
func ReadBytes(conn net.Conn) (result []byte, err error) {
	size := 4096
	buf := make([]byte, size)
	const sliceWait = 300 * time.Millisecond // 分片等待窗口
	waitDeadline := time.Time{}              // 零值 = 尚未进入短等待阶段
	defer func() {
		if !waitDeadline.IsZero() {
			// 清掉短等待 deadline 残留；每次调用只针对调用方传入的这一条 conn 独立设置，
			// 并发探测互不影响。忽略设置失败(个别 conn 不支持 deadline)。
			_ = conn.SetReadDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
		}
		if len(result) > 0 {
			err = nil
		}
	}()
	for {
		count, rerr := conn.Read(buf)
		if count > 0 {
			// 先用上本次已读数据，再处理错误——修复原实现 err!=nil 时先 break 丢掉 n>0 字节
			result = append(result, buf[0:count]...)
		}
		if rerr != nil {
			err = rerr // 已读数据全部保留；无数据时快速失败，有数据时 defer 会把 err 置回 nil
			break
		}
		if count < size && waitDeadline.IsZero() {
			// 首次未读满一块：进入带 deadline 的短等待；一次性绝对 deadline，后续无论
			// 收到多少分片都以它封顶，读到 EOF/超时即结束，不会无限等待。
			waitDeadline = time.Now().Add(sliceWait)
			_ = conn.SetReadDeadline(waitDeadline)
		}
	}
	return result, err
}

var key = "0123456789abcdef"

func AesEncrypt(orig string, key string) string {
	// 转成字节数组
	origData := []byte(orig)
	k := []byte(key)
	// 分组秘钥
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 补全码
	origData = PKCS7Padding(origData, blockSize)
	// 加密模式
	blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])
	// 创建数组
	cryted := make([]byte, len(origData))
	// 加密
	blockMode.CryptBlocks(cryted, origData)
	return base64.StdEncoding.EncodeToString(cryted)
}
func AesDecrypt(cryted string, key string) string {
	// 转成字节数组
	crytedByte, _ := base64.StdEncoding.DecodeString(cryted)
	k := []byte(key)
	// 分组秘钥
	block, _ := aes.NewCipher(k)
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 加密模式
	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])
	// 创建数组
	orig := make([]byte, len(crytedByte))
	// 解密
	blockMode.CryptBlocks(orig, crytedByte)
	// 去补全码
	orig = PKCS7UnPadding(orig)
	return string(orig)
}

// 补码
// AES加密数据块分组长度必须为128bit(byte[16])，密钥长度可以是128bit(byte[16])、192bit(byte[24])、256bit(byte[32])中的任意一个。
func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
	padding := blocksize - len(ciphertext)%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// 去码
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
