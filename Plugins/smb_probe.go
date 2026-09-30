package Plugins

import (
	"time"

	"github.com/shadow1ng/fscan/common"
)

// SMB 方言探测结果。
const (
	smbDialectUnknown = "unknown" // 连接失败/超时/非预期响应
	smbDialectSMB1    = "smb1"    // 响应 \xffSMB: 服务器接受 SMB1(含双栈与纯 SMB1 老设备)
	smbDialectSMB2    = "smb2"    // 响应 \xfeSMB: SMB1 被禁、仅 SMB2+(现代 Windows/Samba 的标准行为)
)

// smbDialectProbe 探测目标 445 端口的 SMB 方言, 供融合入口 SmbScan 将爆破
// 二选一路由到 smb1(stacktitan) 或 smb2(go-smb2) 后端, 保证全字典只跑一遍。
//
// 原理: 发送"仅含 SMB1 方言"的 negotiate(复用 ms17010.go 的经典检测报文,
// 包级只读共享、并发写安全)。按 [MS-SMB2] 3.3.5.2.1, SMB1 禁用的服务器会回
// SMB2 wildcard 响应(魔数 \xfeSMB); 接受 SMB1 的老设备回 \xffSMB。
// 响应结构 = NetBIOS session 头(4字节) + SMB 魔数, 故魔数在 offset 4。
//
// 探测目标固定 host:445 —— 与两个爆破后端一致(SmblConn/Smb2Con 均硬编码 445),
// 即使调用方 info.Ports 是 1445/4445(-m smb / 端口兜底映射), 后端实际打的也是 445。
// 一条探测连接(毫秒级)完成分流, 不计入爆破预算, 不产生双倍爆破。
func smbDialectProbe(addr string, timeout time.Duration) string {
	conn, err := common.WrapperTcpWithTimeout("tcp", addr, timeout)
	if err != nil {
		return smbDialectUnknown
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(negotiateProtocolRequest); err != nil {
		return smbDialectUnknown
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return smbDialectUnknown
	}
	// NetBIOS session 头(4字节)之后是 SMB1(\xffSMB) 或 SMB2(\xfeSMB) 魔数
	if buf[4] == 0xff && buf[5] == 'S' && buf[6] == 'M' && buf[7] == 'B' {
		return smbDialectSMB1
	}
	if buf[4] == 0xfe && buf[5] == 'S' && buf[6] == 'M' && buf[7] == 'B' {
		return smbDialectSMB2
	}
	return smbDialectUnknown
}
