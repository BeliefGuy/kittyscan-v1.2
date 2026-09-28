package Plugins

// Plugins/winrm.go — WinRM(5985/5986) HTTP NTLM 口令爆破实现。
//
// 认证流程（HTTP Negotiate，携带 NTLM token）：
//  1. POST /wsman 不带认证             → 期望 401 + WWW-Authenticate: Negotiate
//  2. Authorization: Negotiate Type1   → 期望 401 + WWW-Authenticate: Negotiate <Type2>
//  3. 解析 Type2（server challenge 8 字节 + TargetInfo AV pairs）
//  4. 按口令计算 NTLMv2 response（MS-NLMP 3.3.2；NT hash = MD4(UTF16LE(pass))）
//  5. Authorization: Negotiate Type3   → 200 认证成功 / 401 口令错误
//
// 成功判定（防误报核心）：只有第 5 步 HTTP 200 才算认证成功并打 [vul]；
// 401 一律判口令错误；连接错误/超时/畸形响应/其他状态码（含 3xx）一律返回
// error，绝不判成功。选择“只认 200”的理由见 winrmTryLogin 内注释。
//
// NTLM 是面向连接的认证（MS-NLMP over HTTP）：Type1/Type2/Type3 必须发生在
// 同一个 TCP 连接上，服务端才会把安全上下文延续到第 3 步。因此爆破阶段的
// HTTP client 用 winrmConnPin 固定连接；存在性检测是单次请求，沿用禁
// keep-alive 的老实现。

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/shadow1ng/fscan/common"
	"golang.org/x/crypto/md4"
)

// ---------------- NTLM 常量（MS-NLMP 2.2.2.5 标志位 / 2.2.2.1 AV ids） ----------------

const (
	ntlmSig = "NTLMSSP\x00"

	ntlmFlagUnicode    = 0x00000001
	ntlmFlagOem        = 0x00000002
	ntlmFlagReqTarget  = 0x00000004
	ntlmFlagSign       = 0x00000010 // NTLMSSP_NEGOTIATE_SIGN
	ntlmFlagSeal       = 0x00000020 // NTLMSSP_NEGOTIATE_SEAL
	ntlmFlagNtlm       = 0x00000200
	ntlmFlagAlwaysSign = 0x00008000
	ntlmFlagEss        = 0x00080000 // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	ntlmFlagTargetInfo = 0x00800000 // NTLMSSP_NEGOTIATE_TARGET_INFO
	ntlmFlagVersion    = 0x02000000
	ntlmFlag128        = 0x20000000
	ntlmFlagKeyExch    = 0x40000000
	ntlmFlag56         = 0x80000000

	// ntlmType1Flags = UNICODE|OEM|REQUEST_TARGET|SIGN|SEAL|NTLM|ALWAYS_SIGN|ESS|
	// TARGET_INFO|128|56 = 0xA0888237。
	//
	// SIGN(0x10)/SEAL(0x20) 是真实 Windows 客户端（SSPI）Type1 必带的能力位，也是
	// 本插件历史上 [vul] 分支从未走通的根因：实测靶机(Windows WinRM:5985)上 8 组消息
	// 互换二分，Type1 缺 SEAL(0x20) 时无论 Type3 怎么构造（补 MIC/AV 字段/session
	// key/VERSION 全试过）服务端一律回 401——口令计算正确（NTLM 登录成功）也 401；
	// Type1 补 SEAL 后原版 Type3 直接 200，只补 SIGN 不行。该位属"客户端能力声明"，
	// 不影响 Type3 载荷计算，是安全的兼容性修复。
	//
	// 显式带 TARGET_INFO(0x00800000) 促使服务端在 Type2 里返回
	// TargetInfo AV pairs（domain / timestamp 依赖它）。
	ntlmType1Flags = ntlmFlagUnicode | ntlmFlagOem | ntlmFlagReqTarget |
		ntlmFlagSign | ntlmFlagSeal | ntlmFlagNtlm | ntlmFlagAlwaysSign |
		ntlmFlagEss | ntlmFlagTargetInfo | ntlmFlag128 | ntlmFlag56

	// ntlmType3AllowedFlags Type3 允许保留的标志子集：显式剔除 VERSION（否则规范要求
	// Type3 携带 8 字节 Version 字段）与 KEY_EXCH（会话密钥我们发空），避免字段歧义。
	ntlmType3AllowedFlags = ntlmFlagUnicode | ntlmFlagOem | ntlmFlagReqTarget | ntlmFlagNtlm |
		ntlmFlagAlwaysSign | ntlmFlagEss | ntlmFlagTargetInfo | ntlmFlag128 | ntlmFlag56

	// TargetInfo AV pair 类型（MS-NLMP 2.2.2.1）
	avEOL       = 0x0000
	avNbDomain  = 0x0002 // MsvAvNbDomainName
	avTimestamp = 0x0007 // MsvAvTimestamp
	avDnsDomain = 0x0009 // MsvAvDnsDomainName
)

// winrmIdentifySOAP 标准 WSMan Identify 报文，只用于第 1/2 段（未认证 / Type1）
// 请求——这两段服务端只回 401 + challenge，不处理报文体，报文保持原样即可。
//
// 第 3 段（Type3）绝不能带它：实测靶机(Windows WinRM:5985)认证成功时空报文→200、
// 本 Identify 报文→500（带 SOAPAction 参数同样 500），500 会落进
// winrmTryLogin 的 default 分支，[vul] 打不出来（门槛二）；认证失败时无论
// 报文体是什么都回 401，改空报文不引入误报。
const winrmIdentifySOAP = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>`

// ---------------- 存在性检测（原 base.go WinrmScan 主体，迁至此处） ----------------

// WinrmDetect WinRM(WS-Management) 存在性指纹检测。向 /wsman 发一次带
// Negotiate(NTLM Type1) 的请求，按 401 + WWW-Authenticate 含 NTLM/Negotiate
// 判定 WinRM 存在。返回是否检测到。
//
// 判定分两层（实测 4 个真实 WinRM 目标后确定）：
//   - "存在"：401 + 含 Negotiate/NTLM 关键字（保留原判据，避免收紧后漏报）；
//   - "可爆破"：响应里真有 NTLM Type2 challenge（winrmExtractType2 校验 NTLMSSP
//     签名与消息类型），并尽量给出 AV pairs 里的目标主机名/域名。
//     关键字命中但拿不到 Type2 时仍报 detected（它确实是 Negotiate 端点），但文案
//     会明确提示爆破大概率失败——因为 Type2 是三段握手第二段，没有它 winrmTryLogin
//     必然走不通。实测 66.11.124.143/145/146 与 218.69.18.138 全部返回 Type2。
func WinrmDetect(info *common.HostInfo) bool {
	client := winrmHTTPClient(nil) // 单次请求：禁 keep-alive，与原实现一致
	auth := base64.StdEncoding.EncodeToString(winrmBuildType1())
	resp, err := winrmPost(client, winrmEndpoint(info), auth, winrmIdentifySOAP)
	if err != nil {
		common.LogError(fmt.Sprintf("[-] winrm %v:%v %v", info.Host, info.Ports, err))
		return false
	}
	detected := resp.StatusCode == 401 && winrmHasChallenge(resp)
	if !detected {
		winrmDrainBody(resp)
		return false
	}
	// 只读 Header，不受后续 DrainBody 影响
	var tail string
	if raw, t2err := winrmExtractType2(resp); t2err == nil {
		tail = "NTLM challenge received"
		if t2, perr := winrmParseType2(raw); perr == nil && t2.domain != "" {
			tail += ", target=" + t2.domain
		}
	} else {
		tail = "Negotiate only, no NTLM challenge (brute force will likely fail)"
	}
	common.LogSuccess(fmt.Sprintf("[*] WinRM %v:%v WS-Management endpoint detected (%s)",
		info.Host, info.Ports, tail))
	winrmDrainBody(resp)
	return detected
}

// ---------------- 爆破主循环（结构与 ssh.go / smb.go 一致） ----------------

// WinrmBruteForce WinRM NTLM 口令爆破：common.Userdict["winrm"] × common.Passwords
// 双重循环，{user} 替换、时间预算、common.CheckErrs(err) 短路、失败日志与
// 其他爆破插件同风格。只有 winrmTryLogin 明确返回 (true, nil) 才打 [vul]。
func WinrmBruteForce(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		// -nobr：只跳过爆破；存在性检测已在 WinrmScan 里完成（与其他插件语义一致）。
		return nil
	}
	users := common.Userdict["winrm"]
	passes := common.Passwords

	// 抗误报 canary：先用随机不存在的账号走一遍完整三段握手。若服务端对无效凭据
	// 也返回 200，说明该端点并未真正校验 NTLM，此时放弃爆破——绝不把“不校验”
	// 记成“口令正确”。canary 不为 200（401/错误）则继续正常爆破。
	now := time.Now().UnixNano()
	if ok, _ := winrmTryLogin(info, fmt.Sprintf("nosuchuser_%d", now%100000000), fmt.Sprintf("Invalid#%d", now%100000000)); ok {
		common.LogError(fmt.Sprintf("[-] winrm %v:%v endpoint accepted invalid credentials, brute force aborted (anti-false-positive)", info.Host, info.Ports))
		return errors.New("winrm: endpoint does not validate NTLM credentials")
	}

	starttime := time.Now().Unix()
	for _, user := range users {
		for _, pass := range passes {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := winrmTryLogin(info, user, pass)
			if flag == true && err == nil {
				// 只有 winrmTryLogin 的 HTTP 200 分支才会让 flag 为 true。
				result := fmt.Sprintf("[vul] WinRM %v:%v:%v %v", info.Host, info.Ports, user, pass)
				common.LogSuccess(result)
				return err
			}
			errlog := fmt.Sprintf("[-] winrm %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
			errlog = strings.Replace(errlog, "\n", "", -1)
			common.LogError(errlog)
			tmperr = err
			if common.CheckErrs(err) {
				return err
			}
			if time.Now().Unix()-starttime > (int64(len(users)*len(passes)) * common.Timeout) {
				return err
			}
		}
	}
	return tmperr
}

// ---------------- 单组凭据的三段握手 ----------------

// winrmTryLogin 对一组 user/pass 执行完整 HTTP NTLM 握手。
// 返回 (true, nil) 当且仅当第 3 段（Type3）请求得到 HTTP 200。
// 口令错误（401）→ (false, err)；连接错误/超时/协议异常/其他状态码 → (false, err)。
// 任何路径都不会在无 200 证据时返回 true（绝不误报）。
//
// 成功判定选择“只认 200”，不接受 3xx：
//  1. 本 client 的 CheckRedirect 返回 ErrUseLastResponse，3xx 不被跟随，只能看到
//     Location。无法可靠区分“认证成功后的业务跳转”和“失败页跳转”，跟随重定向更
//     可能被任意 200 错误页骗过——拿不准就按失败/错误处理，宁可漏报不误报；
//  2. 第 3 段用空报文请求（见 winrmIdentifySOAP 注释：Identify 报文在认证成功后
//     也只回 500，空报文才回 200），服务端对成功认证直接返回 200，正常实现不依赖
//     重定向；403/400/500 等同样按错误处理（记 [-] 日志，不记 [vul]）。
func winrmTryLogin(info *common.HostInfo, user string, pass string) (bool, error) {
	pin := &winrmConnPin{timeout: time.Duration(common.BruteTimeout2) * time.Second}
	client := winrmHTTPClient(pin)
	defer func() {
		client.CloseIdleConnections()
		if pin.conn != nil {
			_ = pin.conn.Close()
		}
	}()
	url := winrmEndpoint(info)

	// 第 1 段：不带认证 → 期望 401 + WWW-Authenticate: Negotiate/NTLM
	resp1, err := winrmPost(client, url, "", winrmIdentifySOAP)
	if err != nil {
		return false, err
	}
	status1 := resp1.StatusCode
	challenge1 := winrmHasChallenge(resp1)
	winrmDrainBody(resp1)
	if status1 != 401 || !challenge1 {
		return false, fmt.Errorf("winrm: server does not offer HTTP NTLM (status %d)", status1)
	}

	// 第 2 段：Negotiate Type1 → 期望 401 + WWW-Authenticate 里携带 Type2
	type1 := base64.StdEncoding.EncodeToString(winrmBuildType1())
	resp2, err := winrmPost(client, url, type1, winrmIdentifySOAP)
	if err != nil {
		return false, err
	}
	status2 := resp2.StatusCode
	type2raw, t2err := winrmExtractType2(resp2)
	winrmDrainBody(resp2)
	if status2 != 401 {
		return false, fmt.Errorf("winrm: expected 401 with Type2 challenge, got %d", status2)
	}
	if t2err != nil {
		return false, t2err
	}

	// 第 3 段前置：解析并校验 Type2（签名/类型/长度全部先判后取，畸形→error 不 panic）
	t2, err := winrmParseType2(type2raw)
	if err != nil {
		return false, err
	}

	// 按该用户口令计算 NTLMv2 response（MS-NLMP 3.3.2）
	ntResp, lmResp, err := winrmComputeResponses(pass, user, t2)
	if err != nil {
		return false, err
	}
	if len(ntResp) > 65535 || len(lmResp) > 65535 {
		return false, errors.New("winrm: ntlm response exceeds Type3 secbuf length field")
	}
	type3 := winrmBuildType3(user, t2.domain, winrmWorkstation(), lmResp, ntResp, t2.flags)

	// 第 3 段：Negotiate Type3 + 空报文 → 200 成功 / 401 口令错误 / 其他 = 错误
	resp3, err := winrmPost(client, url, base64.StdEncoding.EncodeToString(type3), "")
	if err != nil {
		return false, err
	}
	status3 := resp3.StatusCode
	winrmDrainBody(resp3)
	switch status3 {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, errors.New("winrm: authentication failed (401)")
	default:
		// 3xx / 400 / 403 / 5xx 一律不当成功（见函数注释）。
		return false, fmt.Errorf("winrm: unexpected status %d after NTLM Type3", status3)
	}
}

// ---------------- HTTP 客户端与请求 ----------------

// winrmConnPin 控制 NTLM 握手期间的拨号次数。
//
// 允许重新拨号(而非禁止)：真实 WinRM 服务端在"第1段无认证 401"的响应里会带
// `Connection: close` 主动要求断开(实测 3/3 公网目标如此), 第2段必须换新连接;
// 若沿用"第二次拨号即拒绝"的严格策略, 87%(694/800) 的正常握手都会被判协议错误,
// 漏报远比误报严重。HTTP NTLM 是 stateless 的——Type3 基于 Type2 的 challenge 计算,
// 服务端(如 HTTP.sys)的 NTLM 状态在端点级而非连接级, 跨连接发送 Type3 依然有效
// (实测: requests 自动重连后仍返回 401 认证失败而非协议错误, 证明新连接被正常受理)。
//
// 仍保留两个约束: ① 拨号次数上限(3 = 三段各一次), 防止服务端反复要求重连导致
// 无限重拨; ② 关闭旧连接再拨新的, 不泄漏 fd。
// 防误报不依赖本 pin——靠 WinrmBruteForce 的 canary(随机账号若回 200 则放弃)
// 与 winrmTryLogin "只认 200"的判定。
type winrmConnPin struct {
	conn    net.Conn
	dials   int
	timeout time.Duration
}

func (p *winrmConnPin) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	p.dials++
	if p.dials > 3 {
		return nil, errors.New("winrm: too many reconnects during ntlm handshake")
	}
	if p.conn != nil {
		// 旧连接可能已被服务端关闭(Connection: close), 释放本地引用防泄漏
		_ = p.conn.Close()
		p.conn = nil
	}
	d := net.Dialer{Timeout: p.timeout}
	c, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	p.conn = c
	return c, nil
}

// winrmHTTPClient 构造方式与原 WinrmScan 一致：BruteTimeout2 超时、5986 跳过
// TLS 证书校验、不跟随重定向（3xx 原样返回，便于按“只认 200”保守判定）。
// pin==nil：存在性检测用，禁 keep-alive（单次请求，与原实现完全一致）；
// pin!=nil：爆破用，启用连接复用并把拨号钉在同一个 TCP 连接上。
func winrmHTTPClient(pin *winrmConnPin) *http.Client {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   pin == nil,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
	}
	if pin != nil {
		transport.DialContext = pin.DialContext
	}
	return &http.Client{
		Timeout:   time.Duration(common.BruteTimeout2) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// winrmEndpoint 5985 走 http，5986 走 https（与原实现一致）。
func winrmEndpoint(info *common.HostInfo) string {
	scheme := "http"
	if info.Ports == "5986" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%v/wsman", scheme, info.Host, info.Ports)
}

// winrmPost 发送 POST /wsman，auth 非空时设置 Authorization: Negotiate <auth>。
// body 为请求体：第 1/2 段传 winrmIdentifySOAP（未认证阶段服务端不处理报文体）；
// 第 3 段（Type3）必须传空报文——见 winrmIdentifySOAP 注释（Identify→500，
// 空报文→200，错误口令两种报文都 401）。
func winrmPost(client *http.Client, url string, auth string, body string) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	if auth != "" {
		req.Header.Set("Authorization", "Negotiate "+auth)
	}
	return client.Do(req)
}

// winrmHasChallenge 判断响应的任一 WWW-Authenticate 头含 NTLM/Negotiate
// （与原存在性检测的判定条件一致）。
func winrmHasChallenge(resp *http.Response) bool {
	for _, v := range resp.Header.Values("WWW-Authenticate") {
		if strings.Contains(v, "NTLM") || strings.Contains(v, "Negotiate") {
			return true
		}
	}
	return false
}

// winrmDrainBody 读干并关闭响应体，让底层连接可复用（NTLM 同连接握手的前提）。
func winrmDrainBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// winrmWorkstation Type3 的 Workstation 字段：本机主机名，取不到则空串。
func winrmWorkstation() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// ---------------- NTLM 消息构造与解析 ----------------

// winrmBuildType1 构造 16 字节 NTLM Type1（NEGOTIATE）：签名 + 类型 1 + 标志。
func winrmBuildType1() []byte {
	msg := make([]byte, 16)
	copy(msg, ntlmSig)
	binary.LittleEndian.PutUint32(msg[8:], 1)
	binary.LittleEndian.PutUint32(msg[12:], ntlmType1Flags)
	return msg
}

// winrmExtractType2 从 401 响应的 WWW-Authenticate 头中找出 base64 编码的
// NTLM Type2。兼容 "Negotiate <token>" / "NTLM <token>"、多行头、逗号分隔的
// 多个 challenge；解码后必须校验 NTLMSSP 签名与消息类型 2。
func winrmExtractType2(resp *http.Response) ([]byte, error) {
	for _, v := range resp.Header.Values("WWW-Authenticate") {
		for _, part := range strings.Split(v, ",") {
			fields := strings.Fields(strings.TrimSpace(part))
			if len(fields) < 2 {
				continue // 裸 "Negotiate"（无 token），不是 Type2
			}
			if !strings.EqualFold(fields[0], "Negotiate") && !strings.EqualFold(fields[0], "NTLM") {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(fields[1])
			if err != nil || len(raw) < 12 {
				continue
			}
			if string(raw[:8]) == ntlmSig && binary.LittleEndian.Uint32(raw[8:12]) == 2 {
				return raw, nil
			}
		}
	}
	return nil, errors.New("winrm: no NTLM Type2 challenge in WWW-Authenticate")
}

// winrmType2 NTLM Type2（CHALLENGE）消息的解析结果。
type winrmType2 struct {
	serverChallenge []byte // 8 字节 server challenge（已拷贝）
	flags           uint32 // Type2 协商标志
	targetInfo      []byte // TargetInfo AV pairs 原样字节（原样回填进 NTLMv2 blob）
	domain          string // responseKey 身份串中的 domain（Nb 优先，Dns 次之，取不到为空）
	timestamp       []byte // MsvAvTimestamp（8 字节 FILETIME），无则为空、计算时用当前时间
}

// winrmParseType2 解析 NTLM Type2。布局（MS-NLMP 2.2.1.2）：
// 0..8 签名 | 8..12 类型=2 | 12..20 TargetName secbuf | 20..24 flags |
// 24..32 server challenge | 32..40 Context | 40..48 TargetInfo secbuf。
// 所有切片前先判长度；畸形消息返回 error，不 panic。
func winrmParseType2(msg []byte) (*winrmType2, error) {
	// 最小长度：签名(8)+类型(4)+TargetName secbuf(8)+flags(4)+challenge(8)=32
	if len(msg) < 32 {
		return nil, fmt.Errorf("winrm: type2 message too short (%d bytes)", len(msg))
	}
	if string(msg[:8]) != ntlmSig {
		return nil, errors.New("winrm: type2 bad signature")
	}
	if mt := binary.LittleEndian.Uint32(msg[8:12]); mt != 2 {
		return nil, fmt.Errorf("winrm: type2 bad message type %d", mt)
	}
	t2 := &winrmType2{
		flags:           binary.LittleEndian.Uint32(msg[20:24]),
		serverChallenge: append([]byte(nil), msg[24:32]...),
	}
	if t2.flags&ntlmFlagTargetInfo != 0 || len(msg) >= 48 {
		if len(msg) < 48 {
			// 声明了 TARGET_INFO 却没有 TargetInfo secbuf → 畸形
			return nil, errors.New("winrm: type2 declares TARGET_INFO but message is truncated")
		}
		ti, err := ntlmReadSecBuf(msg, 40)
		if err != nil {
			return nil, fmt.Errorf("winrm: type2 targetinfo: %w", err)
		}
		t2.targetInfo = ti
		domain, ts, err := ntlmParseAvPairs(ti)
		if err != nil {
			return nil, err
		}
		t2.domain = domain
		t2.timestamp = ts
	}
	return t2, nil
}

// ntlmReadSecBuf 读取安全缓冲区（len:uint16 | alloc:uint16 | offset:uint32，全小端）
// 并做边界校验：offset+len 越过消息尾即报错。返回底层切片（只读使用）。
func ntlmReadSecBuf(msg []byte, fieldOff int) ([]byte, error) {
	if fieldOff < 0 || fieldOff+8 > len(msg) {
		return nil, fmt.Errorf("secbuf field out of range (off=%d msg=%d)", fieldOff, len(msg))
	}
	l := int(binary.LittleEndian.Uint16(msg[fieldOff:]))
	if l == 0 {
		return nil, nil
	}
	off := binary.LittleEndian.Uint32(msg[fieldOff+4:])
	if uint64(off)+uint64(l) > uint64(len(msg)) {
		return nil, fmt.Errorf("secbuf payload out of range (off=%d len=%d msg=%d)", off, l, len(msg))
	}
	return msg[int(off) : int(off)+l], nil
}

// ntlmParseAvPairs 遍历 TargetInfo AV pairs（id:uint16 | len:uint16 | value，全小端），
// 提取 domain（MsvAvNbDomainName 优先，其次 MsvAvDnsDomainName）与 MsvAvTimestamp。
// 任何头/值截断都返回 error；EOL 或字节耗尽视为正常结束。
func ntlmParseAvPairs(ti []byte) (domain string, timestamp []byte, err error) {
	var nb, dns string
	i := 0
	done := false
	for !done && i < len(ti) {
		if i+4 > len(ti) {
			return "", nil, fmt.Errorf("winrm: truncated av-pair header at offset %d", i)
		}
		id := binary.LittleEndian.Uint16(ti[i:])
		l := int(binary.LittleEndian.Uint16(ti[i+2:]))
		i += 4
		if i+l > len(ti) {
			return "", nil, fmt.Errorf("winrm: av-pair 0x%04x (%d bytes) overruns targetinfo", id, l)
		}
		val := ti[i : i+l]
		i += l
		switch id {
		case avEOL:
			done = true
		case avNbDomain:
			s, e := utf16LEToString(val)
			if e != nil {
				return "", nil, e
			}
			nb = s
		case avDnsDomain:
			s, e := utf16LEToString(val)
			if e != nil {
				return "", nil, e
			}
			dns = s
		case avTimestamp:
			if l == 8 {
				timestamp = append([]byte(nil), val...)
			}
			// 长度不为 8 的 timestamp 按“无时间戳”处理（计算时退回当前时间），
			// 时间戳客户端自选、服务端不据此判口令，不视为致命畸形。
		}
	}
	domain = nb
	if domain == "" {
		domain = dns
	}
	return domain, timestamp, nil
}

// ---------------- NTLMv2 计算（MS-NLMP 3.3.2） ----------------

// winrmComputeResponses 计算 NTLMv2 的 NT response 与 LMv2 response：
//
//	NT hash        = MD4(UTF16LE(password))
//	responseKeyNT  = HMAC-MD5(NT hash, UTF16LE(UPPER(user)+domain))   // 依据 MS-NLMP 3.3.2
//	blob           = 0x0101 0000 | 4*0 | timestamp(8) | clientChallenge(8) |
//	                 4*0 | TargetInfo(原样回填) | 4*0
//	ntProofStr     = HMAC-MD5(responseKeyNT, serverChallenge || blob)
//	NT response    = ntProofStr || blob
//	LMv2 response  = HMAC-MD5(responseKeyNT, serverChallenge || clientChallenge) || clientChallenge
//	               // LMv2 的 key 派生式与 responseKeyNT 相同（MS-NLMP 3.3.2
//	               // DefineResponseKeyLM），也可整体用 24 字节 0，此处按规范计算。
//
// timestamp 优先取 Type2 的 MsvAvTimestamp，无则用当前时间的 100ns 自 1601-01-01 起。
func winrmComputeResponses(pass string, user string, t2 *winrmType2) (ntResp []byte, lmResp []byte, err error) {
	if len(t2.serverChallenge) != 8 {
		return nil, nil, fmt.Errorf("winrm: server challenge must be 8 bytes, got %d", len(t2.serverChallenge))
	}
	// ResponseKeyNT = HMAC-MD5(NT hash, UTF16LE(UPPER(user) + domain))
	identity := utf16LE(strings.ToUpper(user) + t2.domain)
	key := hmac.New(md5.New, ntlmNTHash(pass))
	key.Write(identity)
	responseKey := key.Sum(nil)

	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return nil, nil, fmt.Errorf("winrm: client challenge: %w", err)
	}
	ts := t2.timestamp
	if len(ts) != 8 {
		ts = winrmFiletimeNow()
	}

	// blob（NTLMv2 附加证明块）
	blob := make([]byte, 0, 32+len(t2.targetInfo))
	blob = append(blob, 0x01, 0x01, 0x00, 0x00) // RespType=1, HiRespType=1, MBZ
	blob = append(blob, 0, 0, 0, 0)             // 4 字节保留
	blob = append(blob, ts...)                  // 时间戳（8 字节）
	blob = append(blob, clientChallenge...)     // 客户端随机挑战（8 字节）
	blob = append(blob, 0, 0, 0, 0)             // 4 字节保留
	blob = append(blob, t2.targetInfo...)       // TargetInfo 原样回填
	blob = append(blob, 0, 0, 0, 0)             // 4 字节保留

	// ntProofStr = HMAC-MD5(responseKeyNT, serverChallenge || blob)
	proof := hmac.New(md5.New, responseKey)
	proof.Write(t2.serverChallenge)
	proof.Write(blob)
	ntProofStr := proof.Sum(nil)
	ntResp = append(append(make([]byte, 0, len(ntProofStr)+len(blob)), ntProofStr...), blob...)

	// LMv2
	lmKey := hmac.New(md5.New, responseKey)
	lmKey.Write(t2.serverChallenge)
	lmKey.Write(clientChallenge)
	lmProof := lmKey.Sum(nil)
	lmResp = append(append(make([]byte, 0, 24), lmProof...), clientChallenge...)
	return ntResp, lmResp, nil
}

// ntlmNTHash NT hash = MD4(UTF16LE(password))（golang.org/x/crypto/md4）。
func ntlmNTHash(password string) []byte {
	h := md4.New()
	h.Write(utf16LE(password))
	return h.Sum(nil)
}

// winrmFiletimeNow 当前时间的 FILETIME：自 1601-01-01 起的 100ns 单位，小端 8 字节。
func winrmFiletimeNow() []byte {
	const epochDiff = uint64(116444736000000000) // 1601-01-01 → 1970-01-01 的 100ns 数
	ft := uint64(time.Now().UnixNano()/100) + epochDiff
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, ft)
	return b
}

// winrmBuildType3 构造 NTLM Type3（AUTHENTICATE，MS-NLMP 2.2.1.3）。
// 头部 64 字节（不带 Version：Type3 flags 已剔除 VERSION/KEY_EXCH），
// 载荷顺序 LM response | NT response | Domain | User | Workstation（均 UTF-16LE，
// 与强制置位的 UNICODE 标志一致），会话密钥 secbuf 为空。
// flags = 服务端 Type2 flags ∩ 本端能力集，再强制 UNICODE。
func winrmBuildType3(user string, domain string, workstation string, lmResp []byte, ntResp []byte, negotiated uint32) []byte {
	d := utf16LE(domain)
	u := utf16LE(user)
	w := utf16LE(workstation)
	const hdr = 64
	msg := make([]byte, hdr+len(lmResp)+len(ntResp)+len(d)+len(u)+len(w))
	copy(msg, ntlmSig)
	binary.LittleEndian.PutUint32(msg[8:], 3)

	off := hdr
	putSecBuf := func(field int, payload []byte) {
		binary.LittleEndian.PutUint16(msg[field:], uint16(len(payload)))
		binary.LittleEndian.PutUint16(msg[field+2:], uint16(len(payload)))
		binary.LittleEndian.PutUint32(msg[field+4:], uint32(off))
		copy(msg[off:], payload)
		off += len(payload)
	}
	putSecBuf(12, lmResp) // LmChallengeResponse
	putSecBuf(20, ntResp) // NtChallengeResponse
	putSecBuf(28, d)      // DomainName
	putSecBuf(36, u)      // UserName
	putSecBuf(44, w)      // Workstation
	putSecBuf(52, nil)    // EncryptedRandomSessionKey（空）
	flags := negotiated&ntlmType3AllowedFlags | ntlmFlagUnicode
	binary.LittleEndian.PutUint32(msg[60:], flags)
	return msg
}

// ---------------- UTF-16LE 编解码 ----------------

// utf16LE 字符串 → UTF-16LE 字节（奇数长度输入在解码侧会报错，编码侧不会）。
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

// utf16LEToString UTF-16LE 字节 → 字符串；奇数长度视为畸形返回 error。
func utf16LEToString(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("winrm: odd utf16le length %d", len(b))
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u)), nil
}
