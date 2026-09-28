package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"net"
	"sync"
	"time"
)

func SnmpScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	// -br（common.BruteThread）并发爆破：使用 SNMP 专用团体名字典，
	// 预组装团体名组合，顺序与原 for 循环一致（无 {user} 替换，与原逻辑一致）。
	type snmpCombo struct{ community string }
	var combos []snmpCombo
	for _, community := range common.Userdict["snmp"] {
		combos = append(combos, snmpCombo{community})
	}
	if len(combos) == 0 {
		return tmperr
	}

	// worker 数；common.BruteThread 默认 1
	workers := common.BruteThread
	if workers < 1 {
		workers = 1
	}
	// 预算：沿用原公式（团体名字典数 × BruteTimeout2 秒），只按 worker 数摊薄；
	// workers=1 时与原表达式一致。
	budget := int64(len(common.Userdict["snmp"])) * common.BruteTimeout2 / int64(workers)

	// 共享状态全部由 mu 保护：found/sucErr/stopped 以及具名返回值 tmperr
	var (
		mu      sync.Mutex
		found   bool
		stopped bool // 终态已发生，close(stop) 只会执行一次
		sucErr  error
	)
	stop := make(chan struct{})
	// signalStop：调用方必须持有 mu；stopped 保证不会重复 close(stop)（panic）
	signalStop := func() {
		if !stopped {
			stopped = true
			close(stop)
		}
	}

	// 预填充有缓冲 channel：容量=组合数，投递不阻塞，worker 提前退出也不会死锁
	jobs := make(chan snmpCombo, len(combos))
	for _, c := range combos {
		jobs <- c
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				select {
				case <-stop:
					return // 已有结果，立即退出（无忙等）
				default:
				}
				if workers > 1 && time.Now().Unix()-starttime > budget {
					return // 预算兜底，仅并发模式在尝试前检查；br=1 保持原判定位置（失败日志之后）
				}
				flag, err := SnmpConn(info, c.community)
				mu.Lock()
				if stopped {
					// 终态之后到达的结果静默丢弃（br=1 单 worker 时不会走到这里）
					mu.Unlock()
					return
				}
				if flag && err == nil {
					// [vul] 由 SnmpConn 内部输出，这里不再重复打印（保持日志模板与次数不变）
					found = true
					sucErr = err
					signalStop()
					mu.Unlock()
					return
				}
				errlog := fmt.Sprintf("[-] snmp %v:%v %v %v", info.Host, info.Ports, c.community, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					signalStop()
					mu.Unlock()
					return
				}
				if time.Now().Unix()-starttime > budget {
					mu.Unlock()
					return
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if found {
		return sucErr
	}
	return tmperr
}

func SnmpConn(info *common.HostInfo, community string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := net.DialTimeout("udp", realhost, time.Duration(common.BruteTimeout2)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(common.BruteTimeout2) * time.Second))

	// 每次请求使用随机非 0 request-id（31 位正整数，非 0 兜底）：
	// 响应必须原样回显该 request-id（RFC 1157 §4：管理端靠 request-id 把响应与
	// 未完成请求配对，agent 在响应中原样带回），避免把上一个团体名/上一次请求的
	// 迟到 UDP 响应（串包）误判为本次团体字成功。原先固定发 0、且完全不校验回显。
	reqID := int32(time.Now().UnixNano() & 0x7fffffff)
	if reqID == 0 {
		reqID = 1
	}

	// SNMP GET 请求 for sysDescr (OID: 1.3.6.1.2.1.1.1.0)
	// 构造 SNMP v1 GET Request
	request := buildSnmpGetRequest(community, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}, reqID)

	_, err = conn.Write(request)
	if err != nil {
		return
	}

	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	if err != nil {
		return
	}

	// 验证 SNMP 响应结构与语义
	// SNMP v1 GetResponse 格式:
	// 0x30 (SEQUENCE) [length] [version] [community] [PDU]
	// PDU: 0xa2 (GetResponse) [length] [request-id] [error-status] [error-index] [varbindlist]
	// 判定为“团体字有效”必须同时满足（缺一不可）：
	//  1) PDU 类型是 GetResponse(0xa2)
	//  2) 响应回显的 request-id == 本次发送值（防串包）
	//  3) error-status == 0 (noError)：错误团体字也可能收到 errorStatus != 0 的
	//     GetResponse（RFC 1157/3411：genErr(4)、readOnly(2) 等），原实现把这种
	//     错误响应当成“团体字正确”造成误报
	//  4) varbindlist 非空，且首个 varbind 是含 OID 的 SEQUENCE
	if n < 20 {
		return // 响应太短，不是有效的 SNMP 响应
	}

	// 外层 SEQUENCE (0x30)；长度支持短形式与 0x81/0x82 长形式——sysDescr 较长时
	// 响应超过 127 字节，原实现只读单字节长度会把这类正常响应误当坏包丢掉（漏报）
	if reply[0] != 0x30 {
		return
	}
	_, msgStart, msgEnd, ok := asn1ReadTLV(reply, n, 0)
	if !ok {
		return
	}

	// version (INTEGER)：不校验取值，v1/v2c 响应均放行（与原实现语义一致）
	tag, _, verEnd, ok := asn1ReadTLV(reply, n, msgStart)
	if !ok || tag != 0x02 || verEnd > msgEnd {
		return
	}
	// community (OCTET STRING)：通用 TLV 解析，修复原实现 pos+1 无边界的潜在越界
	tag, _, commEnd, ok := asn1ReadTLV(reply, n, verEnd)
	if !ok || tag != 0x04 || commEnd > msgEnd {
		return
	}
	// PDU 类型
	tag, pduStart, pduEnd, ok := asn1ReadTLV(reply, n, commEnd)
	if !ok || tag != 0xa2 || pduEnd > msgEnd {
		return // 不是 GetResponse
	}

	// request-id：必须与本次发送值一致
	reqIDVal, next, ok := asn1ReadInt32(reply, n, pduStart, pduEnd)
	if !ok || reqIDVal != reqID {
		return
	}
	// error-status：必须为 0 (noError)
	errStatus, next, ok := asn1ReadInt32(reply, n, next, pduEnd)
	if !ok || errStatus != 0 {
		return
	}
	// error-index：只需解析位置正确；error-status==0 时其语义无意义，不强制为 0（避免误伤）
	if _, next, ok = asn1ReadInt32(reply, n, next, pduEnd); !ok {
		return
	}
	// varbindlist：非空，且首个 varbind 是含 OID 的 SEQUENCE
	tag, vbStart, vbEnd, ok := asn1ReadTLV(reply, n, next)
	if !ok || tag != 0x30 || vbEnd > pduEnd || vbStart >= vbEnd {
		return
	}
	tag, vb1Start, vb1End, ok := asn1ReadTLV(reply, n, vbStart)
	if !ok || tag != 0x30 || vb1End > vbEnd || vb1Start >= vb1End {
		return
	}
	tag, _, _, ok = asn1ReadTLV(reply, n, vb1Start)
	if !ok || tag != 0x06 { // varbind 第一个元素必须是 OID
		return
	}

	// 验证通过：是 error-status=noError、回显本次 request-id 的有效 SNMP GetResponse
	flag = true
	result := fmt.Sprintf("[vul] SNMP %v:%v community: %v", info.Host, info.Ports, community)
	common.LogSuccess(result)
	return
}

// asn1ReadTLV 从 buf[i] 处读取一个 TLV（tag + 长度；长度支持短形式与 0x81/0x82 长形式），
// 返回 tag、内容起始/结束下标。ok=false 表示越界或长度非法。
func asn1ReadTLV(buf []byte, n int, i int) (tag byte, contentStart int, contentEnd int, ok bool) {
	if i < 0 || i+2 > n {
		return
	}
	tag = buf[i]
	b := buf[i+1]
	var length int
	pos := i + 2
	if b < 0x80 {
		length = int(b)
	} else {
		num := int(b & 0x7f)
		if num == 0 || num > 4 || pos+num > n {
			return // 不支持不定长编码/越界的长形式
		}
		for k := 0; k < num; k++ {
			length = length<<8 | int(buf[pos])
			pos++
		}
	}
	if length < 0 || pos+length > n {
		return
	}
	return tag, pos, pos + length, true
}

// asn1ReadInt32 从 buf[i] 处读取一个 INTEGER（1~4 字节），返回值与下一个字段起始下标；
// limit 用于禁止该字段越出所属容器（PDU/消息）边界。
func asn1ReadInt32(buf []byte, n int, i int, limit int) (val int32, next int, ok bool) {
	t, start, end, valid := asn1ReadTLV(buf, n, i)
	if !valid || t != 0x02 || end > limit || start >= end || end-start > 4 {
		return 0, 0, false
	}
	if buf[start]&0x80 != 0 {
		val = -1 // 负数：符号扩展
	}
	for j := start; j < end; j++ {
		val = val<<8 | int32(buf[j])
	}
	return val, end, true
}

func buildSnmpGetRequest(community string, oid []byte, requestID int32) []byte {
	commBytes := []byte(community)
	version := []byte{0x02, 0x01, 0x00} // version 0 = v1
	comm := append([]byte{0x04, byte(len(commBytes))}, commBytes...)

	oidEntry := append([]byte{0x06, byte(len(oid))}, oid...)
	oidEntry = append(oidEntry, 0x05, 0x00) // NULL

	varBindings := append([]byte{0x30, byte(len(oidEntry))}, oidEntry...)
	// PDU 内容 = request-id(02 04 + 4 字节 = 6) + error-status(3) + error-index(3) + varbindlist
	getReq := append([]byte{0xa0, byte(12 + len(varBindings))},
		0x02, 0x04, // request-id：4 字节正整数（随机，须与响应回显一致）
		byte(requestID>>24), byte(requestID>>16), byte(requestID>>8), byte(requestID),
		0x02, 0x01, 0x00, // error-status: 0
		0x02, 0x01, 0x00, // error-index: 0
	)
	getReq = append(getReq, varBindings...)

	bodyLen := len(version) + len(comm) + len(getReq)
	body := append(version, comm...)
	body = append(body, getReq...)
	msg := append([]byte{0x30, byte(bodyLen)}, body...)
	return msg
}
