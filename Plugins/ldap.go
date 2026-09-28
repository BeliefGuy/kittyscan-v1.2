package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"strings"
	"sync"
	"time"
)

func LdapScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	// -br 并发爆破：先把字典组装成组合列表，user 主序、pass 次序与原双重 for 循环完全一致，
	// {user} 替换语义不变；组合为空直接返回，与原循环不执行等价。
	type combo struct{ user, pass string }
	var combos []combo
	for _, user := range common.Userdict["ldap"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			combos = append(combos, combo{user, pass})
		}
	}
	if len(combos) == 0 {
		return tmperr
	}
	workers := common.BruteThread
	if workers < 1 {
		workers = 1
	}
	// 共享状态全部由 mu 保护；closed 保证 close(stop) 只执行一次（防重复 close panic）
	var (
		mu     sync.Mutex
		found  bool
		closed bool
		stop   = make(chan struct{})
	)
	start := time.Now()
	// 预算沿用原公式：组合数 × BruteTimeout2 秒，只按 worker 数摊薄
	budget := time.Duration(len(combos)) * time.Duration(common.BruteTimeout2) * time.Second / time.Duration(workers)
	// 预填充有缓冲 channel：容量=组合数，投递不阻塞、worker 提前退出也不会死锁
	jobs := make(chan combo, len(combos))
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
				select { // 已有结果/致命错误，立即退出
				case <-stop:
					return
				default:
				}
				if time.Since(start) > budget { // 预算兜底
					return
				}
				flag, err := LdapConn(info, c.user, c.pass)
				mu.Lock()
				if flag && err == nil {
					if !found {
						found = true
						tmperr = nil // 成功返回 nil，与原 return err(err==nil) 一致
						if !closed {
							closed = true
							close(stop)
						}
					}
					mu.Unlock()
					return
				}
				if found || closed { // 已有结果，抑制在途尝试的多余 [-] 日志
					mu.Unlock()
					return
				}
				// Bind 被拒（服务端拒绝凭据）而 err==nil 时，避免日志打出 <nil>；格式串与字段不变
				errMsg := "bind rejected"
				if err != nil {
					errMsg = err.Error()
				}
				common.LogError(fmt.Sprintf("[-] ldap %v:%v %v %v %v", info.Host, info.Ports, c.user, c.pass, errMsg))
				tmperr = err
				if common.CheckErrs(err) {
					if !closed {
						closed = true
						close(stop)
					}
					mu.Unlock()
					return
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return tmperr
}

func LdapConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	// 使用 net 包进行 LDAP 绑定测试
	conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(common.BruteTimeout2)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(common.BruteTimeout2) * time.Second))

	// LDAP Bind Request (简单认证)
	// 构造 LDAP BindRequest 包
	dn := fmt.Sprintf("cn=%s", user)
	if strings.Contains(user, "\\") {
		dn = user
	}
	bindRequest := buildLdapBindRequest(dn, pass)

	_, err = conn.Write(bindRequest)
	if err != nil {
		return
	}

	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	if err != nil || n < 7 {
		return
	}

	// 检查 LDAP Bind Response（BER 解析）
	// 报文结构：30 <len> 02 01 01 61 <len> 0A 01 00 ...，0x61 = BindResponse，resultCode 0 = success
	// 不写死下标：长度字段支持长短格式，越界或长度异常返回 false，不会 panic
	if ldapBindSuccess(reply[:n]) {
		flag = true
		result := fmt.Sprintf("[vul] LDAP %v:%v:%v %v", info.Host, info.Ports, user, pass)
		common.LogSuccess(result)
	}
	return
}

// buildLdapBindRequest 构造 LDAP Simple Bind 请求
func buildLdapBindRequest(dn, password string) []byte {
	dnBytes := []byte(dn)
	passBytes := []byte(password)

	// LDAP Message = [tag 0x30] [length] [messageID] [BindRequest]
	// BindRequest = [tag 0x60] [length] [version] [name] [authentication]

	version := []byte{0x02, 0x01, 0x03} // version 3
	name := append([]byte{0x04, byte(len(dnBytes))}, dnBytes...)
	auth := append([]byte{0x80, byte(len(passBytes))}, passBytes...)

	bindReq := append([]byte{0x60, byte(len(version)+len(name)+len(auth))}, version...)
	bindReq = append(bindReq, name...)
	bindReq = append(bindReq, auth...)

	msgID := []byte{0x02, 0x01, 0x01} // messageID = 1
	msgLen := len(msgID) + len(bindReq)
	msg := append([]byte{0x30, byte(msgLen)}, msgID...)
	msg = append(msg, bindReq...)

	return msg
}

// berLen 解析 BER 长度字段（b[pos] 为长度首字节），返回内容起始下标与内容长度。
// 短格式(0x00-0x7F)与长格式(0x81-0x84)均支持；不定长(0x80)、越界或溢出一律返回 ok=false。
func berLen(b []byte, pos int) (start int, length int, ok bool) {
	if pos < 0 || pos >= len(b) {
		return 0, 0, false
	}
	first := int(b[pos])
	pos++
	if first < 0x80 {
		length = first
	} else {
		num := first & 0x7f
		if num == 0 || num > 4 || pos+num > len(b) {
			return 0, 0, false
		}
		for i := 0; i < num; i++ {
			length = length<<8 | int(b[pos+i])
		}
		pos += num
	}
	if length < 0 || pos+length > len(b) {
		return 0, 0, false
	}
	return pos, length, true
}

// ldapBindSuccess 按 BER 结构解析 LDAP BindResponse，判断 resultCode 是否为 success(0)。
// 结构：LDAPMessage(0x30) = SEQUENCE{ messageID(0x02), BindResponse(0x61) }，
// BindResponse = SEQUENCE{ resultCode ENUMERATED(0x0A), matchedDN, diagnosticMessage }。
// 每步取值前都先校验长度，输入任意长度都不会越界 panic，异常返回 false。
func ldapBindSuccess(b []byte) bool {
	// 外层 LDAPMessage SEQUENCE
	if len(b) < 2 || b[0] != 0x30 {
		return false
	}
	msgStart, msgLen, ok := berLen(b, 1)
	if !ok || msgLen < 2 {
		return false
	}
	msg := b[msgStart : msgStart+msgLen]
	// messageID INTEGER
	if msg[0] != 0x02 {
		return false
	}
	idStart, idLen, ok := berLen(msg, 1)
	if !ok {
		return false
	}
	body := msg[idStart+idLen:]
	// BindResponse APPLICATION 1
	if len(body) < 2 || body[0] != 0x61 {
		return false
	}
	respStart, respLen, ok := berLen(body, 1)
	if !ok {
		return false
	}
	resp := body[respStart : respStart+respLen]
	// resultCode ENUMERATED，success = 0
	if len(resp) < 1 || resp[0] != 0x0a {
		return false
	}
	codeStart, codeLen, ok := berLen(resp, 1)
	if !ok || codeLen < 1 {
		return false
	}
	return resp[codeStart] == 0x00
}
