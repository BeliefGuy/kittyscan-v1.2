package Plugins

import (
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"golang.org/x/crypto/md4"
	"net"
	"strings"
	"sync"
	"time"
)

func RsyncScan(info *common.HostInfo) (tmperr error) {
	// 未授权检测
	flag, _ := RsyncUnauth(info)
	if flag {
		return
	}
	if common.IsBrute {
		return
	}
	// -br 并发爆破：先按原语义组装 {user} 替换后的组合列表（user 主序、pass 次序与原双重循环一致）；
	// 上面的未授权检测与 IsBrute 判断保持串行原位不动。
	type combo struct{ user, pass string }
	var combos []combo
	for _, user := range common.Userdict["rsync"] {
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
				// RsyncConn 内部的三段握手/MD4/MD5 认证协议逻辑一字未动
				flag, err := RsyncConn(info, c.user, c.pass)
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
				// 失败日志与原 else 分支逐字一致（err 可能为 nil，无条件打印）
				common.LogError(fmt.Sprintf("[-] rsync %v:%v %v %v %v", info.Host, info.Ports, c.user, c.pass, err))
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

func RsyncUnauth(info *common.HostInfo) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := net.DialTimeout("tcp", realhost, time.Duration(common.BruteTimeout2)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(common.BruteTimeout2) * time.Second))

	// Rsync 协议握手：客户端问候 @RSYNCD <协议版本>（rsync 3.1.0 客户端实发 "@RSYNCD: 31.0"）
	_, err = conn.Write([]byte("@RSYNCD: 31.0\n"))
	if err != nil {
		return
	}

	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	if err != nil || n == 0 {
		return
	}

	// 检查是否是 RSYNCD 响应（协议握手）
	if !strings.Contains(string(reply[:n]), "RSYNCD") {
		return // 不是 Rsync 服务
	}

	// 请求模块列表（发送空行）
	_, err = conn.Write([]byte("\n"))
	if err != nil {
		return
	}

	// 读取模块列表：读到 "@RSYNCD: EXIT"/"@ERROR" 或达到次数上限为止；
	// 读循环有次数上限且受连接 deadline 约束，不会卡死
	var lastErr error
	moduleList := ""
	for i := 0; i < 8; i++ {
		n, rerr := conn.Read(reply)
		if n > 0 {
			moduleList += string(reply[:n])
			if strings.Contains(moduleList, "@RSYNCD: EXIT") || strings.Contains(moduleList, "@ERROR") {
				break
			}
		}
		if rerr != nil {
			lastErr = rerr
			break
		}
	}
	if moduleList == "" {
		err = lastErr
		return
	}

	// 提取模块名（列表行格式为 "名字<填充>\t注释"，MOTD 等非模块行无制表符自然被过滤），
	// 最多探测 3 个：模块名列表本身是公开的，只有“不带口令即可进入模块”才算未授权，
	// 避免把需要口令的模块误报为 unauthorized
	var modules []string
	for _, line := range strings.Split(moduleList, "\n") {
		if idx := strings.Index(line, "\t"); idx > 0 {
			name := strings.TrimSpace(line[:idx])
			if name != "" && !strings.HasPrefix(name, "@") {
				modules = append(modules, name)
				if len(modules) >= 3 {
					break
				}
			}
		}
	}
	for _, mod := range modules {
		open, _ := rsyncModuleOpen(realhost, mod)
		if open {
			flag = true
			result := fmt.Sprintf("[vul] Rsync %s:%v unauthorized", info.Host, info.Ports)
			common.LogSuccess(result)
			return
		}
	}

	return
}

// rsyncModuleOpen 探测某模块是否无需口令即可进入（真实未授权访问）。
// 每次探测独立连接走真实协议：问候 → 模块名 → 判定应答
// （"@RSYNCD: OK"=开放；AUTHREQD=需口令认证；@ERROR=不可用/拒绝）。
// 读循环有次数上限且受 deadline 约束，不会卡死。
func rsyncModuleOpen(realhost, module string) (open bool, err error) {
	conn, err := net.DialTimeout("tcp", realhost, time.Duration(common.BruteTimeout2)*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(common.BruteTimeout2) * time.Second))

	if _, err = conn.Write([]byte("@RSYNCD: 31.0\n")); err != nil {
		return false, err
	}
	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	if err != nil || n == 0 || !strings.Contains(string(reply[:n]), "RSYNCD") {
		return false, err
	}
	if _, err = conn.Write([]byte(module + "\n")); err != nil {
		return false, err
	}
	for i := 0; i < 5; i++ {
		n, err = conn.Read(reply)
		if err != nil || n == 0 {
			return false, err
		}
		line := string(reply[:n])
		if strings.Contains(line, "@RSYNCD: OK") || strings.Contains(line, "@RSYNCD OK") {
			return true, nil
		}
		if strings.Contains(line, "AUTHREQD") || strings.Contains(line, "@ERROR") {
			return false, nil
		}
		// 其他行（如 MOTD），继续读
	}
	return false, nil
}

func RsyncConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := net.DialTimeout("tcp", realhost, time.Duration(common.BruteTimeout2)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(common.BruteTimeout2) * time.Second))

	// Rsync 协议握手：客户端问候 @RSYNCD <协议版本>，rsync 3.1.0 客户端实发 "@RSYNCD: 31.0"
	_, err = conn.Write([]byte("@RSYNCD: 31.0\n"))
	if err != nil {
		return
	}

	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	if err != nil || n == 0 {
		return
	}

	// 检查是否是 RSYNCD 响应
	greeting := string(reply[:n])
	if !strings.Contains(greeting, "RSYNCD") {
		return
	}

	// digest 选择（rsync 协议既定规则，MD4/MD5 两条路径都可用）：
	// 1) 服务端问候声明 digest 列表（rsync>=3.2.7，形如 "@RSYNCD: 31.0 sha512 sha256 sha1 md4 md5"）：
	//    按列表选择，列表含 md5（3.2.7 起内置）时按协议对未声明列表的 30/31 客户端用 MD5 校验；
	// 2) 未声明列表（rsync<=3.2.6，协议 30/31 及更早版本）：认证摘要固定为 MD4。
	firstLine := greeting
	if idx := strings.IndexAny(greeting, "\r\n"); idx >= 0 {
		firstLine = greeting[:idx]
	}
	fields := strings.Fields(firstLine)
	useMD5 := false
	if len(fields) > 2 { // 版本字段之外还有令牌 → 服务端声明了 digest 列表
		for _, d := range fields[2:] {
			if d == "md5" {
				useMD5 = true
				break
			}
		}
	}

	// 模块选择行：真实协议此处发送模块名（原实现发非标准的 "@AUTH_REQ user"，任何 rsyncd 均回 @ERROR）
	_, err = conn.Write([]byte(user + "\n"))
	if err != nil {
		return
	}

	// 读取服务端应答（可能夹杂 MOTD 行）：AUTHREQD 携带 challenge；
	// 读循环有次数上限且受连接 deadline 约束，不会卡死
	challenge := ""
	authed := false
	for i := 0; i < 5; i++ {
		n, err = conn.Read(reply)
		if err != nil || n == 0 {
			return
		}
		line := string(reply[:n])
		if idx := strings.Index(line, "AUTHREQD"); idx >= 0 {
			// "@RSYNCD: AUTHREQD <challenge>"（兼容不带冒号的变体）
			challenge = strings.TrimSpace(line[idx+len("AUTHREQD"):])
			if challenge == "" {
				return
			}
			authed = true
			break
		}
		if strings.Contains(line, "@RSYNCD: OK") || strings.Contains(line, "@RSYNCD OK") {
			// 模块无需口令直接放行：未经过口令校验，判失败（未授权访问由 RsyncUnauth 上报）
			return
		}
		if idx := strings.Index(line, "@ERROR"); idx >= 0 {
			// 如 "@ERROR: Unknown module 'x'"（模块不存在）等，带原文返回 err，
			// 由现有 [-] 日志打印，区分“模块名不对”与“密码错误”
			msg := line[idx:]
			if j := strings.IndexAny(msg, "\r\n"); j >= 0 {
				msg = msg[:j]
			}
			err = errors.New(msg)
			return
		}
		// 其他行（如 MOTD），继续读
	}
	if !authed {
		return
	}

	// 按 rsync AUTH 协议用口令计算挑战应答并发送：<user> <base64(digest(口令+challenge))>
	_, err = conn.Write([]byte(rsyncAuthResponse(user, pass, challenge, useMD5) + "\n"))
	if err != nil {
		return
	}

	// 成功判定：服务端校验该口令的应答通过后回 "@RSYNCD: OK"；口令错误回 "@ERROR: auth failed ..."
	for i := 0; i < 3; i++ {
		n, err = conn.Read(reply)
		if err != nil || n == 0 {
			return
		}
		line := strings.TrimSpace(string(reply[:n]))
		if line == "@RSYNCD: OK" || line == "@RSYNCD OK" {
			flag = true
			result := fmt.Sprintf("[vul] Rsync %v:%v:%v %v", info.Host, info.Ports, user, pass)
			common.LogSuccess(result)
			return
		}
		if idx := strings.Index(line, "@ERROR"); idx >= 0 {
			// 口令校验失败：如 "@ERROR: auth failed on module 'x'"，带原文返回 err，
			// 由现有 [-] 日志打印，与“模块不存在”类错误区分
			msg := line[idx:]
			if j := strings.IndexAny(msg, "\r\n"); j >= 0 {
				msg = msg[:j]
			}
			err = errors.New(msg)
			return
		}
		// 其他行，继续读
	}
	return
}

// rsyncAuthResponse 计算 rsync 挑战应答：digest(口令 + challenge) 的标准 Base64（无填充），
// 与 rsync 源码 generate_hash(pass, challenge) 一致（先 sum_update(pass) 再 sum_update(challenge)，
// base64 pad=0）。useMD5=true 走 MD5（rsync>=3.2.7），否则走 MD4（rsync<=3.2.6）。
// 返回单行应答 "<user> <response>"。
func rsyncAuthResponse(user, pass, challenge string, useMD5 bool) string {
	input := []byte(pass + challenge)
	var sum []byte
	if useMD5 {
		h := md5.New()
		h.Write(input)
		sum = h.Sum(nil)
	} else {
		h := md4.New()
		h.Write(input)
		sum = h.Sum(nil)
	}
	return user + " " + base64.RawStdEncoding.EncodeToString(sum)
}
