package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"strings"
	"sync"
	"time"
)

func TelnetScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	// -br（common.BruteThread）并发爆破：预组装 user×pass 组合，顺序与原双重 for 循环完全一致
	// （user 主序、password 次序），并保留 {user} 占位符替换语义。
	type telnetCombo struct{ user, pass string }
	var combos []telnetCombo
	for _, user := range common.Userdict["telnet"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			combos = append(combos, telnetCombo{user, pass})
		}
	}
	if len(combos) == 0 {
		return tmperr
	}

	// worker 数；common.BruteThread 默认 1
	workers := common.BruteThread
	if workers < 1 {
		workers = 1
	}
	// 预算：沿用原公式（字典全组合数 × BruteTimeout2 秒），只按 worker 数摊薄；
	// workers=1 时与原表达式一致。
	budget := int64(len(common.Userdict["telnet"])*len(common.Passwords)) * common.BruteTimeout2 / int64(workers)

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
	jobs := make(chan telnetCombo, len(combos))
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
				flag, err := TelnetConn(info, c.user, c.pass)
				mu.Lock()
				if stopped {
					// 终态之后到达的结果静默丢弃（br=1 单 worker 时不会走到这里）
					mu.Unlock()
					return
				}
				if flag && err == nil {
					// [vul] 由 TelnetConn 内部输出，这里不再重复打印（保持日志模板与次数不变）
					found = true
					sucErr = err
					signalStop()
					mu.Unlock()
					return
				}
				errlog := fmt.Sprintf("[-] telnet %v:%v %v %v %v", info.Host, info.Ports, c.user, c.pass, err)
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

func TelnetConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(common.BruteTimeout2)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(common.BruteTimeout2) * time.Second))

	// 读取 banner（login prompt）
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	banner := string(buf[:n])

	// 检查是否是 Telnet 服务（应该包含 login 相关提示）
	bannerLower := strings.ToLower(banner)
	if !strings.Contains(bannerLower, "login") && !strings.Contains(bannerLower, "username") &&
		!strings.Contains(bannerLower, "user") && !strings.Contains(bannerLower, "password") {
		// 不是标准 Telnet 登录服务，跳过
		return
	}

	// 发送用户名
	_, err = conn.Write([]byte(user + "\r\n"))
	if err != nil {
		return
	}
	time.Sleep(300 * time.Millisecond)
	conn.Read(buf)

	// 发送密码
	_, err = conn.Write([]byte(pass + "\r\n"))
	if err != nil {
		return
	}
	time.Sleep(500 * time.Millisecond)

	// 读取登录结果
	n, err = conn.Read(buf)
	if err != nil {
		return
	}
	reply := string(buf[:n])

	// 如果响应为空或只有空白字符，判定为失败（避免空响应误报）
	trimmedReply := strings.TrimSpace(reply)
	if trimmedReply == "" {
		return
	}

	// 取“最后一个非空行”（先剥离尾部空白/NUL/CR/LF，再按行切分），用于
	// “登录提示重发”与“行尾 shell 提示符”判定。
	lastLine := ""
	if trimmed := strings.TrimRight(reply, "\x00\r\n \t"); trimmed != "" {
		if idx := strings.LastIndexAny(trimmed, "\r\n"); idx >= 0 {
			lastLine = trimmed[idx+1:]
		} else {
			lastLine = trimmed
		}
	}
	lastLine = strings.TrimSpace(lastLine)
	lastLineLower := strings.ToLower(lastLine)

	// 明确的失败关键词（优先检查，命中即判失败——先于一切成功判定）
	failKeywords := []string{
		"login failed", "login incorrect", "login failure",
		"incorrect password", "invalid password", "wrong password",
		"authentication failed", "auth failed",
		"access denied", "permission denied",
		"bad password", "failed",
		// 扩充：覆盖常见失败回显（"unsuccessful" 必须先于成功词 "successful" 命中，
		// 否则 "Login unsuccessful" 会被 "successful" 子串误判成功）
		"incorrect", "invalid", "authentication failure",
		"unsuccessful", "not authorized", "authorization failed",
		"denied", "try again",
	}
	replyLower := strings.ToLower(reply)
	for _, kw := range failKeywords {
		if strings.Contains(replyLower, kw) {
			return // 明确失败
		}
	}
	// 登录提示被原样重发（末行是 login:/password:/username: 形式的提示）= 认证未通过；
	// 要求以 ":" 结尾，避免误伤 "Login successful" 之类以 login 开头的成功消息
	if strings.HasSuffix(lastLineLower, ":") &&
		(strings.HasPrefix(lastLineLower, "login") || strings.HasPrefix(lastLineLower, "password") ||
			strings.HasPrefix(lastLineLower, "username") || strings.HasPrefix(lastLineLower, "user name")) {
		return
	}

	// 正向检测成功标志（保持原判定的强成功消息，并改为大小写不敏感：
	// 真实回显多为 "Last login:"/"Welcome"，原实现按小写子串匹配会漏掉，避免漏报）
	successIndicators := []string{
		"welcome", "last login", "successful", // 成功消息
		"root@", "admin@", // 带用户名的提示符（成功登录后才会出现在回复里）
	}
	success := false
	for _, indicator := range successIndicators {
		if strings.Contains(replyLower, indicator) {
			success = true
			break
		}
	}
	// 收紧："$ # > %" 不再按“回复任意位置包含”判定（含 > 或 % 的失败/错误消息会误报），
	// 改为要求提示符位于“最后一个非空行的行尾”（登录后的稳定 shell 态）。
	// 真实成功提示符（root@host:~# / admin> / $ / C:\Users\>）仍命中。
	if !success {
		success = isTelnetShellPrompt(lastLine)
	}
	if success {
		flag = true
		result := fmt.Sprintf("[vul] Telnet %v:%v:%v %v", info.Host, info.Ports, user, pass)
		common.LogSuccess(result)
		return
	}

	// 如果没有明确的成功或失败标志，判定为失败（保守策略）
	// 只有当响应中确实包含成功标志时才报告漏洞
	return
}

// isTelnetShellPrompt 判断“最后一行”是否是登录成功后的 shell 提示符：
// 提示符字符必须位于该行行尾、整行较短（真实提示符都很短），
// 并排除以 < 或 - 开头的 XML/HTML 片段（</response>）与注释（-->）等以 > 结尾的普通文本。
func isTelnetShellPrompt(line string) bool {
	line = strings.TrimRight(line, "\x00\x01\x02\x03\x04\x05\x06\x07\b\f\v\r")
	if line == "" {
		return false
	}
	last := line[len(line)-1]
	if last != '$' && last != '#' && last != '>' && last != '%' {
		return false // 提示符必须位于行尾
	}
	if len(line) == 1 {
		return true // 纯提示符：$ # > %
	}
	if len(line) > 64 {
		return false // 过长的行是普通文本，不是提示符
	}
	if line[0] == '<' || line[0] == '-' {
		return false // </tag>、--> 之类
	}
	return true
}
