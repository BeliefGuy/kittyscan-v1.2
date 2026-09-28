package Plugins

import (
	"crypto/des"
	"encoding/binary"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"net"
	"strings"
	"sync"
	"time"
)

func VncScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	// -br（common.BruteThread）并发爆破：VNC 只有密码维度（{user} 恒替换为 "vnc"），
	// 预组装密码组合，顺序与原 for 循环一致。
	type vncCombo struct{ pass string }
	var combos []vncCombo
	for _, pass := range common.Passwords {
		pass = strings.Replace(pass, "{user}", "vnc", -1)
		combos = append(combos, vncCombo{pass})
	}
	if len(combos) == 0 {
		return tmperr
	}

	// worker 数；common.BruteThread 默认 1
	workers := common.BruteThread
	if workers < 1 {
		workers = 1
	}
	// 预算：沿用原公式（密码字典数 × BruteTimeout2 秒），只按 worker 数摊薄；
	// workers=1 时与原表达式一致。
	budget := int64(len(common.Passwords)) * common.BruteTimeout2 / int64(workers)

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
	jobs := make(chan vncCombo, len(combos))
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
				flag, err := VncConn(info, c.pass)
				mu.Lock()
				if stopped {
					// 终态之后到达的结果静默丢弃（br=1 单 worker 时不会走到这里）
					mu.Unlock()
					return
				}
				if flag && err == nil {
					// [vul] 由 VncConn 内部输出，这里不再重复打印（保持日志模板与次数不变）
					found = true
					sucErr = err
					signalStop()
					mu.Unlock()
					return
				}
				// 认证结果非 0（凭据被拒）时 err==nil，避免日志打出 <nil>；err 非空时照旧打印真实错误
				errMsg := "auth rejected"
				if err != nil {
					errMsg = err.Error()
				}
				errlog := fmt.Sprintf("[-] vnc %v:%v %v %v", info.Host, info.Ports, c.pass, errMsg)
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

func VncConn(info *common.HostInfo, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := net.DialTimeout("tcp", realhost, time.Duration(common.BruteTimeout2)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(common.BruteTimeout2) * time.Second))

	// 读取 RFB 版本 (12 bytes, e.g. "RFB 003.008\n")
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return
	}

	// 解析 RFB 版本："RFB 003.008" 下标 4-6 是主版本 "003"，下标 8-10 才是次版本 "008"。
	// 原实现判 [6]=='0'&&[7]=='0'&&[8]=='3'，而 [6] 实际是 '3'，条件永不成立 → minorVer 恒为 8
	// → 3.3 分支不可达，RFB 3.3 目标被按 3.7 流程解析而漏报。这里按下标 4-6/8-10 正确解析。
	rfbVersion := string(buf[:11]) // "RFB 003.008" or "RFB 003.007"
	minorVer := 8
	if len(rfbVersion) >= 11 && rfbVersion[4] == '0' && rfbVersion[5] == '0' && rfbVersion[6] == '3' {
		switch rfbVersion[8:11] {
		case "003":
			minorVer = 3
		case "004":
			minorVer = 4
		case "005":
			minorVer = 5
		case "006":
			minorVer = 6
		case "007":
			minorVer = 7
		default:
			minorVer = 8
		}
	}

	// 发送协商版本：回显服务端提供的版本行（补规范的 '\n' 结尾）。
	// 原固定回发 "RFB 003.008\n"：3.3 服务端会再回一次 "RFB 003.003\n"，本端不重读版本行，
	// 后续把这 12 字节当安全类型解析必然错位；回显则协商版本与上面 minorVer 的解析结果一致。
	version := make([]byte, 12)
	copy(version, buf[:11])
	version[11] = '\n'
	_, err = conn.Write(version)
	if err != nil {
		return
	}

	// 根据版本处理安全类型
	if minorVer >= 7 {
		// RFB 3.7+: 客户端先发 SecurityTypes 支持列表
		// 读取服务端支持的安全类型数量
		n, err = conn.Read(buf[:1])
		if err != nil || n < 1 {
			return
		}
		numTypes := int(buf[0])
		if numTypes == 0 {
			// 服务端拒绝，读取原因
			readVNCReason(conn, buf)
			return
		}
		// 读取安全类型列表
		if numTypes > 32 {
			numTypes = 32 // 限制
		}
		n, err = conn.Read(buf[:numTypes])
		if err != nil || n < numTypes {
			return
		}

		// 查找 VNC 认证 (type 2)
		hasVNC := false
		for i := 0; i < numTypes; i++ {
			if buf[i] == 2 {
				hasVNC = true
				break
			}
		}
		if !hasVNC {
			return // 不支持 VNC 认证
		}

		// 选择 VNC 认证 (type 2)
		_, err = conn.Write([]byte{2})
		if err != nil {
			return
		}
	} else {
		// RFB 3.3: 规范规定服务端直接发送 4 字节（U32 大端）安全类型，
		// 没有数量前缀、也不是类型列表。原实现按 1 字节当"数量"读，3.3 服务端发的
		// 00 00 00 02 首字节恒为 0x00 → numTypes=0 → 被当成拒绝直接返回，密码爆破永不发起（漏报）。
		n, err = conn.Read(buf[:4])
		if err != nil || n < 4 {
			return
		}
		secType := binary.BigEndian.Uint32(buf[:4])
		if secType == 0 {
			// 认证被拒绝，读取原因
			readVNCReason(conn, buf)
			return
		}
		if secType != 2 {
			// 服务端未提供 VNC 认证（如 None/无密码），无法进行口令爆破
			return
		}
		// secType == 2（VNC authentication）：3.3 客户端无需选择，服务端直接发送 16 字节 challenge
	}

	// 读取挑战 (16 bytes)
	n, err = conn.Read(buf[:16])
	if err != nil || n < 16 {
		return
	}
	challenge := make([]byte, 16)
	copy(challenge, buf[:16])

	// DES 加密挑战
	encrypted := vncEncrypt(challenge, pass)

	// 发送响应
	_, err = conn.Write(encrypted)
	if err != nil {
		return
	}

	// 读取认证结果 (4 bytes, 0=success, 1=failed)
	n, err = conn.Read(buf[:4])
	if err != nil || n < 4 {
		return
	}
	result := binary.BigEndian.Uint32(buf[:4])
	if result == 0 {
		flag = true
		rlt := fmt.Sprintf("[vul] Vnc %v:%v %v", info.Host, info.Ports, pass)
		common.LogSuccess(rlt)
	} else {
		// 认证失败，RFB 3.8+ 会发送原因字符串
		if minorVer >= 8 {
			readVNCReason(conn, buf)
		}
	}
	return
}

// readVNCReason 读取 VNC 服务端拒绝/失败原因
func readVNCReason(conn net.Conn, buf []byte) {
	n, err := conn.Read(buf[:4])
	if err != nil || n < 4 {
		return
	}
	reasonLen := binary.BigEndian.Uint32(buf[:4])
	if reasonLen > 0 && reasonLen < 256 {
		reasonBuf := make([]byte, reasonLen)
		conn.Read(reasonBuf)
	}
}

func vncEncrypt(challenge []byte, password string) []byte {
	// 密码不足8字节补零，超过截断
	key := make([]byte, 8)
	copy(key, []byte(password))

	// 每个字节做位反转
	for i := range key {
		key[i] = reverseByte(key[i])
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return make([]byte, 16)
	}

	result := make([]byte, 16)
	for i := 0; i < 16; i += 8 {
		block.Encrypt(result[i:i+8], challenge[i:i+8])
	}
	return result
}

func reverseByte(b byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		result = (result << 1) | (b & 1)
		b >>= 1
	}
	return result
}
