package common

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode/utf16"
)

func Parse(Info *HostInfo) {
	ParseUser()
	ParsePass(Info)
	ParseInput(Info)
	ParseScantype(Info)
	// -m finger / -m fingeronly 属于纯指纹模式: 只做 webtitle + 指纹识别,
	// 强制关闭 web POC 扫描与密码爆破, 避免对目标发起漏洞验证请求。
	if Scantype == "finger" || Scantype == "fingeronly" {
		NoPoc = true
		IsBrute = false
		if !Silent {
			fmt.Println("[*] finger mode: 仅做webtitle与指纹识别, 已跳过POC扫描与密码爆破")
		}
	}
}

func ParseUser() {
	if Username == "" && Userfile == "" {
		return
	}
	var Usernames []string
	if Username != "" {
		for _, user := range strings.Split(Username, ",") {
			// L3: 拆分后统一 trim 并丢弃空串, 与 Readfile 路径行为一致
			// (旧实现 "admin, test" 会得到 " test", "admin," 会产生空用户名)
			if user = strings.TrimSpace(user); user != "" {
				Usernames = append(Usernames, user)
			}
		}
	}

	if Userfile != "" {
		users, err := Readfile(Userfile)
		if err == nil {
			for _, user := range users {
				if user != "" {
					Usernames = append(Usernames, user)
				}
			}
		}
	}

	Usernames = RemoveDuplicate(Usernames)
	for name := range Userdict {
		Userdict[name] = Usernames
	}
}

func ParsePass(Info *HostInfo) {
	var PwdList []string
	if Password != "" {
		passs := strings.Split(Password, ",")
		for _, pass := range passs {
			// L3: 拆分后统一 trim 并丢弃空串, 与 Readfile 路径行为一致
			if pass = strings.TrimSpace(pass); pass != "" {
				PwdList = append(PwdList, pass)
			}
		}
		Passwords = PwdList
	}
	if Passfile != "" {
		passs, err := Readfile(Passfile)
		if err == nil {
			for _, pass := range passs {
				if pass != "" {
					PwdList = append(PwdList, pass)
				}
			}
			Passwords = PwdList
		}
	}
	// L4: -u 与 -uf 合并进同一个去重集合(以当前 Urls 为种子), 跨来源去重,
	// 避免同一 URL 在 -u 和 -uf 同时出现时被扫描两遍
	mergedUrls := make(map[string]struct{}, len(Urls))
	for _, u := range Urls {
		mergedUrls[u] = struct{}{}
	}
	if URL != "" {
		urls := strings.Split(URL, ",")
		for _, u := range urls {
			if u == "" {
				continue
			}
			if _, ok := mergedUrls[u]; !ok {
				mergedUrls[u] = struct{}{}
				Urls = append(Urls, u)
			}
		}
	}
	if UrlFile != "" {
		urls, err := Readfile(UrlFile)
		if err == nil {
			for _, u := range urls {
				if u == "" {
					continue
				}
				if _, ok := mergedUrls[u]; !ok {
					mergedUrls[u] = struct{}{}
					Urls = append(Urls, u)
				}
			}
		}
	}
	if PortFile != "" {
		ports, err := Readfile(PortFile)
		if err == nil {
			newport := ""
			for _, port := range ports {
				if port != "" {
					newport += port + ","
				}
			}
			// L5: 空文件/全非法行时 newport 为空或只含非法项, 直接赋给 Ports 会让
			// 后续解析出空端口集 → 静默 0/0 空扫。复用 ParsePort 做校验:
			// 非法项由 ParsePort 自己报错退出, 这里只兜"解析结果为空"的情况,
			// 明确报错并以退出码 1 终止(与 L2 的用法错误退出码语义一致)。
			if len(ParsePort(newport)) == 0 {
				fmt.Printf("[-] -portf %s: no valid port parsed (file is empty or contains only invalid lines)\n", PortFile)
				os.Exit(1)
			}
			Ports = newport
		}
	}
}

func Readfile(filename string) ([]string, error) {
	return readTextLines(filename), nil
}

// readTextLines 读取文本文件并按行返回(trim 过、去掉空行), 与旧的
// bufio.Scanner 逐行读取行为一致。读取后统一做编码规整(L6):
// (a) 剥离 UTF-8 BOM; (b) 探测 UTF-16 LE/BE BOM 并整段转码为 UTF-8。
// 打开失败或转码失败都打印明确错误并以退出码 1 终止, 不静默返回坏数据
// (调用方普遍忽略返回的 error, 静默返回会导致凭据/IP 解析失败与 0/0 空扫)。
func readTextLines(filename string) []string {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		os.Exit(1)
	}
	text, err := decodeTextBytes(data)
	if err != nil {
		fmt.Printf("[-] read %s error: %v\n", filename, err)
		os.Exit(1)
	}
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// decodeTextBytes 把文件原始字节规整为 UTF-8 文本:
// UTF-16 LE(BOM: FF FE) / UTF-16 BE(BOM: FE FF) 整段转码为 UTF-8,
// UTF-8 BOM(EF BB BF) 剥离, 其余按原样当作 UTF-8 文本。
// 无 BOM 的 UTF-16 不做启发式猜测(超出本项修复范围), 与旧实现一致。
func decodeTextBytes(data []byte) (string, error) {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return decodeUTF16(data[2:], binary.LittleEndian)
	}
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return decodeUTF16(data[2:], binary.BigEndian)
	}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	return string(data), nil
}

// decodeUTF16 将 UTF-16 字节流(已去掉 BOM)按 order 解码为 UTF-8 字符串。
// 奇数字节长、孤立/未配对代理项都视为转码失败并返回错误, 由调用方报错退出。
// 仅用标准库 unicode/utf16, 不引入新依赖。
func decodeUTF16(data []byte, order binary.ByteOrder) (string, error) {
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
		case u >= 0xD800 && u <= 0xDBFF: // 高代理项, 后面必须紧跟低代理项
			if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
				return "", fmt.Errorf("UTF-16 decode failed: unpaired surrogate 0x%04X at unit %d", u, i)
			}
			runes = append(runes, utf16.DecodeRune(rune(u), rune(units[i+1])))
			i++
		case u >= 0xDC00 && u <= 0xDFFF: // 孤立低代理项
			return "", fmt.Errorf("UTF-16 decode failed: unpaired surrogate 0x%04X at unit %d", u, i)
		default:
			runes = append(runes, rune(u))
		}
	}
	return string(runes), nil
}

func ParseInput(Info *HostInfo) {
	if Info.Host == "" && HostFile == "" && URL == "" && UrlFile == "" {
		fmt.Println("Host is none")
		flag.Usage()
		os.Exit(1) // L2: 用法错误 → 退出码 1
	}

	if BruteThread <= 0 {
		BruteThread = 1
	}

	// 数值参数边界保护（参考 -br 的实现）
	if Threads <= 0 {
		Threads = 100
	}
	if PocNum <= 0 {
		PocNum = 20
	}
	if Timeout <= 0 {
		Timeout = 3
	}
	if WebTimeout <= 0 {
		WebTimeout = 5
	}

	if TmpSave == true {
		IsSave = false
	}

	// L7: -o 输出文件启动预检。WriteFile 对每条结果都会尝试打开输出文件,
	// 目录不存在时会逐条刷 "Open ... error", 扫完整个目标才发现结果全丢;
	// 这里在扫描开始前只打开一次确认可创建/可追加, 失败立即明确报错并
	// 以退出码 1 终止。-no(TmpSave) 已在上方把 IsSave 置 false、不写文件,
	// 因此条件为 IsSave 时预检自然跳过, 不会因 -no 误报。
	if IsSave {
		f, err := os.OpenFile(Outputfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("[-] Open output file %q error, %v\n", Outputfile, err)
			os.Exit(1)
		}
		f.Close()
	}

	if Ports == DefaultPorts {
		Ports += "," + Webport
	}

	if PortAdd != "" {
		if strings.HasSuffix(Ports, ",") {
			Ports += PortAdd
		} else {
			Ports += "," + PortAdd
		}
	}

	if UserAdd != "" {
		// L3: 拆分后统一 trim 并丢弃空串, 再并入 Userdict 并去重(语义与去重逻辑不变)
		var user []string
		for _, u := range strings.Split(UserAdd, ",") {
			if u = strings.TrimSpace(u); u != "" {
				user = append(user, u)
			}
		}
		for a := range Userdict {
			Userdict[a] = append(Userdict[a], user...)
			Userdict[a] = RemoveDuplicate(Userdict[a])
		}
	}

	if PassAdd != "" {
		// L3: 同上, trim 后丢弃空串, RemoveDuplicate 去重保持不变
		var pass []string
		for _, p := range strings.Split(PassAdd, ",") {
			if p = strings.TrimSpace(p); p != "" {
				pass = append(pass, p)
			}
		}
		Passwords = append(Passwords, pass...)
		Passwords = RemoveDuplicate(Passwords)
	}
	// 代理统一入口 -proxy(原 -socks5 已并入本参数, 按协议区分作用域):
	//   http://   → 仅 HTTP(Web/POC) 出口: 只设 http.Transport.Proxy,
	//               端口扫描/服务识别/爆破等 TCP 流量仍然直连(Socks5Proxy 留空)。
	//   socks5:// → 全局代理: Socks5Proxy=Proxy, 所有 WrapperTCP 拨号
	//               (proxy.go)与 HTTP 拨号层(client.go)都走代理, 并自动跳过 ICMP。
	if Proxy != "" {
		if Proxy == "1" {
			Proxy = "http://127.0.0.1:8080"
		} else if Proxy == "2" {
			Proxy = "socks5://127.0.0.1:1080"
		} else if !strings.Contains(Proxy, "://") {
			// 纯端口号 → 127.0.0.1:port; host:port → 直接补 http://。
			// 原实现无条件拼 "http://127.0.0.1:" , -proxy 127.0.0.1:8080 会拼成
			// http://127.0.0.1:127.0.0.1:8080 (非法地址), 与帮助文案示例不符, 此处修正。
			if strings.Contains(Proxy, ":") {
				Proxy = "http://" + Proxy
			} else {
				Proxy = "http://127.0.0.1:" + Proxy
			}
		}
		if !strings.HasPrefix(Proxy, "socks") && !strings.HasPrefix(Proxy, "http") {
			fmt.Println("no support this proxy")
			os.Exit(1) // L2: 用法错误 → 退出码 1
		}
		_, err := url.Parse(Proxy)
		if err != nil {
			fmt.Println("Proxy parse error:", err)
			os.Exit(1) // L2: 用法错误 → 退出码 1
		}
		if strings.HasPrefix(Proxy, "socks5://") {
			Socks5Proxy = Proxy
			NoPing = true // SOCKS5 链路上 ICMP 不可用, 与原 -socks5 行为一致
		} else if strings.HasPrefix(Proxy, "socks") {
			// 底层 Socks5Dailer 只认 socks5 方案, socks:// 等提前拦掉,
			// 否则要到拨号阶段才报 "Only support socks5"。
			fmt.Println("only socks5:// is supported for global proxy, e.g.: -proxy socks5://127.0.0.1:1080")
			os.Exit(1) // L2: 用法错误 → 退出码 1
		}
		// L1: 状态回显受 -silent 控制; 上方解析错误提示保持可见
		if !Silent {
			if Socks5Proxy != "" {
				fmt.Printf("Proxy: %s (全局代理: 端口/服务/爆破 + Web/POC)\n", Proxy)
			} else {
				fmt.Printf("Proxy: %s (仅HTTP出口: Web/POC)\n", Proxy)
			}
		}
	}

	// Redis反弹Shell格式校验
	if RedisShell != "" && !strings.Contains(RedisShell, ":") {
		fmt.Println("[-] RedisShell format error, must be host:port (e.g.: 192.168.1.1:6666)")
		os.Exit(1)
	}

	if Hash != "" && len(Hash) != 32 {
		fmt.Println("[-] Hash is error,len(hash) must be 32")
		os.Exit(1)
	} else if Hash != "" {
		var err error
		HashBytes, err = hex.DecodeString(Hash)
		if err != nil {
			fmt.Println("[-] Hash is error,hex decode error")
			os.Exit(1)
		}
	}
}

func ParseScantype(Info *HostInfo) {
	_, ok := PORTList[Scantype]
	if !ok {
		showmode()
	}
	// 端口收敛条件：用户显式 -p（UserSetPort，flag 解析后记录）或 -portf 指定端口文件时
	// 以用户端口为准、不做收敛；其余情况按模式收敛端口（-pa 追加的端口在收敛后补回）。
	// 旧实现用 Ports == DefaultPorts+","+Webport 精确比较，-pa 先拼进 Ports 会让比较恒为 false，
	// 导致 switch 整体被跳过（如 -m ssh -pa 3389 按全量端口扫描）。
	if Scantype != "all" && !UserSetPort && PortFile == "" {
		switch Scantype {
		case "wmiexec":
			Ports = "135"
		case "wmiinfo":
			Ports = "135"
		case "smbinfo":
			Ports = "445"
		case "hostname":
			Ports = "135,137,139,445"
		case "smb2":
			Ports = "445"
		case "web":
			Ports = Webport
		case "webonly":
			Ports = Webport
		// webpoc 此前没有 case, 会落 default 分支被收敛成哨兵值 1000003(端口集为空 -> 静默 0/0)
		case "webpoc":
			Ports = Webport
		case "finger":
			Ports = Webport
		case "fingeronly":
			Ports = Webport
		case "ms17010":
			Ports = "445"
		case "cve20200796":
			Ports = "445"
		case "portscan":
			Ports = DefaultPorts + "," + Webport
		case "main":
			Ports = DefaultPorts
		default:
			ports, ok := PortGroup[Scantype]
			if ok {
				Ports = ports
			} else {
				port, _ := PORTList[Scantype]
				Ports = strconv.Itoa(port)
			}
		}
		// 收敛后把 -pa 追加的端口并入（ParseInput 拼进旧 Ports 后此处已被收敛值覆盖）
		if PortAdd != "" {
			if strings.HasSuffix(Ports, ",") {
				Ports += PortAdd
			} else {
				Ports += "," + PortAdd
			}
		}
		// 只有存在 IP 目标(-h/-hf)时才会用到端口列表去扫描/探测。
		// 仅指定 -u/-uf 直接扫 URL 时不走端口流程, 不打印这行以免误导。
		if Info.Host != "" || HostFile != "" {
			// L1: 状态回显受 -silent 控制
			if !Silent {
				fmt.Println("-m ", Scantype, " start scan the port:", Ports)
			}
		}
	}
}

func CheckErr(text string, err error, flag bool) {
	if err != nil {
		fmt.Println("Parse", text, "error: ", err.Error())
		if flag {
			if err != ParseIPErr {
				fmt.Println(ParseIPErr)
			}
			os.Exit(1) // L2: 参数解析错误 → 退出码 1
		}
	}
}

func showmode() {
	fmt.Println("The specified scan type does not exist")
	fmt.Println("-m")
	for name := range PORTList {
		fmt.Println("   [" + name + "]")
	}
	os.Exit(1) // L2: 用法错误(扫描类型不存在) → 退出码 1
}
