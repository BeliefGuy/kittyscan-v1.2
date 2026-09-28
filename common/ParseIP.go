package common

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var ParseIPErr = errors.New(" host parsing error\n" +
	"format: \n" +
	"192.168.1.1\n" +
	"192.168.1.1/8\n" +
	"192.168.1.1/16\n" +
	"192.168.1.1/24\n" +
	"192.168.1.1,192.168.1.2\n" +
	"192.168.1.1-192.168.255.255\n" +
	"192.168.1.1-255")

// MaxExpandIPs 是单个目标(CIDR 或 IP 段)允许全量展开的最大地址数。
// 展开前先计算地址数量,超过该上限的目标直接拒绝并打印明确提示,
// 防止 /7、/9、/0 或手工跨段大范围(如 1.0.0.0-150.255.255.255)
// 把上亿地址全量塞进 []string 导致 OOM。/8 仍走 parseIP8 抽样。
const MaxExpandIPs = 65536

func ParseIP(host string, filename string, nohosts ...string) (hosts []string, err error) {
	if strings.Contains(host, ",") {
		// 多目标：逐项处理，每项单独判断 host:port 形态。
		// 不能整体按冒号拆分：ip1:port1,ip2:port2 会被拆成 4 段而落空，
		// IPv6(多个冒号)也会被整体丢弃，最终静默 0/0。
		for _, item := range strings.Split(host, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if strings.Count(item, ":") == 1 {
				hostport := strings.SplitN(item, ":", 2)
				if UserSetPort {
					// 用户显式指定 -p：以用户端口为准，忽略项内端口
					hosts = append(hosts, ParseIPs(hostport[0])...)
				} else {
					// 每项登记为 "ip:port" 目标，扫描时跳过端口探测直接派发
					for _, h := range ParseIPs(hostport[0]) {
						HostPort = append(HostPort, h+":"+hostport[1])
					}
				}
			} else {
				hosts = append(hosts, ParseIPs(item)...)
			}
		}
	} else if strings.Count(host, ":") == 1 {
		// 单目标 host:port（如 192.168.1.1:8080）；IPv6 含多个冒号不会进入此分支
		hostport := strings.SplitN(host, ":", 2)
		hosts = ParseIPs(hostport[0])
		// 仅在用户未显式指定 -p 时才用 host 内的端口覆盖端口设置（与模式收敛同一标记）
		if !UserSetPort {
			Ports = hostport[1]
		}
	} else {
		// 普通目标 / CIDR / IPv6（多个冒号）走正常解析
		hosts = ParseIPs(host)
	}
	if filename != "" {
		var filehost []string
		filehost, _ = Readipfile(filename)
		hosts = append(hosts, filehost...)
	}

	// -hn 展开后的排除主机列表(CIDR/范围用 ParseIPs 展开),供下方 hosts 与 HostPort 过滤复用
	var nohostList []string
	if len(nohosts) > 0 {
		nohost := nohosts[0]
		if nohost != "" {
			nohostList = ParseIPs(nohost)
			if len(nohostList) > 0 {
				temp := map[string]struct{}{}
				for _, host := range hosts {
					temp[host] = struct{}{}
				}

				for _, host := range nohostList {
					delete(temp, host)
				}

				var newDatas []string
				for host := range temp {
					newDatas = append(newDatas, host)
				}
				hosts = newDatas
				sort.Strings(hosts)
			} else {
				// P2: -hn 值非空但解析为空(如 10.0.0.1/33、192.168.1.1-300)时,
				// 旧逻辑直接跳过整个排除分支 → 该排除的主机照常被扫且无任何提示。
				// 用户明确选择"警告但继续": 打印 [-] 警告(不包 if !Silent、不 os.Exit),
				// hosts/HostPort 保持原样继续扫描。
				fmt.Printf("[-] -hn %q 解析失败（格式非法），本次未排除任何主机；支持单IP/逗号列表/CIDR/IP段\n", nohost)
			}
		}
	}

	// -hn/-pn 对 Readipfile 写入的全局 HostPort("ip:port" 行)同样生效:
	// 拆出 host 与 port 分别比对 nohosts/NoPorts,避免被排除的目标仍被请求。
	// -hn 为 CIDR/范围时复用上面 ParseIPs 的展开结果。
	if len(HostPort) > 0 && (len(nohostList) > 0 || NoPorts != "") {
		nohostSet := make(map[string]struct{}, len(nohostList))
		for _, h := range nohostList {
			nohostSet[h] = struct{}{}
		}
		noPortSet := make(map[int]struct{})
		for _, p := range ParsePort(NoPorts) {
			noPortSet[p] = struct{}{}
		}
		var newHostPort []string
		for _, hp := range HostPort {
			parts := strings.SplitN(hp, ":", 2)
			if len(parts) == 2 {
				if _, ok := nohostSet[parts[0]]; ok {
					continue
				}
				if port, perr := strconv.Atoi(parts[1]); perr == nil {
					if _, ok := noPortSet[port]; ok {
						continue
					}
				}
			}
			newHostPort = append(newHostPort, hp)
		}
		HostPort = newHostPort
	}
	hosts = RemoveDuplicate(hosts)
	// 任一目标来源(-h 或 -hf)存在但最终解析为空即报错（如非法 IP、-hn 全部排除），
	// 避免静默打印"已完成 0/0"让用户误以为扫过；-u/-uf 只扫 URL 时
	// Host 与 HostFile 均为空，不视为错误。
	if len(hosts) == 0 && len(HostPort) == 0 && (host != "" || filename != "") {
		err = ParseIPErr
	}
	return
}

func ParseIPs(ip string) (hosts []string) {
	if strings.Contains(ip, ",") {
		IPList := strings.Split(ip, ",")
		var ips []string
		for _, ip := range IPList {
			ips = parseIP(ip)
			hosts = append(hosts, ips...)
		}
	} else {
		hosts = parseIP(ip)
	}
	return hosts
}

func parseIP(ip string) []string {
	reg := regexp.MustCompile(`[a-zA-Z]+`)
	switch {
	case ip == "192":
		return parseIP("192.168.0.0/8")
	case ip == "172":
		return parseIP("172.16.0.0/12")
	case ip == "10":
		return parseIP("10.0.0.0/8")
	// 扫描/8时,只扫网关和随机IP,避免扫描过多IP
	case strings.HasSuffix(ip, "/8"):
		return parseIP8(ip)
	//解析 /24 /16 /8 /xxx 等
	case strings.Contains(ip, "/"):
		return parseIP2(ip)
	//可能是域名,用lookup获取ip
	case reg.MatchString(ip):
		//	_, err := net.LookupHost(ip)
		//	if err != nil {
		//		return nil
		//	}
		return []string{ip}
	//192.168.1.1-192.168.1.100
	case strings.Contains(ip, "-"):
		return parseIP1(ip)
	//处理单个ip
	default:
		testIP := net.ParseIP(ip)
		if testIP == nil {
			return nil
		}
		return []string{ip}
	}
}

// 把 192.168.x.x/xx 转换成 192.168.x.x-192.168.x.x
func parseIP2(host string) (hosts []string) {
	_, ipNet, err := net.ParseCIDR(host)
	if err != nil {
		return
	}
	// 展开前先算地址数 1<<(32-prefix),超过上限直接拒绝该目标,避免大 CIDR 全量展开 OOM
	ones, bits := ipNet.Mask.Size()
	if ones >= 0 && bits <= 32 && bits-ones >= 0 {
		count := uint64(1) << uint(bits-ones)
		if count > MaxExpandIPs {
			fmt.Printf("[-] 目标过大：目标 %s 展开后 %d 个地址，超过上限 %d；请缩小范围或使用 /8（已拒绝该目标）\n",
				host, count, MaxExpandIPs)
			return
		}
	}
	hosts = parseIP1(IPRange(ipNet))
	return
}

// 解析ip段:
//
//	192.168.111.1-255
//	192.168.111.1-192.168.112.255
func parseIP1(ip string) []string {
	IPRange := strings.Split(ip, "-")
	testIP := net.ParseIP(IPRange[0])
	var AllIP []string
	if len(IPRange[1]) < 4 {
		Range, err := strconv.Atoi(IPRange[1])
		if testIP == nil || Range > 255 || err != nil {
			return nil
		}
		SplitIP := strings.Split(IPRange[0], ".")
		// 防御：起始地址不是点分四段(如 IPv6 "xx::1-5")时直接拒绝，避免 SplitIP[3] 越界
		if len(SplitIP) != 4 {
			return nil
		}
		ip1, err1 := strconv.Atoi(SplitIP[3])
		ip2, err2 := strconv.Atoi(IPRange[1])
		PrefixIP := strings.Join(SplitIP[0:3], ".")
		if ip1 > ip2 || err1 != nil || err2 != nil {
			return nil
		}
		for i := ip1; i <= ip2; i++ {
			AllIP = append(AllIP, PrefixIP+"."+strconv.Itoa(i))
		}
	} else {
		SplitIP1 := strings.Split(IPRange[0], ".")
		SplitIP2 := strings.Split(IPRange[1], ".")
		if len(SplitIP1) != 4 || len(SplitIP2) != 4 {
			return nil
		}
		start, end := [4]int{}, [4]int{}
		for i := 0; i < 4; i++ {
			ip1, err1 := strconv.Atoi(SplitIP1[i])
			ip2, err2 := strconv.Atoi(SplitIP2[i])
			// 逐八位组校验 0-255，非法立即报错拒绝该范围：
			// 否则 192.168.1.1-192.168.1.300 的 end[3]=300 会参与 endNum 计算，
			// 实际生成到 192.168.2.44，扫到用户输入范围之外
			if err1 != nil || err2 != nil || ip1 < 0 || ip1 > 255 || ip2 < 0 || ip2 > 255 {
				fmt.Printf("[-] IP段 %s 含非法八位组(0-255)，已拒绝该范围\n", ip)
				return nil
			}
			start[i], end[i] = ip1, ip2
		}
		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]
		// 起止 IP 整体转数值再比较：旧逻辑逐八位组比较会把
		// 192.168.255.1-192.169.1.1 在第 3 位(255>1)误判为非法而整体拒绝
		if startNum > endNum {
			fmt.Printf("[-] IP段 %s 起始IP大于结束IP，已拒绝该范围\n", ip)
			return nil
		}
		// 跨段大范围展开前先算地址数 endNum-startNum+1,超过上限拒绝该目标,避免 OOM
		if count := int64(endNum) - int64(startNum) + 1; count > MaxExpandIPs {
			fmt.Printf("[-] 目标过大：目标 %s 展开后 %d 个地址，超过上限 %d；请缩小范围或使用 /8（已拒绝该目标）\n",
				ip, count, MaxExpandIPs)
			return nil
		}
		for num := startNum; num <= endNum; num++ {
			ip := strconv.Itoa((num>>24)&0xff) + "." + strconv.Itoa((num>>16)&0xff) + "." + strconv.Itoa((num>>8)&0xff) + "." + strconv.Itoa((num)&0xff)
			AllIP = append(AllIP, ip)
		}
	}
	return AllIP
}

// 获取起始IP、结束IP
func IPRange(c *net.IPNet) string {
	start := c.IP.String()
	mask := c.Mask
	bcst := make(net.IP, len(c.IP))
	copy(bcst, c.IP)
	for i := 0; i < len(mask); i++ {
		ipIdx := len(bcst) - i - 1
		bcst[ipIdx] = c.IP[ipIdx] | ^mask[len(mask)-i-1]
	}
	end := bcst.String()
	return fmt.Sprintf("%s-%s", start, end) //返回用-表示的ip段,192.168.1.0-192.168.255.255
}

// 按行读ip
func Readipfile(filename string) ([]string, error) {
	// L6: 复用 readTextLines —— 统一剥离 UTF-8 BOM、UTF-16 LE/BE BOM 转码 UTF-8,
	// 避免 BOM 粘在首行或行内混入 0x00 导致 IP 全部解析失败(静默 0/0 空扫);
	// 打开失败/转码失败由 readTextLines 明确报错并退出, 不再静默。
	// 纯空白行已由 readTextLines 过滤(TrimSpace 后为空不入列), 此处不再判。
	var content []string
	skippedComments := 0 // 跳过的注释行(# / ; 开头)
	fixedSpaceIP := 0    // 首字段是合法IPv4、后跟说明文字而被修正的行
	for _, line := range readTextLines(filename) {
		// P3 (1): 注释行(# / ; 开头)是明确的注释, 不是域名, 跳过不下发, 计数汇总
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			skippedComments++
			continue
		}
		text := strings.Split(line, ":")
		if len(text) == 2 {
			port := strings.Split(text[1], " ")[0]
			num, err := strconv.Atoi(port)
			if err != nil || (num < 1 || num > 65535) {
				// P3 (4): 带冒号但端口非法的行(如 192.168.1.1:abc)旧实现静默丢弃;
				// 改为打印警告说明跳过原因, 继续处理其余行(警告不包 if !Silent)
				fmt.Printf("[-] -hf %q: 跳过行 %q（端口 %q 非法，需为 1-65535 的数字）\n", filename, line, port)
				continue
			}
			hosts := ParseIPs(text[0])
			for _, host := range hosts {
				HostPort = append(HostPort, fmt.Sprintf("%s:%s", host, port))
			}
		} else {
			// P3 (3): 含空格的行(如 "192.168.1.1 nginx")。保守修正规则:
			// 仅当行含空格(多字段)且首字段是合法 IPv4 时, 取首字段作为目标并计数;
			// 首字段不是 IPv4(真域名如 oa.example.com、域名+备注)则保持现状,
			// 整行交由 ParseIPs —— 真域名走 reg [a-zA-Z]+ 分支照常下发, 不误伤。
			if fields := strings.Fields(line); len(fields) > 1 {
				if first := net.ParseIP(fields[0]); first != nil && first.To4() != nil {
					content = append(content, fields[0])
					fixedSpaceIP++
					continue
				}
			}
			host := ParseIPs(line)
			content = append(content, host...)
		}
	}
	// P3 汇总: 结束时输出一条(仅在确有注释被跳过或有行被修正时), 不包 if !Silent
	if skippedComments > 0 || fixedSpaceIP > 0 {
		fmt.Printf("[-] -hf %q: 跳过 %d 行注释, 修正 %d 行含空格的IP\n", filename, skippedComments, fixedSpaceIP)
	}
	return content, nil
}

// 去重
func RemoveDuplicate(old []string) []string {
	result := []string{}
	temp := map[string]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func parseIP8(ip string) []string {
	realIP := ip[:len(ip)-2]
	testIP := net.ParseIP(realIP)

	if testIP == nil {
		return nil
	}

	IPrange := strings.Split(ip, ".")[0]
	var AllIP []string
	for a := 0; a <= 255; a++ {
		for b := 0; b <= 255; b++ {
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 1))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 2))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 4))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 5))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(6, 55)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(56, 100)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(101, 150)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(151, 200)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, RandInt(201, 253)))
			AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", IPrange, a, b, 254))
		}
	}
	return AllIP
}

func RandInt(min, max int) int {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Intn(max-min) + min
}
