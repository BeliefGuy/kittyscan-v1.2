package common

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ParsePort 解析端口串，支持单端口(22)、列表(22,80,443)、范围(1-100)与端口组名(ssh/all 等)。
// 解析失败、范围半截(缺起止)、端口为 0 或超过 65535 时立即明确报错并退出，
// 不再静默丢弃产生错误/空端口集(端口集为空会导致静默 0/0 扫描)。
// 空串按"未指定"处理并返回空集——调用方(PortScan/NoPortScan)对 -pn 等空入参依赖此行为。
func ParsePort(ports string) (scanPorts []int) {
	if ports == "" {
		return
	}
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		if PortGroup[port] != "" {
			port = PortGroup[port]
			scanPorts = append(scanPorts, ParsePort(port)...)
			continue
		}
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			// 100-200-300 这类多段输入直接拒绝，不再忽略多余段
			if len(ranges) != 2 {
				fmt.Printf("[-] parse port %q error, invalid range (want: start-end)\n", port)
				os.Exit(1)
			}
			ranges[0] = strings.TrimSpace(ranges[0])
			ranges[1] = strings.TrimSpace(ranges[1])
			startPort, err1 := strconv.Atoi(ranges[0])
			endPort, err2 := strconv.Atoi(ranges[1])
			// 80-(缺结束)、-1(缺起始)、80-abc 等半截/非数字输入直接报错
			if err1 != nil || err2 != nil {
				fmt.Printf("[-] parse port %q error, please check your port format\n", port)
				os.Exit(1)
			}
			if !isValidPortNum(startPort) || !isValidPortNum(endPort) {
				fmt.Printf("[-] parse port %q error, port must be 1-65535\n", port)
				os.Exit(1)
			}
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}
		}
		start, err1 := strconv.Atoi(port)
		end, err2 := strconv.Atoi(upper)
		if err1 != nil || err2 != nil {
			fmt.Printf("[-] parse port %q error, please check your port format\n", port)
			os.Exit(1)
		}
		if !isValidPortNum(start) || !isValidPortNum(end) {
			fmt.Printf("[-] parse port %q error, port must be 1-65535\n", port)
			os.Exit(1)
		}
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	scanPorts = removeDuplicate(scanPorts)
	// 非空入参却解析不出任何有效端口(如只有逗号/空白)，同样报错退出
	if len(scanPorts) == 0 {
		fmt.Printf("[-] parse port %q error, no valid port parsed\n", ports)
		os.Exit(1)
	}
	return scanPorts
}

func isValidPortNum(port int) bool {
	return port >= 1 && port <= 65535
}

func removeDuplicate(old []int) []int {
	result := []int{}
	temp := map[int]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
