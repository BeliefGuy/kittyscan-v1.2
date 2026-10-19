package Plugins

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/shadow1ng/fscan/common"
)

type Addr struct {
	ip   string
	port int
}

func PortScan(hostslist []string, ports string, timeout int64, onFound func(address string)) []string {
	AliveAddress := make([]string, 0, len(hostslist)*20) // 预分配：主机数×预估端口数
	probePorts := common.ParsePort(ports)
	if len(probePorts) == 0 {
		fmt.Printf("[-] parse port %s error, please check your port format\n", ports)
		return AliveAddress
	}
	noPorts := common.ParsePort(common.NoPorts)
	if len(noPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range probePorts {
			temp[port] = struct{}{}
		}

		for _, port := range noPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port := range temp {
			newDatas = append(newDatas, port)
		}
		probePorts = newDatas
		sort.Ints(probePorts)
	}
	// 异步 SYN 引擎分支（2026-10-19）：仅当 -syn 且平台后端初始化成功时
	// EngineActive() 为真（Windows=Npcap；其余平台恒假）。masscan 风格
	// 无状态收发，契约与下方旧实现一致；本地/回环目标在分支内部自动回落
	// 既有 PortConnect，结果与旧路径完全一致。
	if EngineActive() {
		return portScanAsync(hostslist, probePorts, timeout, onFound)
	}

	workers := common.Threads
	Addrs := make(chan Addr, workers)
	results := make(chan string, workers)
	var wg sync.WaitGroup

	//接收结果 → 流水线：发现一个端口立刻触发漏扫
	go func() {
		for found := range results {
			AliveAddress = append(AliveAddress, found)
			if onFound != nil {
				onFound(found)
			}
			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				PortConnect(addr, results, timeout, &wg)
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, port := range probePorts {
		for _, host := range hostslist {
			wg.Add(1)
			Addrs <- Addr{host, port}
		}
	}
	wg.Wait()
	close(Addrs)
	close(results)
	return AliveAddress
}

func PortConnect(addr Addr, respondingHosts chan<- string, adjustedTimeout int64, wg *sync.WaitGroup) {
	host, port := addr.ip, addr.port
	address := host + ":" + strconv.Itoa(port)

	// 优先使用 SYN 扫描（半连接，更快）
	// 2026-09-29: [port] 行不再在扫描期打印, 改由派发层输出(all/main 走
	// IdentifyScan 在识别完成后打印 "[port] ip:port(svc)" 一行成型)。
	if synAvailable {
		timeout := time.Duration(adjustedTimeout) * time.Second
		if SYNPortSend(host, port, timeout) {
			wg.Add(1)
			respondingHosts <- address
		}
		return
	}

	// 降级：TCP Connect 扫描（完整三次握手）
	conn, err := common.WrapperTcpWithTimeout("tcp4", address, time.Duration(adjustedTimeout)*time.Second)
	if err == nil {
		// D方案(2026-09-29 用户选定, 仅优化 connect 路径, 不做真SYN):
		// SetLinger(0) -> close 时发 RST 而非 FIN 四次挥手, 连接不进 TIME_WAIT。
		// Windows 动态端口仅 ~16k(49152-65535) 且 TIME_WAIT 持续 ~4 分钟,
		// 高速扫大端口段会本地端口耗尽(WSAEADDRNOTAVAIL)导致漏报;
		// RST 关闭还避免在目标侧留下 TIME_WAIT/已建立连接残留。
		// 对 target 的既有业务连接(Banner/爆破/WebTitle)无影响——本函数只做端口探测。
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		defer conn.Close()
		wg.Add(1)
		respondingHosts <- address
	}
}

func NoPortScan(hostslist []string, ports string) (AliveAddress []string) {
	probePorts := common.ParsePort(ports)
	AliveAddress = make([]string, 0, len(hostslist)*len(probePorts))
	noPorts := common.ParsePort(common.NoPorts)
	if len(noPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range probePorts {
			temp[port] = struct{}{}
		}

		for _, port := range noPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port, _ := range temp {
			newDatas = append(newDatas, port)
		}
		probePorts = newDatas
		sort.Ints(probePorts)
	}
	for _, port := range probePorts {
		for _, host := range hostslist {
			address := host + ":" + strconv.Itoa(port)
			AliveAddress = append(AliveAddress, address)
		}
	}
	return
}
