package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/WebScan"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

func Scan(info common.HostInfo) {
	// 显示扫描模式
	if common.SynScan {
		if TrySYNScan() {
			if !common.Silent {
				fmt.Println("[*] Scan mode: SYN (raw socket)")
			}
		} else {
			fmt.Println("[-] SYN scan not available on this platform, fallback to TCP Connect")
			fmt.Println("    (SYN scan only supported on Linux with root privileges)")
		}
	} else {
		if !common.Silent {
			fmt.Println("[*] Scan mode: TCP Connect")
		}
	}

	Hosts, err := common.ParseIP(info.Host, common.HostFile, common.NoHosts)
	if err != nil {
		fmt.Println("len(hosts)==0", err)
		// L4: 目标解析失败(ParseIPErr: 非法 IP/-hf 全为空或全被排除等)属于
		// 用法错误。原实现只打印后 return, 进程退出码仍为 0, 脚本/流水线会把
		// "没有目标可扫"误当成功; 改为以退出码 1 终止(与 common.CheckErr/
		// ParseInput 的用法错误退出码语义一致)。此时扫描尚未开始, 无日志需收尾。
		os.Exit(1)
	}
	lib.Inithttp()
	var ch = make(chan struct{}, common.Threads)
	var wg = sync.WaitGroup{}
	web := strconv.Itoa(common.PORTList["web"])
	ms17010 := strconv.Itoa(common.PORTList["ms17010"])
	if len(Hosts) > 0 || len(common.HostPort) > 0 {
		if common.NoPing == false && len(Hosts) > 1 || common.Scantype == "icmp" {
			Hosts = CheckLive(Hosts, common.Ping)
			if !common.Silent {
				fmt.Println("[*] Icmp alive hosts len is:", len(Hosts))
			}
		}
		if common.Scantype == "icmp" {
			common.LogWG.Wait()
			return
		}
		var AlivePorts []string

		// 已派发 target(ip:port) 集合：onPortFound 由 PortScan 的 results 收集
		// goroutine 串行回调，HostPort 循环在 PortScan 的 wg.Wait() 返回之后执行，
		// 两者存在 happens-before 关系，普通 map 无需加锁。
		// 用于 -hf 中 host:port 与端口扫描结果/重复行之间的去重(S4)。
		dispatched := make(map[string]struct{})

		// 流水线回调：发现一个端口 → Web探测 + 服务扫描并行
		onPortFound := func(targetIP string) {
			// 记录已派发键(与 AlivePorts/-hf 的 ip:port 格式一致)，供 HostPort 去重
			dispatched[targetIP] = struct{}{}
			sHost, sPort := strings.Split(targetIP, ":")[0], strings.Split(targetIP, ":")[1]
			sInfo := common.HostInfo{Host: sHost, Ports: sPort}
			if common.Scantype == "all" || common.Scantype == "main" {
				// 所有端口都探测 Web（抓非标端口上的 Web 服务）
				AddScan(web, sInfo, &ch, &wg)
				// 已知服务端口额外走对应的插件扫描
				switch {
				case sPort == "135":
					AddScan(sPort, sInfo, &ch, &wg)
					if common.IsWmi {
						AddScan("1000005", sInfo, &ch, &wg)
					}
				case sPort == "445":
					AddScan(ms17010, sInfo, &ch, &wg)
					// 保留 MS17-010 检测的同时补上 SMB 弱口令爆破(PluginMap["445"]=SmbScan);
					// switch 分支互斥,不会与下面 ServicePorts 分支重复调度
					AddScan(sPort, sInfo, &ch, &wg)
				case ServicePorts[sPort]:
					AddScan(sPort, sInfo, &ch, &wg)
				}
			} else {
				scantype := strconv.Itoa(common.PORTList[common.Scantype])
				// -m portscan 的派发键为字面量 "0"(PORTList["portscan"]=0)：
				// PluginMap/PortToPlugin 均查不到 "0"，下发只会给每个开放端口
				// 产生一个空 goroutine，使 Num/End 进度虚增(S2)。portscan 模式
				// 不需要任何插件任务，直接跳过；all/main 走上面的 if 分支不受影响。
				if scantype == "0" {
					return
				}
				AddScan(scantype, sInfo, &ch, &wg)
			}
		}

		if common.Scantype == "webonly" || common.Scantype == "webpoc" || common.Scantype == "fingeronly" {
			AlivePorts = NoPortScan(Hosts, common.Ports)
			// webpoc/fingeronly 需要把算出的目标真正下发, 否则模式空跑(0/0)。
			// webonly 在本版本中存在"算出目标但不下发"的历史bug, 为避免影响
			// 既有行为, 这里不改动它, 只对需要的模式下发。
			if common.Scantype == "webpoc" || common.Scantype == "fingeronly" {
				for _, alivePort := range AlivePorts {
					onPortFound(alivePort)
				}
			}
		} else if common.Scantype == "hostname" {
			common.Ports = "139"
			AlivePorts = NoPortScan(Hosts, common.Ports)
			// 与 webpoc/fingeronly 同款：算出的目标必须真正下发，否则模式空跑(0/0)。
			// 派发键取 PORTList["hostname"]=135 → PluginMap["135"]=Findnet，输出主机名信息
			for _, alivePort := range AlivePorts {
				onPortFound(alivePort)
			}
		} else if len(Hosts) > 0 {

			AlivePorts = PortScan(Hosts, common.Ports, common.Timeout, onPortFound)
			if !common.Silent {
				fmt.Println("[*] alive ports len is:", len(AlivePorts))
			}
			if common.Scantype == "portscan" {
				common.LogWG.Wait()
				return
			}
		}
		// 处理 -hf 中直接指定的 host:port（跳过端口扫描）
		if len(common.HostPort) > 0 {
			for _, hp := range common.HostPort {
				// 与已派发集合去重(S4)：-hf 同时含纯 IP 行(该端口已经端口扫描
				// 下发)与 IP:端口 行、或 -hf 内有重复行时，同一 host:port 只派发
				// 一次。去重键为 ip:port 字符串，与 onPortFound 入参/AlivePorts
				// 格式一致。不在集合中的条目照常派发，单条路径行为不变。
				if _, ok := dispatched[hp]; ok {
					continue
				}
				onPortFound(hp)
			}
			common.HostPort = nil
		}
	}
	for _, url := range common.Urls {
		info.Url = url
		AddScan(web, info, &ch, &wg)
	}
	wg.Wait()
	common.LogWG.Wait()
	close(common.Results)
	if !common.Silent {
		// M1: 读侧与 common/log.go 的 atomic.LoadInt64 配对, 消除跨文件数据竞争
		fmt.Printf("已完成 %v/%v\n", atomic.LoadInt64(&common.End), atomic.LoadInt64(&common.Num))
	}
}

// StopRequested 是中断停止标志(Ctrl+C/SIGTERM 时由 main 置 1, atomic 读写)。
// 置位后 AddScan 不再派发新任务, 已在途任务继续执行完毕, 由 main 侧有界等待收尾。
var StopRequested int64

// RequestStop 置中断停止标志, 供 main.go 的信号处理协程调用。
func RequestStop() {
	atomic.StoreInt64(&StopRequested, 1)
}

// M1: Num/End 写侧改 atomic.AddInt64, 与读侧(common/log.go 的 atomic.LoadInt64)
// 配对。原先写侧用 Mutex、读侧用 atomic 属于不匹配: 读侧拿不到写侧的锁,
// `-race` 仍会报数据竞争, 32 位构建下写侧也必须原子。
// 经全项目 grep 确认 `Plugins.Mutex` 只在本文件 AddScan 内使用、不保护其他字段,
// 故连同 `var Mutex = &sync.Mutex{}` 一并移除(无其他引用点, 删除不破坏编译)。
// Num 改为在派发时同步自增(原在 goroutine 内): 若留在 goroutine 内, 调度前存在
// "Num 尚未自增而其他任务 End 已追平" 的瞬时空窗, 会让中断收尾的 Num==End 判据
// 提前成立; 派发时自增后, Num==End 严格等价于"所有已派发任务均已执行完毕"。
func AddScan(scantype string, info common.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	// M3: 中断后停止派发新任务——不占并发槽、不计入 Num/End, 避免进度虚增
	if atomic.LoadInt64(&StopRequested) != 0 {
		return
	}
	*ch <- struct{}{}
	wg.Add(1)
	atomic.AddInt64(&common.Num, 1)
	go func() {
		ScanFunc(&scantype, &info)
		atomic.AddInt64(&common.End, 1)
		wg.Done()
		<-*ch
	}()
}

func ScanFunc(name *string, info *common.HostInfo) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[-] %v:%v scan error: %v\n", info.Host, info.Ports, err)
		}
	}()
	// 非标端口映射到标准端口插件
	pluginName := *name
	if standard, ok := PortToPlugin[pluginName]; ok {
		pluginName = standard
	}
	if fn, ok := PluginMap[pluginName]; ok {
		switch f := fn.(type) {
		case func(*common.HostInfo):
			f(info)
		case func(*common.HostInfo) error:
			f(info)
		case func(*common.HostInfo) (error, []WebScan.CheckDatas):
			f(info)
		}
	}
}
