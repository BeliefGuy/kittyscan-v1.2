package Plugins

import (
	"bytes"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"golang.org/x/net/icmp"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	AliveHosts []string
	ExistHosts = make(map[string]struct{})
	livewg     sync.WaitGroup
	// aliveMu 保护 AliveHosts：consumer goroutine 的 append 与
	// RunIcmp1 等待循环的 len 读取并发，必须用同一把锁串行化
	aliveMu sync.Mutex
)

// aliveHostsLen 在锁内读取 AliveHosts 长度，与 consumer 的 append 互斥
func aliveHostsLen() int {
	aliveMu.Lock()
	defer aliveMu.Unlock()
	return len(AliveHosts)
}

func CheckLive(hostslist []string, Ping bool) []string {
	// 构建主机 map 用于 O(1) 查找
	hostMap := make(map[string]struct{}, len(hostslist))
	for _, h := range hostslist {
		hostMap[h] = struct{}{}
	}

	chanHosts := make(chan string, len(hostslist))
	go func() {
		for ip := range chanHosts {
			if _, ok := ExistHosts[ip]; !ok {
				if _, inList := hostMap[ip]; inList {
					ExistHosts[ip] = struct{}{}
					if common.Silent == false {
						if Ping == false {
							fmt.Printf("(icmp) Target %-15s is alive\n", ip)
						} else {
							fmt.Printf("(ping) Target %-15s is alive\n", ip)
						}
					}
					aliveMu.Lock()
					AliveHosts = append(AliveHosts, ip)
					aliveMu.Unlock()
				}
			}
			livewg.Done()
		}
	}()

	if Ping == true {
		//使用ping探测
		RunPing(hostslist, chanHosts)
	} else {
		//优先尝试监听本地icmp,批量探测
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err == nil {
			RunIcmp1(hostslist, conn, chanHosts)
		} else {
			common.LogError(err)
			//尝试无监听icmp探测
			// L5: 状态类回显包 -silent, 口径与本文件上方 (icmp)/(ping) alive 打印一致
			if !common.Silent {
				fmt.Println("trying RunIcmp2")
			}
			conn, err := net.DialTimeout("ip4:icmp", "127.0.0.1", 3*time.Second)
			defer func() {
				if conn != nil {
					conn.Close()
				}
			}()
			if err == nil {
				RunIcmp2(hostslist, chanHosts)
			} else {
				common.LogError(err)
				//使用ping探测
				// L5: 权限降级提示包 -silent
				if !common.Silent {
					fmt.Println("The current user permissions unable to send icmp packets")
					fmt.Println("start ping")
				}
				RunPing(hostslist, chanHosts)
			}
		}
	}

	livewg.Wait()
	close(chanHosts)

	if len(hostslist) > 1000 {
		arrTop, arrLen := ArrayCountValueTop(AliveHosts, common.LiveTop, true)
		for i := 0; i < len(arrTop); i++ {
			output := fmt.Sprintf("[*] LiveTop %-16s 段存活数量为: %d", arrTop[i]+".0.0/16", arrLen[i])
			common.LogSuccess(output)
		}
	}
	if len(hostslist) > 256 {
		arrTop, arrLen := ArrayCountValueTop(AliveHosts, common.LiveTop, false)
		for i := 0; i < len(arrTop); i++ {
			output := fmt.Sprintf("[*] LiveTop %-16s 段存活数量为: %d", arrTop[i]+".0/24", arrLen[i])
			common.LogSuccess(output)
		}
	}

	return AliveHosts
}

func RunIcmp1(hostslist []string, conn *icmp.PacketConn, chanHosts chan string) {
	// endflag 跨 goroutine 读写：改用 atomic.Bool，消除裸 bool 的数据竞争
	var endflag atomic.Bool
	// readerDone 由 reader goroutine 在退出时 close，作为主流程与 reader 的汇合点，
	// 保证 reader 完成最后一次 livewg.Add+发送之后，主流程才会走到
	// CheckLive 的 livewg.Wait() 与 close(chanHosts)，杜绝 send on closed channel
	// 及 WaitGroup Add/Wait 并发 misuse
	readerDone := make(chan struct{})
	// 发送前先建立 "解析IP -> 原始host(s)" 映射。hostMap 的键是用户原始输入
	// （可能是域名），回包只能给出点分IP，故回包时经此映射回传原始 host，
	// consumer 侧用原始 host 精确匹配即可命中。映射在 reader 启动前建完，
	// 避免并发读写 map。
	// 用一对多映射：多个 host 可能指向同一 IP(如 localhost 与 127.0.0.1，
	// 或域名解析到某台机器的 IP)，该 IP 的回包必须回传全部 host，
	// 否则只有最后一个被标记存活。
	ipToHost := make(map[string][]string, len(hostslist)*2)
	resolved := make(map[string]*net.IPAddr, len(hostslist))
	for _, host := range hostslist {
		ipToHost[host] = append(ipToHost[host], host)
		dst, err := net.ResolveIPAddr("ip", host)
		if err != nil {
			// 解析失败不再静默吞掉：记录日志，且该目标不写入 resolved，
			// 后续发送阶段跳过它（原先会拿 nil 地址 WriteTo，错误同样被忽略）。
			common.LogError(err)
			continue
		}
		resolved[host] = dst
		if ip := dst.IP.String(); ip != host {
			ipToHost[ip] = append(ipToHost[ip], host)
		}
	}

	go func() {
		// reader 退出前一定 close(readerDone)（含下面所有 Add+发送完成后才退出）
		defer close(readerDone)
		for {
			if endflag.Load() {
				return
			}
			msg := make([]byte, 100)
			_, sourceIP, err := conn.ReadFrom(msg)
			if err != nil {
				// 主流程 endflag 置位后 conn.Close() 会使阻塞的 ReadFrom 返回错误，
				// reader 由此正常退出；不再依赖裸 bool 轮询终止
				return
			}
			if sourceIP != nil {
				target := sourceIP.String()
				// 点分IP命中映射时回传全部对应的原始 host（域名），否则原样回传
				if hosts, ok := ipToHost[target]; ok {
					livewg.Add(len(hosts))
					for _, h := range hosts {
						chanHosts <- h
					}
				} else {
					livewg.Add(1)
					chanHosts <- target
				}
			}
		}
	}()

	for _, host := range hostslist {
		dst, ok := resolved[host]
		if !ok {
			// 解析失败的目标已在上方记录日志，跳过发送
			continue
		}
		IcmpByte := makemsg(host)
		conn.WriteTo(IcmpByte, dst)
	}
	//根据hosts数量修改icmp监听时间
	start := time.Now()
	for {
		// 锁内读取长度，避免与 consumer goroutine 的 append 数据竞争
		if aliveHostsLen() == len(hostslist) {
			break
		}
		since := time.Since(start)
		var wait time.Duration
		switch {
		case len(hostslist) <= 256:
			wait = time.Second * 3
		default:
			wait = time.Second * 6
		}
		if since > wait {
			break
		}
		// 原为无 sleep 纯自旋（3~6 秒单核 100% CPU），改为 100ms 轮询
		time.Sleep(100 * time.Millisecond)
	}
	endflag.Store(true)
	conn.Close()
	// 汇合点：conn.Close() 唤醒阻塞的 ReadFrom，reader 退出时 close(readerDone)；
	// 必须等 reader 完全退出（其后的 Add+发送全部完成）才允许 RunIcmp1 返回，
	// 之后 CheckLive 才执行 livewg.Wait() 和 close(chanHosts)
	<-readerDone
}

func RunIcmp2(hostslist []string, chanHosts chan string) {
	num := 1000
	if len(hostslist) < num {
		num = len(hostslist)
	}
	var wg sync.WaitGroup
	limiter := make(chan struct{}, num)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if icmpalive(host) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
	close(limiter)
}

func icmpalive(host string) bool {
	startTime := time.Now()
	conn, err := net.DialTimeout("ip4:icmp", host, 6*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	if err := conn.SetDeadline(startTime.Add(6 * time.Second)); err != nil {
		return false
	}
	msg := makemsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}

	return true
}

func RunPing(hostslist []string, chanHosts chan string) {
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 50)
	for _, host := range hostslist {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if ExecCommandPing(host) {
				livewg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
}

func ExecCommandPing(ip string) bool {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	case "darwin":
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -W 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	default: //linux
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		return false
	}
	if err = command.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(outinfo.String(), "true") && strings.Count(outinfo.String(), ip) > 2 {
			return true
		} else {
			return false
		}
	}
}

func makemsg(host string) []byte {
	msg := make([]byte, 40)
	id0, id1 := genIdentifier(host)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = genSequence(1)
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)
	return msg
}

func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	answer := uint16(^sum)
	return answer
}

func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}

func genIdentifier(host string) (byte, byte) {
	return host[0], host[1]
}

func ArrayCountValueTop(arrInit []string, length int, flag bool) (arrTop []string, arrLen []int) {
	if len(arrInit) == 0 {
		return
	}
	arrMap1 := make(map[string]int)
	arrMap2 := make(map[string]int)
	for _, value := range arrInit {
		line := strings.Split(value, ".")
		if len(line) == 4 {
			if flag {
				value = fmt.Sprintf("%s.%s", line[0], line[1])
			} else {
				value = fmt.Sprintf("%s.%s.%s", line[0], line[1], line[2])
			}
		}
		if arrMap1[value] != 0 {
			arrMap1[value]++
		} else {
			arrMap1[value] = 1
		}
	}
	for k, v := range arrMap1 {
		arrMap2[k] = v
	}

	i := 0
	for range arrMap1 {
		var maxCountKey string
		var maxCountVal = 0
		for key, val := range arrMap2 {
			if val > maxCountVal {
				maxCountVal = val
				maxCountKey = key
			}
		}
		arrTop = append(arrTop, maxCountKey)
		arrLen = append(arrLen, maxCountVal)
		i++
		if i >= length {
			return
		}
		delete(arrMap2, maxCountKey)
	}
	return
}
