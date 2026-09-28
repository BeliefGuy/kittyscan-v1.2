package Plugins

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/shadow1ng/fscan/common"
	"net"
	"strings"
	"sync"
	"time"
)

func FtpScan(info *common.HostInfo) (tmperr error) {
	starttime := time.Now().Unix()
	// 匿名访问检测：属于漏洞/未授权检测而非口令爆破，-nobr（仅做漏洞检测）时仍须执行，
	// 故放在 IsBrute 判断之前；成功时 FtpConn 内部照常输出 [vul] ftp host:port:anonymous
	flag, err := FtpConn(info, "anonymous", "")
	if flag && err == nil {
		return err
	} else {
		errlog := fmt.Sprintf("[-] ftp %v:%v %v %v", info.Host, info.Ports, "anonymous", err)
		common.LogError(errlog)
		tmperr = err
		if common.CheckErrs(err) {
			return err
		}
	}

	// -nobr：跳过密码爆破（仅做漏洞检测），上面的匿名访问检测已执行完毕
	if common.IsBrute {
		return
	}
	// -br（common.BruteThread）并发爆破：预组装 user×pass 组合，顺序与原双重 for 循环完全一致
	// （user 主序、password 次序），并保留 {user} 占位符替换语义。
	type ftpCombo struct{ user, pass string }
	var combos []ftpCombo
	for _, user := range common.Userdict["ftp"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			combos = append(combos, ftpCombo{user, pass})
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
	// 预算：沿用原公式（字典全组合数 × Timeout 秒），只按 worker 数摊薄；
	// workers=1 时与原表达式一致。
	budget := int64(len(common.Userdict["ftp"])*len(common.Passwords)) * common.Timeout / int64(workers)

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
	jobs := make(chan ftpCombo, len(combos))
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
				flag, err := FtpConn(info, c.user, c.pass)
				mu.Lock()
				if stopped {
					// 终态之后到达的结果静默丢弃（br=1 单 worker 时不会走到这里）
					mu.Unlock()
					return
				}
				if flag && err == nil {
					// [vul] 由 FtpConn 内部输出，这里不再重复打印（保持日志模板与次数不变）
					found = true
					sucErr = err
					signalStop()
					mu.Unlock()
					return
				}
				errlog := fmt.Sprintf("[-] ftp %v:%v %v %v %v", info.Host, info.Ports, c.user, c.pass, err)
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

func FtpConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	addr := fmt.Sprintf("%v:%v", Host, Port)
	timeout := time.Duration(common.BruteTimeout2) * time.Second
	deadline := time.Now().Add(timeout)
	// Q1: jlaffaye/ftp 的 DialTimeout 只管拨号，Login/List/QUIT 的读写都没有 deadline，
	// 且 ServerConn 不暴露底层 conn。改用 DialWithDialFunc 注入自建连接并 SetDeadline：
	// 库的控制连接与 PASV 数据连接都走同一 dialFunc，单次尝试全部读写都在预算内报错返回。
	conn, err := ftp.Dial(addr, ftp.DialWithDialFunc(func(network, address string) (net.Conn, error) {
		c, derr := net.DialTimeout(network, address, timeout)
		if derr != nil {
			return nil, derr
		}
		_ = c.SetDeadline(deadline)
		return c, nil
	}))
	if err != nil {
		return
	}
	// Q1: 原来全函数没有任何 Close（//defer conn.Logout() 被注释掉），每次尝试（含匿名）
	// 都泄漏控制连接。Quit() 发送 QUIT 后会关闭底层连接，deadline 保证它也不会挂死。
	defer conn.Quit()
	err = conn.Login(Username, Password)
	if err != nil {
		return
	}
	flag = true
	result := fmt.Sprintf("[vul] ftp %v:%v:%v %v", Host, Port, Username, Password)
	dirs, lerr := conn.List("")
	if lerr == nil && len(dirs) > 0 {
		for i := 0; i < len(dirs); i++ {
			if len(dirs[i].Name) > 50 {
				result += "\n   [->]" + dirs[i].Name[:50]
			} else {
				result += "\n   [->]" + dirs[i].Name
			}
			if i == 5 {
				break
			}
		}
	}
	common.LogSuccess(result)
	return flag, nil
}
