package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"github.com/stacktitan/smb/smb"
	"strings"
	"sync"
	"time"
)

func SmbScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return nil
	}
	starttime := time.Now().Unix()
	// -br（common.BruteThread）并发爆破：预组装 user×pass 组合，顺序与原双重 for 循环完全一致
	// （user 主序、password 次序），并保留 {user} 占位符替换语义。
	// doWithTimeOut（signal 缓冲 1 + 独立 done channel 的超时封装）不属于字典循环，保持原样。
	type smbCombo struct{ user, pass string }
	var combos []smbCombo
	for _, user := range common.Userdict["smb"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			combos = append(combos, smbCombo{user, pass})
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
	budget := int64(len(common.Userdict["smb"])*len(common.Passwords)) * common.Timeout / int64(workers)

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
	jobs := make(chan smbCombo, len(combos))
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
				flag, err := doWithTimeOut(info, c.user, c.pass)
				mu.Lock()
				if stopped {
					// 终态之后到达的结果静默丢弃，避免成功后追加 [-] 日志或重复 [vul]；
					// br=1 单 worker 时不会走到这里。
					mu.Unlock()
					return
				}
				if flag == true && err == nil {
					var result string
					if common.Domain != "" {
						result = fmt.Sprintf("[vul] SMB %v:%v:%v\\%v %v", info.Host, info.Ports, common.Domain, c.user, c.pass)
					} else {
						result = fmt.Sprintf("[vul] SMB %v:%v:%v %v", info.Host, info.Ports, c.user, c.pass)
					}
					common.LogSuccess(result)
					found = true
					sucErr = err
					signalStop()
					mu.Unlock()
					return
				}
				errlog := fmt.Sprintf("[-] smb %v:%v %v %v %v", info.Host, 445, c.user, c.pass, err)
				errlog = strings.Replace(errlog, "\n", "", -1)
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

func SmblConn(info *common.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	flag = false
	Host, Username, Password := info.Host, user, pass
	options := smb.Options{
		Host:        Host,
		Port:        445,
		User:        Username,
		Password:    Password,
		Domain:      common.Domain,
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			flag = true
		}
	}
	signal <- struct{}{}
	return flag, err
}

func doWithTimeOut(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	// Q2 修复：
	// 1) signal 原为无缓冲 channel，超时返回后慢速完成的 SmblConn 会在 `signal <-` 上永久阻塞（goroutine 泄漏）；
	//    改为带缓冲 1，发送永不阻塞。
	// 2) 原 goroutine 直接写 doWithTimeOut 的具名返回值 flag/err，与超时分支并发读写产生数据竞争；
	//    结果改经独立的带缓冲 channel 传出，两个 goroutine 不再共享变量。
	type result struct {
		flag bool
		err  error
	}
	signal := make(chan struct{}, 1)
	done := make(chan result, 1)
	go func() {
		f, e := SmblConn(info, user, pass, signal)
		done <- result{flag: f, err: e}
	}()
	select {
	case r := <-done:
		return r.flag, r.err
	case <-time.After(time.Duration(common.Timeout) * time.Second):
		return false, errors.New("time out")
	}
}
