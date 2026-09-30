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

// SmbScan SMB 爆破统一入口(2026-09-29 融合: SmbScan + SmbScan2 按方言二选一)。
// 流程: -nobr 跳过 → -hash 直接 smb2 后端(PTH 仅 go-smb2 支持) →
// smbDialectProbe 一条连接探测方言 → 只跑被选中后端的全字典(单遍, 不双倍):
//   - smb1(stacktitan): 目标接受 SMB1(双栈/老设备)
//   - smb2(go-smb2):    目标禁 SMB1 仅 SMB2+(现代 Windows/Samba)、探测失败默认、-hash
//
// 探测失败走 smb2 是安全兜底: 死主机/非 SMB 由 ErrJudge(连续超时3次)与
// CheckErrs(致命错误)快速终止, 不会白跑全字典。日志格式按后端保持原样
// (smb1→[-] smb/[vul] SMB, smb2→[-] smb2/[vul] SMB2), 下游解析不受影响。
func SmbScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return nil
	}
	// -hash NTLM 哈希传递: stacktitan/smb(SMB1)不支持, 必须走 go-smb2
	if len(common.Hash) > 0 {
		return smb2Brute(info)
	}
	// 探测目标固定 445: 两个后端(SmblConn/Smb2Con)均硬编码打 host:445,
	// 即使 info.Ports 是 1445/4445(-m smb / 端口兜底映射)实际连接也是 445。
	switch smbDialectProbe(fmt.Sprintf("%v:445", info.Host), time.Duration(common.Timeout)*time.Second) {
	case smbDialectSMB1:
		return smb1Brute(info)
	default: // smb2 与 unknown 统一走 go-smb2(现代默认+快速失败兜底)
		return smb2Brute(info)
	}
}

// smb1Brute SMB1 协议弱口令爆破(原 SmbScan 主体, stacktitan/smb 栈, 逻辑零改动, 仅改名)。
func smb1Brute(info *common.HostInfo) (tmperr error) {
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
	judge := common.ErrJudge{} // 连续超时判定: 超时3次才停, 致命错误立即停(2026-09-29)
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
				if judge.ShouldStop(err) {
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
