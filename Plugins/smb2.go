package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2"
)

func SmbScan2(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return nil
	}
	hasprint := false
	starttime := time.Now().Unix()
	hash := common.HashBytes

	// -br（common.BruteThread）并发爆破：预组装 user×pass 组合，顺序与原双重 for 循环完全一致
	// （user 主序、password 次序），并保留 {user} 占位符替换语义。
	// hash 认证不依赖密码，原逻辑每用户在首个密码尝试后 break PASS 跳过该用户其余密码，
	// 因此 len(common.Hash) > 0 时每个用户只投递一个组合（替换后的首个密码），语义一致。
	type smb2Combo struct{ user, pass string }
	var combos []smb2Combo
	for _, user := range common.Userdict["smb"] {
		if len(common.Hash) > 0 {
			if len(common.Passwords) > 0 {
				pass := strings.Replace(common.Passwords[0], "{user}", user, -1)
				combos = append(combos, smb2Combo{user, pass})
			}
			continue
		}
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			combos = append(combos, smb2Combo{user, pass})
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

	// 共享状态全部由 mu 保护：found/sucErr/stopped/hasprint 以及具名返回值 tmperr
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
	jobs := make(chan smb2Combo, len(combos))
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
				mu.Lock()
				hp := hasprint // 读共享的 [*] SMB2-shares 抑制标志（与原串行传值一致）
				mu.Unlock()
				flag, err, flag2 := Smb2Con(info, c.user, c.pass, hash, hp)
				mu.Lock()
				if flag2 {
					hasprint = true
				}
				if stopped {
					// 终态之后到达的结果静默丢弃，避免成功后追加 [-] 日志或重复 [vul]；
					// br=1 单 worker 时不会走到这里。
					mu.Unlock()
					return
				}
				if flag == true {
					var result string
					if common.Domain != "" {
						result = fmt.Sprintf("[vul] SMB2 %v:%v:%v\\%v ", info.Host, info.Ports, common.Domain, c.user)
					} else {
						result = fmt.Sprintf("[vul] SMB2 %v:%v:%v ", info.Host, info.Ports, c.user)
					}
					if len(hash) > 0 {
						result += "hash: " + common.Hash
					} else {
						result += c.pass
					}
					common.LogSuccess(result)
					found = true
					sucErr = err
					signalStop()
					mu.Unlock()
					return
				}
				var errlog string
				if len(common.Hash) > 0 {
					errlog = fmt.Sprintf("[-] smb2 %v:%v %v %v %v", info.Host, 445, c.user, common.Hash, err)
				} else {
					errlog = fmt.Sprintf("[-] smb2 %v:%v %v %v %v", info.Host, 445, c.user, c.pass, err)
				}
				errlog = strings.Replace(errlog, "\n", " ", -1)
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

func Smb2Con(info *common.HostInfo, user string, pass string, hash []byte, hasprint bool) (flag bool, err error, flag2 bool) {
	conn, err := net.DialTimeout("tcp", info.Host+":445", time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	// Q1: go-smb2@v1.1.0 不会给调用方传入的 conn 设 deadline（对比 smb.go 有 doWithTimeOut），
	// d.Dial/ListSharenames/Mount 的阻塞读会无限挂死。拨号后立即设绝对 deadline，
	// 本次尝试的全部 SMB2 读写都会在 common.Timeout 内报错返回。
	_ = conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	initiator := smb2.NTLMInitiator{
		User:   user,
		Domain: common.Domain,
	}
	if len(hash) > 0 {
		initiator.Hash = hash
	} else {
		initiator.Password = pass
	}
	d := &smb2.Dialer{
		Initiator: &initiator,
	}

	s, err := d.Dial(conn)
	if err != nil {
		return // 认证失败：flag=false、err=握手/认证错误
	}
	defer s.Logoff()
	// Q6: d.Dial 成功即认证通过（等价 smb.go 的 IsAuthenticated），认证成功即判成功；
	// C$ 读取只是权限探测，失败不再把"有效但非管理员"的凭据记成失败去跑完整个字典。
	flag = true
	names, nerr := s.ListSharenames()
	if nerr != nil {
		// 认证已成功：列共享名失败只影响信息输出，err 保持 nil
		return
	}
	if !hasprint {
		var result string
		if common.Domain != "" {
			result = fmt.Sprintf("[*] SMB2-shares %v:%v:%v\\%v ", info.Host, info.Ports, common.Domain, user)
		} else {
			result = fmt.Sprintf("[*] SMB2-shares %v:%v:%v ", info.Host, info.Ports, user)
		}
		if len(hash) > 0 {
			result += "hash: " + common.Hash
		} else {
			result += pass
		}
		result = fmt.Sprintf("%v shares: %v", result, names)
		common.LogSuccess(result)
		flag2 = true
	}
	// 以下仅探测 C$ 读取权限（信息输出用），成功与否都不改变认证结论；
	// 探测错误用独立变量接收，避免污染具名返回值 err。
	fs, merr := s.Mount("C$")
	if merr != nil {
		return
	}
	defer fs.Umount()
	path := `Windows\win.ini`
	f, oerr := fs.OpenFile(path, os.O_RDONLY, 0666)
	if oerr != nil {
		return
	}
	defer f.Close()
	return
	//bs, err := ioutil.ReadAll(f)
	//if err != nil {
	//	return
	//}
	//fmt.Println(string(bs))
	//return

}

//if info.Path == ""{
//}
//path = info.Path
//f, err := fs.OpenFile(path, os.O_RDONLY, 0666)
//if err != nil {
//	return
//}
//flag = true
//_, err = f.Seek(0, io.SeekStart)
//if err != nil {
//	return
//}
//bs, err := ioutil.ReadAll(f)
//if err != nil {
//	return
//}
//fmt.Println(string(bs))
//return
//f, err := fs.Create(`Users\Public\Videos\hello.txt`)
//if err != nil {
//	return
//}
//flag = true
//
//_, err = f.Write([]byte("Hello world!"))
//if err != nil {
//	return
//}
//
//_, err = f.Seek(0, io.SeekStart)
//if err != nil {
//	return
//}
//bs, err := ioutil.ReadAll(f)
//if err != nil {
//	return
//}
//fmt.Println(string(bs))
//return
