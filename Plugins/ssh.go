package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func SshScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	starttime := time.Now().Unix()

	// -br（common.BruteThread）并发爆破：预组装 user×pass 组合，顺序与原双重 for 循环完全一致
	// （user 主序、password 次序），并保留 {user} 占位符替换语义。
	// -sshkey 私钥路径：SshConn 在 SshKey != "" 时走公钥认证、忽略密码，原逻辑每个用户在
	// 第一个密码尝试后 break 跳出密码循环继续下一用户，因此该路径每个用户只投递一个组合
	// （替换后的首个密码），语义与原串行逐条等价；密码字典为空时与原逻辑一致（内层循环不执行）直接返回。
	type sshCombo struct{ user, pass string }
	var combos []sshCombo
	if common.SshKey != "" {
		if len(common.Passwords) == 0 {
			return tmperr
		}
		for _, user := range common.Userdict["ssh"] {
			pass := strings.Replace(common.Passwords[0], "{user}", user, -1)
			combos = append(combos, sshCombo{user, pass})
		}
	} else {
		for _, user := range common.Userdict["ssh"] {
			for _, pass := range common.Passwords {
				pass = strings.Replace(pass, "{user}", user, -1)
				combos = append(combos, sshCombo{user, pass})
			}
		}
	}
	if len(combos) == 0 {
		return tmperr
	}

	// worker 数；common.BruteThread 默认 1（Parse.go 已钳制 <=0 → 1）
	workers := common.BruteThread
	if workers < 1 {
		workers = 1
	}
	// 预算：沿用原公式（字典全组合数 × Timeout 秒），只按 worker 数摊薄；
	// workers=1 时除以 1，与原表达式逐字节一致。
	budget := int64(len(common.Userdict["ssh"])*len(common.Passwords)) * common.Timeout / int64(workers)

	// 共享状态全部由 mu 保护：found/sucErr/stopped 以及具名返回值 tmperr
	var (
		mu      sync.Mutex
		found   bool
		stopped bool // 终态（成功或致命错误）已发生，close(stop) 只会执行一次
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
	jobs := make(chan sshCombo, len(combos))
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
				flag, err := SshConn(info, c.user, c.pass)
				mu.Lock()
				if stopped {
					// 终态之后到达的结果静默丢弃，避免成功后追加 [-] 日志或覆盖返回值；
					// br=1 单 worker 时 worker 在终态后即返回，不会走到这里。
					mu.Unlock()
					return
				}
				if flag == true && err == nil {
					// [vul] 由 SshConn 内部输出，这里不再重复打印（保持日志模板与次数不变）
					found = true
					sucErr = err
					signalStop()
					mu.Unlock()
					return
				}
				errlog := fmt.Sprintf("[-] ssh %v:%v %v %v %v", info.Host, info.Ports, c.user, c.pass, err)
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

func SshConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	var Auth []ssh.AuthMethod
	if common.SshKey != "" {
		pemBytes, err := os.ReadFile(common.SshKey)
		if err != nil {
			return false, errors.New("read key failed" + err.Error())
		}
		// L3: -sshkey 文件可能带 BOM(如记事本另存为 UTF-8), 裸字节直接
		// ParsePrivateKey 会失败; 先经 decodeBOMText(redis.go, 与 -rf 公钥同款)
		// 剥 UTF-8 BOM / 转码 UTF-16 后再解析。
		keyText, derr := decodeBOMText(pemBytes)
		if derr != nil {
			return false, errors.New("read key failed" + derr.Error())
		}
		signer, err := ssh.ParsePrivateKey([]byte(keyText))
		if err != nil {
			return false, errors.New("parse key failed" + err.Error())
		}
		Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		Auth = []ssh.AuthMethod{ssh.Password(Password)}
	}

	config := &ssh.ClientConfig{
		User:    Username,
		Auth:    Auth,
		Timeout: time.Duration(common.BruteTimeout) * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// Q1: ssh.ClientConfig.Timeout 只作用于 ssh.Dial 的拨号阶段；SSH 握手（NewClientConn）
	// 的阻塞读没有 deadline，卡死的目标会把全盘扫描挂死（爆破预算检查在尝试返回后才执行）。
	// 这里改为手动拨号，并在握手前对 conn 设置绝对 deadline，握手读写必在超时内报错返回。
	addr := fmt.Sprintf("%v:%v", Host, Port)
	dialTimeout := time.Duration(common.BruteTimeout) * time.Second
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		return false, err
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	// Q6: 走到这里 SSH 认证已经通过，直接判成功；会话（NewSession/命令执行）失败只单独记日志，
	// 不再因 NewSession 失败返回 (false, nil) 把有效凭据记成失败并继续爆破。
	flag = true
	// 会话阶段刷新一次 deadline，保证 NewSession/命令执行同样在超时内必返回。
	_ = conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))

	var combo string
	session, sessErr := client.NewSession()
	if sessErr != nil {
		common.LogSuccess(fmt.Sprintf("[*] ssh %v:%v auth ok but new session failed: %v", Host, Port, sessErr))
	} else {
		defer session.Close()
		if common.Command != "" {
			out, _ := session.CombinedOutput(common.Command)
			combo = string(out)
		}
	}

	var result string
	if common.Command != "" {
		result = fmt.Sprintf("[vul] SSH %v:%v:%v %v \n %v", Host, Port, Username, Password, combo)
		if common.SshKey != "" {
			result = fmt.Sprintf("[vul] SSH %v:%v sshkey correct \n %v", Host, Port, combo)
		}
	} else {
		result = fmt.Sprintf("[vul] SSH %v:%v:%v %v", Host, Port, Username, Password)
		if common.SshKey != "" {
			result = fmt.Sprintf("[vul] SSH %v:%v sshkey correct", Host, Port)
		}
	}
	common.LogSuccess(result)
	return flag, nil

}
