package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

func SvnScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	// -br（common.BruteThread）并发爆破：预组装 user×pass 组合，顺序与原双重 for 循环完全一致
	// （user 主序、password 次序），并保留 {user} 占位符替换语义。
	type svnCombo struct{ user, pass string }
	var combos []svnCombo
	for _, user := range common.Userdict["svn"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			combos = append(combos, svnCombo{user, pass})
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
	// 预算：沿用原公式（字典全组合数 × BruteTimeout2 秒），只按 worker 数摊薄；
	// workers=1 时与原表达式一致。
	budget := int64(len(common.Userdict["svn"])*len(common.Passwords)) * common.BruteTimeout2 / int64(workers)

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
	jobs := make(chan svnCombo, len(combos))
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
				flag, err := SvnConn(info, c.user, c.pass)
				mu.Lock()
				if stopped {
					// 终态之后到达的结果静默丢弃（br=1 单 worker 时不会走到这里）
					mu.Unlock()
					return
				}
				if flag && err == nil {
					// [vul] 由 SvnConn 内部输出，这里不再重复打印（保持日志模板与次数不变）
					found = true
					sucErr = err
					signalStop()
					mu.Unlock()
					return
				}
				errlog := fmt.Sprintf("[-] svn %v:%v %v %v %v", info.Host, info.Ports, c.user, c.pass, err)
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

func SvnConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("http://%s:%v/", info.Host, info.Ports)
	client := &http.Client{
		Timeout: time.Duration(common.BruteTimeout2) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("OPTIONS", realhost, nil)
	if err != nil {
		return
	}
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	// 认证成功：返回 200 且有 DAV/SVN 相关头或内容
	// 必须同时满足：1) 状态码 200 2) 有 SVN/DAV 特征 3) 不是认证失败页面
	if resp.StatusCode == 200 {
		hasSVNFeature := strings.Contains(resp.Header.Get("DAV"), "svn") ||
			strings.Contains(resp.Header.Get("Server"), "SVN") ||
			strings.Contains(bodyStr, "SVN") ||
			strings.Contains(bodyStr, "svn://") ||
			strings.Contains(bodyStr, "Subversion")
		isNotFailure := !strings.Contains(bodyStr, "401") &&
			!strings.Contains(bodyStr, "Unauthorized") &&
			!strings.Contains(bodyStr, "Authentication failed")

		if hasSVNFeature && isNotFailure {
			flag = true
			result := fmt.Sprintf("[vul] SVN %v:%v:%v %v", info.Host, info.Ports, user, pass)
			common.LogSuccess(result)
		}
	}

	// 401 表示认证失败，不报告
	// 其他状态码也不报告

	return
}
