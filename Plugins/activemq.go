package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func ActivemqScan(info *common.HostInfo) (tmperr error) {
	// 未授权检测
	flag, _ := ActivemqUnauth(info)
	if flag {
		return
	}
	if common.IsBrute {
		return
	}
	// -br 并发爆破：先按原语义组装 {user} 替换后的组合列表（user 主序、pass 次序与原双重循环一致）；
	// 上面的未授权检测与 IsBrute 判断保持串行原位不动。
	type combo struct{ user, pass string }
	var combos []combo
	for _, user := range common.Userdict["activemq"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			combos = append(combos, combo{user, pass})
		}
	}
	if len(combos) == 0 {
		return tmperr
	}
	workers := common.BruteThread
	if workers < 1 {
		workers = 1
	}
	// 共享状态全部由 mu 保护；closed 保证 close(stop) 只执行一次（防重复 close panic）
	var (
		mu     sync.Mutex
		found  bool
		closed bool
		stop   = make(chan struct{})
	)
	start := time.Now()
	// 预算沿用原公式：组合数 × BruteTimeout2 秒，只按 worker 数摊薄
	budget := time.Duration(len(combos)) * time.Duration(common.BruteTimeout2) * time.Second / time.Duration(workers)
	// 预填充有缓冲 channel：容量=组合数，投递不阻塞、worker 提前退出也不会死锁
	jobs := make(chan combo, len(combos))
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
				select { // 已有结果/致命错误，立即退出
				case <-stop:
					return
				default:
				}
				if time.Since(start) > budget { // 预算兜底
					return
				}
				// ActivemqConn 内部的 url.Values 表单编码与成功判定逻辑一字未动
				flag, err := ActivemqConn(info, c.user, c.pass)
				mu.Lock()
				if flag && err == nil {
					if !found {
						found = true
						tmperr = nil // 成功返回 nil，与原 return err(err==nil) 一致
						if !closed {
							closed = true
							close(stop)
						}
					}
					mu.Unlock()
					return
				}
				if found || closed { // 已有结果，抑制在途尝试的多余 [-] 日志
					mu.Unlock()
					return
				}
				// HTTP 登录未成功（401/仍回登录页）而 err==nil 时，避免日志打出 <nil>；格式串与字段不变
				errMsg := "login rejected"
				if err != nil {
					errMsg = err.Error()
				}
				common.LogError(fmt.Sprintf("[-] activemq %v:%v %v %v %v", info.Host, info.Ports, c.user, c.pass, errMsg))
				tmperr = err
				if common.CheckErrs(err) {
					if !closed {
						closed = true
						close(stop)
					}
					mu.Unlock()
					return
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return tmperr
}

func ActivemqUnauth(info *common.HostInfo) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("http://%s:%v/admin/", info.Host, info.Ports)
	client := &http.Client{
		Timeout: time.Duration(common.BruteTimeout2) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(realhost)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.StatusCode == 200 && strings.Contains(string(body), "ActiveMQ Broker") {
		flag = true
		result := fmt.Sprintf("[vul] ActiveMQ %s:%v unauthorized", info.Host, info.Ports)
		common.LogSuccess(result)
	}
	return
}

func ActivemqConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("http://%s:%v/admin/login.jsp", info.Host, info.Ports)
	client := &http.Client{
		Timeout: time.Duration(common.BruteTimeout2) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// Q7: 表单必须做 URL 编码：口令含 &、+（会被解码成空格）、% 时，原样拼接会破坏正确口令导致漏报。
	form := url.Values{}
	form.Set("j_username", user)
	form.Set("j_password", pass)
	req, err := http.NewRequest("POST", realhost, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	// 登录成功：跳转到管理页面（不是登录页）
	if resp.StatusCode == 302 {
		location := resp.Header.Get("Location")
		// 成功跳转通常是跳转到 /admin/ 或 /admin/index.html
		if strings.Contains(location, "/admin/") && !strings.Contains(location, "login") {
			flag = true
			result := fmt.Sprintf("[vul] ActiveMQ %v:%v:%v %v", info.Host, info.Ports, user, pass)
			common.LogSuccess(result)
			return
		}
	}

	// 200 响应：必须包含管理页面特征
	if resp.StatusCode == 200 && strings.Contains(bodyStr, "ActiveMQ Console") &&
		!strings.Contains(bodyStr, "Invalid login") && !strings.Contains(bodyStr, "Login failed") {
		flag = true
		result := fmt.Sprintf("[vul] ActiveMQ %v:%v:%v %v", info.Host, info.Ports, user, pass)
		common.LogSuccess(result)
	}

	return
}
