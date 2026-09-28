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

func TomcatScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	// -br 并发爆破：先按原语义组装 {user} 替换后的组合列表（user 主序、pass 次序与原双重循环一致）。
	type combo struct{ user, pass string }
	var combos []combo
	for _, user := range common.Userdict["tomcat"] {
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
				flag, err := TomcatConn(info, c.user, c.pass)
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
				// 失败日志与原 else 分支逐字一致（err 可能为 nil，无条件打印）
				common.LogError(fmt.Sprintf("[-] tomcat %v:%v %v %v %v", info.Host, info.Ports, c.user, c.pass, err))
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

func TomcatConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("http://%s:%v/manager/html", info.Host, info.Ports)
	client := &http.Client{
		Timeout: time.Duration(common.BruteTimeout2) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", realhost, nil)
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

	// 登录成功判断（严格条件）
	// 依据：nuclei 模板 http/default-logins/apache/tomcat-default-login.yaml、
	// MyPocs/NucleiTP-main/high/tomcat-manager-bruteforce.yaml 均以 status==200 为必要条件；
	// HTTP 状态一律看 resp.StatusCode，绝不用 body 文本是否含 "401" 代替。
	if resp.StatusCode == 200 {
		// 分支1（保持原样）：Tomcat Manager 页面特有文案（Tomcat 源码
		// LocalStrings.properties: htmlManagerServlet.title=Tomcat Web Application Manager、
		// helpHtmlManager=HTML Manager App，为页面固定标题/导航链接）
		if strings.Contains(bodyStr, "Tomcat Web Application Manager") ||
			strings.Contains(bodyStr, "HTML Manager App") {
			flag = true
			result := fmt.Sprintf("[vul] Tomcat %v:%v:%v %v", info.Host, info.Ports, user, pass)
			common.LogSuccess(result)
			return
		}
		// 分支2（收紧，替换原 "Manager App"+"Deploy" 通用词组合）：要求 Tomcat Manager
		// 页面才有的路径结构特征——源码 HTMLManagerServlet.java MANAGER_SECTION 固定输出
		// {contextPath}/status 导航链接，DEPLOY/UPLOAD_SECTION 固定输出
		// /manager/html/deploy 与 /manager/html/upload 表单 action。路径特征不依赖页面
		// 文案语言，任何其他带 "Manager App/Deploy" 字样的管理页不再误命中。
		if strings.Contains(bodyStr, "/manager/status") &&
			(strings.Contains(bodyStr, "/manager/html/deploy") ||
				strings.Contains(bodyStr, "/manager/html/upload")) {
			flag = true
			result := fmt.Sprintf("[vul] Tomcat %v:%v:%v %v", info.Host, info.Ports, user, pass)
			common.LogSuccess(result)
			return
		}
	}

	// 302 跳转：必须是跳进 manager 页面本身（不是登录页）。
	// 参照 weblogic.go WeblogicConn 的同类修法：成功特征 + 排除 login（大小写不敏感）；
	// 并且只看 Location 的路径部分（截掉 ?query/#fragment），避免登录回跳把
	// "?redirect=/manager/html" 之类的查询参数误判为成功（原实现的主要 302 误报来源）。
	if resp.StatusCode == 302 {
		location := resp.Header.Get("Location")
		locPath := location
		if idx := strings.IndexAny(locPath, "?#"); idx >= 0 {
			locPath = locPath[:idx]
		}
		// 成功跳转通常是跳转到 /manager/html 或 /manager/html/ 或 /manager/
		if strings.Contains(locPath, "/manager/") && !strings.Contains(strings.ToLower(location), "login") {
			flag = true
			result := fmt.Sprintf("[vul] Tomcat %v:%v:%v %v", info.Host, info.Ports, user, pass)
			common.LogSuccess(result)
			return
		}
	}

	return
}
