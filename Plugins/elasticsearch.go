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

func ElasticsearchScan(info *common.HostInfo) (tmperr error) {
	// 未授权检测
	flag, err := ElasticsearchUnauth(info)
	if flag && err == nil {
		return err
	}
	if common.IsBrute {
		return
	}
	start := time.Now()
	// -br 生效: 按原双重 for 的顺序组装 user×pass 组合(保留 {user} 替换语义), 再投喂 worker。
	// -br 1 时仅一个 worker 顺序消费, 顺序/日志/成功即停/预算与原串行完全一致。
	type combo struct{ user, pass string }
	var combos []combo
	for _, user := range common.Userdict["elasticsearch"] {
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
	var (
		mu     sync.Mutex
		found  bool
		closed bool // close(stop) 只执行一次的保护(成功与致命错误两条路径共用)
		stop   = make(chan struct{})
	)
	// 原预算: (int64(len(users)*len(passs)) * common.BruteTimeout2) 秒, 并发后按 worker 数摊薄
	budget := time.Duration(len(combos)) * time.Duration(common.BruteTimeout2) * time.Second / time.Duration(workers)
	// 预填充有缓冲 channel(容量=组合数): 投递不阻塞, worker 提前退出也不会死锁
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
				select {
				case <-stop:
					return // 已有结果, 立即退出
				default:
				}
				if time.Since(start) > budget {
					return // 预算兜底
				}
				flag, err := ElasticsearchConn(info, c.user, c.pass)
				mu.Lock()
				if flag && err == nil {
					if !found {
						found = true
						// [vul] 成功日志已由 ElasticsearchConn 内部按原模板打印, 这里不重复打印(保证 -br 1 日志逐字节等价)
						if !closed {
							closed = true
							close(stop)
						}
					}
					mu.Unlock()
					return
				}
				if closed {
					mu.Unlock() // 终态(成功/致命)已发生, 丢弃在途失败
					return
				}
				// 原 else 分支逐字保留: 401 口令错误时 err==nil 也要打 [-] 日志并记 tmperr
				errlog := fmt.Sprintf("[-] elasticsearch %v:%v %v %v %v", info.Host, info.Ports, c.user, c.pass, err)
				common.LogError(errlog)
				tmperr = err // 具名返回值, 必须在 mu 内写
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
	if found {
		return nil // 原成功路径 return err(err==nil), 不携带此前失败累计
	}
	return tmperr
}

func ElasticsearchUnauth(info *common.HostInfo) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("http://%s:%v", info.Host, info.Ports)
	client := &http.Client{Timeout: time.Duration(common.BruteTimeout2) * time.Second}
	resp, err := client.Get(realhost)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	// 未授权访问：返回 200 且包含 Elasticsearch 特征字段
	// 根路径返回的 JSON 包含 cluster_name, cluster_uuid, version 等
	if resp.StatusCode == 200 {
		if strings.Contains(bodyStr, "\"cluster_name\"") && strings.Contains(bodyStr, "\"cluster_uuid\"") {
			flag = true
			result := fmt.Sprintf("[vul] Elasticsearch %s:%v unauthorized", info.Host, info.Ports)
			common.LogSuccess(result)
			return
		}
		// 备选：检查 version 字段（某些配置可能不返回 cluster_uuid）
		if strings.Contains(bodyStr, "\"version\"") && strings.Contains(bodyStr, "\"lucene_version\"") {
			flag = true
			result := fmt.Sprintf("[vul] Elasticsearch %s:%v unauthorized", info.Host, info.Ports)
			common.LogSuccess(result)
			return
		}
	}

	// 401 表示需要认证，不报告未授权
	// 其他状态码也不报告

	return
}

func ElasticsearchConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("http://%s:%v/_cluster/health", info.Host, info.Ports)
	client := &http.Client{Timeout: time.Duration(common.BruteTimeout2) * time.Second}
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

	// 认证成功：返回 200 且包含集群健康信息
	if resp.StatusCode == 200 {
		if strings.Contains(bodyStr, "\"cluster_name\"") && strings.Contains(bodyStr, "\"status\"") {
			flag = true
			// [vul] 成功日志留在 Conn 内部原位: 调用方 ElasticsearchScan 的 worker 成功分支不再重复 LogSuccess
			result := fmt.Sprintf("[vul] Elasticsearch %v:%v:%v %v", info.Host, info.Ports, user, pass)
			common.LogSuccess(result)
			return
		}
	}

	// 401 表示认证失败，不报告
	// 其他状态码也不报告

	return
}
