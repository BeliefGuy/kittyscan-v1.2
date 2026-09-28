package Plugins

import (
	"database/sql"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	_ "github.com/sijms/go-ora/v2"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// oracleServiceName 是 go-ora DSN 末段的 Oracle service name（go-ora 把 URL path 当 service name）。
// 限制：本次只允许修改 Plugins 下的 9 个文件，common/flag.go 只读，无法新增 -oraservice 命令行参数，
// 默认值保持 orcl；扫描 XE 等 service name 非 orcl 的实例时，可用环境变量 ORACLE_SERVICE 覆盖。
var oracleServiceName = func() string {
	if v := strings.TrimSpace(os.Getenv("ORACLE_SERVICE")); v != "" {
		return v
	}
	return "orcl"
}()

// escapeOracleDsnCred 对 DSN 中的 user/password 做百分号编码：
// go-ora 用 url.Parse 解析 DSN，口令含 #、/、?、@ 等字符时（默认字典里就有 admin123!@#、{user}!@#）
// 会被当成 fragment/path 截断，正确口令全部尝试失败（漏报）。
// QueryEscape 会把空格编成 '+'，而 URI userinfo 里 '+' 是字面量，故统一替换成 %20。
func escapeOracleDsnCred(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func OracleScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	start := time.Now()
	// -br 生效: 按原双重 for 的顺序组装 user×pass 组合(保留 {user} 替换语义), 再投喂 worker。
	// -br 1 时仅一个 worker 顺序消费, 顺序/日志/成功即停/预算与原串行完全一致。
	type combo struct{ user, pass string }
	var combos []combo
	for _, user := range common.Userdict["oracle"] {
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
	// 原预算: (int64(len(users)*len(passs)) * common.Timeout) 秒, 并发后按 worker 数摊薄
	budget := time.Duration(len(combos)) * time.Duration(common.Timeout) * time.Second / time.Duration(workers)
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
				flag, err := OracleConn(info, c.user, c.pass)
				mu.Lock()
				if flag && err == nil {
					if !found {
						found = true
						// [vul] 成功日志已由 OracleConn 内部按原模板打印, 这里不重复打印(保证 -br 1 日志逐字节等价)
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
				errlog := fmt.Sprintf("[-] oracle %v:%v %v %v %v", info.Host, info.Ports, c.user, c.pass, err)
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

func OracleConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	// Q4: service name 由 oracleServiceName 提供（默认 orcl，可用环境变量 ORACLE_SERVICE 覆盖）；
	// user/password 必须转义，否则含 #、/、? 的口令被 url.Parse 截断导致正确口令漏报。
	dataSourceName := fmt.Sprintf("oracle://%s:%s@%s:%s/%s",
		escapeOracleDsnCred(Username), escapeOracleDsnCred(Password), Host, Port, oracleServiceName)
	db, err := sql.Open("oracle", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(common.BruteTimeout2) * time.Second)
		db.SetConnMaxIdleTime(time.Duration(common.BruteTimeout2) * time.Second)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			// [vul] 成功日志留在 Conn 内部原位: 调用方 OracleScan 的 worker 成功分支不再重复 LogSuccess
			result := fmt.Sprintf("[vul] oracle %v:%v:%v %v", Host, Port, Username, Password)
			common.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
