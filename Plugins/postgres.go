package Plugins

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/shadow1ng/fscan/common"
	"strings"
	"sync"
	"time"
)

func PostgresScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}
	start := time.Now()
	// -br 生效: 按原双重 for 的顺序组装 user×pass 组合(保留 {user} 替换语义), 再投喂 worker。
	// -br 1 时仅一个 worker 顺序消费, 顺序/日志/成功即停/预算与原串行完全一致。
	type combo struct{ user, pass string }
	var combos []combo
	for _, user := range common.Userdict["postgresql"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", string(user), -1)
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
				flag, err := PostgresConn(info, c.user, c.pass)
				mu.Lock()
				if flag && err == nil {
					if !found {
						found = true
						// [vul] 成功日志已由 PostgresConn 内部按原模板打印, 这里不重复打印(保证 -br 1 日志逐字节等价)
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
				errlog := fmt.Sprintf("[-] psql %v:%v %v %v %v", info.Host, info.Ports, c.user, c.pass, err)
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

func PostgresConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	dataSourceName := fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v&connect_timeout=%v", Username, Password, Host, Port, "postgres", "disable", common.BruteTimeout2)
	db, err := sql.Open("postgres", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(common.BruteTimeout2) * time.Second)
		defer db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(common.BruteTimeout2)*time.Second)
		defer cancel()
		err = db.PingContext(ctx)
		if err == nil {
			// [vul] 成功日志留在 Conn 内部原位: 调用方 PostgresScan 的 worker 成功分支不再重复 LogSuccess
			result := fmt.Sprintf("[vul] Postgres:%v:%v:%v %v", Host, Port, Username, Password)
			common.LogSuccess(result)
			flag = true
		}
	}
	return flag, err
}
