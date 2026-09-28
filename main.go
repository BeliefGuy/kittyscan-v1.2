package main

import (
	"fmt"
	"github.com/shadow1ng/fscan/Plugins"
	"github.com/shadow1ng/fscan/common"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	start := time.Now()
	var Info common.HostInfo

	// 在 flag 解析前检查帮助参数
	if len(os.Args) <= 1 {
		common.Banner()
		common.ShowHelp()
		return
	}
	for _, arg := range os.Args[1:] {
		if arg == "-help" || arg == "--help" {
			common.Banner()
			common.ShowHelp()
			return
		}
		if arg == "-hen" {
			common.Banner()
			common.ShowHelpEn()
			return
		}
	}

	common.Flag(&Info)
	common.Parse(&Info)

	// M3: 捕获中断信号(Windows 上 Ctrl+C 即 os.Interrupt)与 SIGTERM。
	// 收到信号后: 停止派发新任务 → 打印中断提示(-silent 时不打印) →
	// 有界等待在途任务与日志落盘(兜底超时 8 秒) → 打印完成统计 → 以 130 退出。
	// 兜底超时保证即使在途任务里有永久阻塞的(历史遗留未修的超时问题),
	// Ctrl+C 也必定能在数秒内结束进程, 不会引入无界挂起。
	// 信号协程只在收到信号时才动作; 正常扫描完成的退出路径(下方 Scan 返回后的
	// 耗时统计)完全不受影响。
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		// 第二次 Ctrl+C 恢复默认处理, 允许用户立即强杀进程
		signal.Stop(sigCh)
		Plugins.RequestStop() // 停止派发新任务(AddScan 派发前检查)
		if !common.Silent {
			fmt.Println("[-] 收到中断信号，等待在途结果落盘...")
		}
		if !common.DrainLogs(8*time.Second) && !common.Silent {
			fmt.Println("[-] 等待落盘超时，强制退出（部分在途结果可能未写出）")
		}
		if !common.Silent {
			fmt.Printf("已完成 %v/%v\n",
				atomic.LoadInt64(&common.End), atomic.LoadInt64(&common.Num))
		}
		os.Exit(130)
	}()

	Plugins.Scan(Info)
	if !common.Silent {
		fmt.Printf("[*] 扫描结束,耗时: %s\n", time.Since(start))
	}
}
