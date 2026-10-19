package Plugins

import "time"

var synAvailable = false

// TrySYNScan Windows：初始化 masscan 风格异步 SYN 引擎（Npcap 后端，
// 见 synasync_windows.go）。成功 → synAvailable=true，portscan.go 走
// portScanAsync 引擎分支（半开扫描 + 限速 + 重传）；失败（非管理员 /
// Npcap 未安装 / wpcap 加载失败）→ 保持 false，整链路回退 TCP connect，
// 行为与不加 -syn 时完全一致。具体失败原因存入 synFailHint 供 scanner.go
// 打印。Windows x86(386) 构建走 synasync_other.go 桩，恒回退。
func TrySYNScan() bool {
	if hint, err := tryStartAsyncEngine(); err != nil {
		synFailHint = hint
		return false
	}
	synFailHint = ""
	synAvailable = true
	return true
}

// SYNPortSend Windows 下端口探测统一由 portScanAsync 引擎分支处理，
// 本函数仅为兼容既有接口保留（不应被逐端口调用）。
func SYNPortSend(host string, port int, timeout time.Duration) bool {
	return false
}
