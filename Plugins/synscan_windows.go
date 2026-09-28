package Plugins

import "time"

var synAvailable = false

// TrySYNScan Windows 不支持原生 SYN 扫描（需要 Npcap cgo 集成，暂未实现）
func TrySYNScan() bool {
	return false
}

// SYNPortSend Windows 下不会被调用
func SYNPortSend(host string, port int, timeout time.Duration) bool {
	return false
}
