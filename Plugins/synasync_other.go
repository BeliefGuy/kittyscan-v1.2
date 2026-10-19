//go:build !windows || (windows && !(amd64 || arm64))

package Plugins

// synasync_other.go — 异步 SYN 引擎的非 Windows / 32 位桩后端。
// Linux 端口扫描仍走 synscan_linux.go 的既有逐端口 raw socket 实现
// （已验证，刻意不改动）；本桩只保证跨平台编译与 EngineActive()==false。

import "fmt"

func newSynBackend(out chan<- synDatagram) (synBackend, error) {
	return nil, fmt.Errorf("%w: Windows 需 x64/arm64 + 管理员 + Npcap，Linux 仍使用逐端口 -syn 实现", errEngineNA)
}
