package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"strings"
	"time"
)

func ZookeeperScan(info *common.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))

	// 发送 ruok 命令（ZooKeeper 四字命令）
	_, err = conn.Write([]byte("ruok"))
	if err != nil {
		return err
	}

	reply := make([]byte, 128)
	n, err := conn.Read(reply)
	if err != nil {
		return err
	}

	if strings.Contains(string(reply[:n]), "imok") {
		result := fmt.Sprintf("[vul] Zookeeper %s:%v unauthorized", info.Host, info.Ports)
		common.LogSuccess(result)
	}
	return nil
}
