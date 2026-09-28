package Plugins

import (
	"encoding/binary"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"io"
	"time"
)

func KafkaScan(info *common.HostInfo) error {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(common.Timeout)*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))

	// Kafka Metadata Request (API Key=3, API Version=0)
	request := []byte{
		0x00, 0x03, // API Key: Metadata
		0x00, 0x00, // API Version: 0
		0x00, 0x00, 0x00, 0x01, // Correlation ID: 1
		0x00, 0x05, // Client ID length: 5
		'k', 'i', 't', 't', 'y', // Client ID: "kitty"
		0x00, 0x00, 0x00, 0x00, // Topics: 数组长度为 Int32(4字节)，0 表示空数组
	}

	// 添加长度前缀 (4 bytes big endian)
	length := uint32(len(request))
	pkt := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(pkt[:4], length)
	copy(pkt[4:], request)

	_, err = conn.Write(pkt)
	if err != nil {
		return err
	}

	// 按 length 前缀读满整个响应：先读 4 字节长度，再读满报文体，避免单次 Read 只拿到半包
	lenBuf := make([]byte, 4)
	if _, err = io.ReadFull(conn, lenBuf); err != nil {
		return err
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	// 有效响应至少要装下 correlation_id(4) + broker count(4)；异常长度直接放弃判定
	if respLen < 8 || respLen > 65536 {
		return nil
	}
	reply := make([]byte, 4+respLen)
	copy(reply, lenBuf)
	if _, err = io.ReadFull(conn, reply[4:]); err != nil {
		return err
	}
	n := len(reply)

	// 检查响应：Kafka Metadata Response 包含 broker 信息
	// 响应格式: [4 bytes length] [4 bytes correlation_id] [4 bytes broker count] ...
	// 至少需要 12 字节的有效响应，且 correlation_id 应为 1
	if n >= 12 {
		// 跳过4字节长度前缀，检查 correlation ID (应为1)
		corrID := binary.BigEndian.Uint32(reply[4:8])
		if corrID == 1 {
			result := fmt.Sprintf("[vul] Kafka %s:%v unauthorized", info.Host, info.Ports)
			common.LogSuccess(result)
		}
	}
	return nil
}
