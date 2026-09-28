package Plugins

import (
	"encoding/binary"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"io"
	"net"
	"strings"
	"time"
)

func MongodbScan(info *common.HostInfo) error {
	// 本函数唯一功能就是未授权检测，无爆破环节：-nobr 不应跳过
	_, err := MongodbUnauth(info)
	if err != nil {
		errlog := fmt.Sprintf("[-] Mongodb %v:%v %v", info.Host, info.Ports, err)
		common.LogError(errlog)
	}
	return err
}

func MongodbUnauth(info *common.HostInfo) (flag bool, err error) {
	flag = false
	// op_msg
	packet1 := []byte{
		0x69, 0x00, 0x00, 0x00, // messageLength
		0x39, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xdd, 0x07, 0x00, 0x00, // opCode OP_MSG
		0x00, 0x00, 0x00, 0x00, // flagBits
		// sections db.adminCommand({getLog: "startupWarnings"})
		0x00, 0x54, 0x00, 0x00, 0x00, 0x02, 0x67, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x57, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x02, 0x24, 0x64, 0x62, 0x00, 0x06, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00, 0x03, 0x6c, 0x73, 0x69, 0x64, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x05, 0x69, 0x64, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x6e, 0x81, 0xf8, 0x8e, 0x37, 0x7b, 0x4c, 0x97, 0x84, 0x4e, 0x90, 0x62, 0x5a, 0x54, 0x3c, 0x93, 0x00, 0x00,
	}
	//op_query
	packet2 := []byte{
		0x48, 0x00, 0x00, 0x00, // messageLength
		0x02, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xd4, 0x07, 0x00, 0x00, // opCode OP_QUERY
		0x00, 0x00, 0x00, 0x00, // flags
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // fullCollectionName admin.$cmd
		0x00, 0x00, 0x00, 0x00, // numberToSkip
		0x01, 0x00, 0x00, 0x00, // numberToReturn
		// query db.adminCommand({getLog: "startupWarnings"})
		0x21, 0x00, 0x00, 0x00, 0x2, 0x67, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x57, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x00,
	}

	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	checkUnAuth := func(address string, packet []byte) (string, error) {
		conn, err := common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(common.Timeout)*time.Second)
		if err != nil {
			return "", err
		}
		defer conn.Close()
		err = conn.SetReadDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
		if err != nil {
			return "", err
		}
		_, err = conn.Write(packet)
		if err != nil {
			return "", err
		}
		// 按 wire protocol 消息头循环读满整帧：前 4 字节为小端 messageLength
		// (含自身)，再读满剩余部分。固定 1024 字节单次 Read 在响应 >1024 或
		// TCP 分片时会截断尾部，导致 totalLinesWritten 特征漏报(S5)。
		// 首帧用建立连接时设置的超时；之后给一个短暂宽限期探测后续帧，
		// 读到超时即视为响应结束，避免为每帧空等完整超时。
		var msg []byte
		for {
			frame, ferr := readMongoFrame(conn)
			if ferr != nil {
				if len(msg) == 0 {
					// 一帧都没读到：保留原有错误路径(交给调用方回退 packet2)
					return "", ferr
				}
				// 已有完整帧后再读失败(超时/对端关闭)：按响应结束处理
				break
			}
			msg = append(msg, frame...)
			if len(msg) >= maxMongoMessageLength {
				break
			}
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		}
		return string(msg), nil
	}

	// send OP_MSG first
	reply, err := checkUnAuth(realhost, packet1)
	if err != nil {
		reply, err = checkUnAuth(realhost, packet2)
		if err != nil {
			return flag, err
		}
	}
	if strings.Contains(reply, "totalLinesWritten") {
		flag = true
		result := fmt.Sprintf("[vul] Mongodb %v unauthorized", realhost)
		common.LogSuccess(result)
	}
	return flag, err
}

// maxMongoMessageLength 单帧上限 4MB：messageLength 由对端控制，
// 不设上限时恶意/畸形响应可声明巨帧导致大内存分配。
const maxMongoMessageLength = 4 * 1024 * 1024

// readMongoFrame 按 MongoDB wire protocol 读取一整帧消息：
// 前 4 字节为小端 messageLength(含这 4 字节自身)，再 io.ReadFull 读满
// 剩余 msgLen-4 字节，返回完整帧(含消息头)。
func readMongoFrame(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	msgLen := binary.LittleEndian.Uint32(hdr[:])
	if msgLen < 4 || uint64(msgLen) > uint64(maxMongoMessageLength) {
		return nil, fmt.Errorf("mongodb: invalid message length %d", msgLen)
	}
	body := make([]byte, int(msgLen)-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	frame := make([]byte, 0, int(msgLen))
	frame = append(frame, hdr[:]...)
	frame = append(frame, body...)
	return frame, nil
}
