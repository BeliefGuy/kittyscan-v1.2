package Plugins

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"strings"
	"time"
)

var (
	negotiateProtocolRequest_enc  = "G8o+kd/4y8chPCaObKK8L9+tJVFBb7ntWH/EXJ74635V3UTXA4TFOc6uabZfuLr0Xisnk7OsKJZ2Xdd3l8HNLdMOYZXAX5ZXnMC4qI+1d/MXA2TmidXeqGt8d9UEF5VesQlhP051GGBSldkJkVrP/fzn4gvLXcwgAYee3Zi2opAvuM6ScXrMkcbx200ThnOOEx98/7ArteornbRiXQjnr6dkJEUDTS43AW6Jl3OK2876Yaz5iYBx+DW5WjiLcMR+b58NJRxm4FlVpusZjBpzEs4XOEqglk6QIWfWbFZYgdNLy3WaFkkgDjmB1+6LhpYSOaTsh4EM0rwZq2Z4Lr8TE5WcPkb/JNsWNbibKlwtNtp94fIYvAWgxt5mn/oXpfUD"
	sessionSetupRequest_enc       = "52HeCQEbsSwiSXg98sdD64qyRou0jARlvfQi1ekDHS77Nk/8dYftNXlFahLEYWIxYYJ8u53db9OaDfAvOEkuox+p+Ic1VL70r9Q5HuL+NMyeyeN5T5el07X5cT66oBDJnScs1XdvM6CBRtj1kUs2h40Z5Vj9EGzGk99SFXjSqbtGfKFBp0DhL5wPQKsoiXYLKKh9NQiOhOMWHYy/C+Iwhf3Qr8d1Wbs2vgEzaWZqIJ3BM3z+dhRBszQoQftszC16TUhGQc48XPFHN74VRxXgVe6xNQwqrWEpA4hcQeF1+QqRVHxuN+PFR7qwEcU1JbnTNISaSrqEe8GtRo1r2rs7+lOFmbe4qqyUMgHhZ6Pwu1bkhrocMUUzWQBogAvXwFb8"
	treeConnectRequest_enc        = "+b/lRcmLzH0c0BYhiTaYNvTVdYz1OdYYDKhzGn/3T3P4b6pAR8D+xPdlb7O4D4A9KMyeIBphDPmEtFy44rtto2dadFoit350nghebxbYA0pTCWIBd1kN0BGMEidRDBwLOpZE6Qpph/DlziDjjfXUz955dr0cigc9ETHD/+f3fELKsopTPkbCsudgCs48mlbXcL13GVG5cGwKzRuP4ezcdKbYzq1DX2I7RNeBtw/vAlYh6etKLv7s+YyZ/r8m0fBY9A57j+XrsmZAyTWbhPJkCg=="
	transNamedPipeRequest_enc     = "k/RGiUQ/tw1yiqioUIqirzGC1SxTAmQmtnfKd1qiLish7FQYxvE+h4/p7RKgWemIWRXDf2XSJ3K0LUIX0vv1gx2eb4NatU7Qosnrhebz3gUo7u25P5BZH1QKdagzPqtitVjASpxIjB3uNWtYMrXGkkuAm8QEitberc+mP0vnzZ8Nv/xiiGBko8O4P/wCKaN2KZVDLbv2jrN8V/1zY6fvWA=="
	trans2SessionSetupRequest_enc = "JqNw6PUKcWOYFisUoUCyD24wnML2Yd8kumx9hJnFWbhM2TQkRvKHsOMWzPVfggRrLl8sLQFqzk8bv8Rpox3uS61l480Mv7HdBPeBeBeFudZMntXBUa4pWUH8D9EXCjoUqgAdvw6kGbPOOKUq3WmNb0GDCZapqQwyUKKMHmNIUMVMAOyVfKeEMJA6LViGwyvHVMNZ1XWLr0xafKfEuz4qoHiDyVWomGjJt8DQd6+jgLk="
	negotiateProtocolRequest, _   = hex.DecodeString(AesDecrypt(negotiateProtocolRequest_enc, key))
	sessionSetupRequest, _        = hex.DecodeString(AesDecrypt(sessionSetupRequest_enc, key))
	treeConnectRequest, _         = hex.DecodeString(AesDecrypt(treeConnectRequest_enc, key))
	transNamedPipeRequest, _      = hex.DecodeString(AesDecrypt(transNamedPipeRequest_enc, key))
	trans2SessionSetupRequest, _  = hex.DecodeString(AesDecrypt(trans2SessionSetupRequest_enc, key))
)

func MS17010(info *common.HostInfo) error {
	// 纯漏洞检测函数，无爆破环节：-nobr(仅做漏洞检测) 不应跳过本检测
	err := MS17010Scan(info)
	if err != nil {
		errlog := fmt.Sprintf("[-] Ms17010 %v %v", info.Host, err)
		common.LogError(errlog)
	}
	return err
}

func MS17010Scan(info *common.HostInfo) error {
	ip := info.Host
	// connecting to a host in LAN if reachable should be very quick
	conn, err := common.WrapperTcpWithTimeout("tcp", ip+":445", time.Duration(common.Timeout)*time.Second)
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		return err
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(common.Timeout) * time.Second))
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		return err
	}
	// 包级模板切片禁止就地改写：多主机并发调用时共享同一底层数组，
	// TreeID/UserID 会互相串包导致校验失败漏报/误判（数据竞争）。
	// 每次调用改用独立的局部副本。
	treeConnect := append([]byte(nil), treeConnectRequest...)
	transNamedPipe := append([]byte(nil), transNamedPipeRequest...)
	trans2SessionSetup := append([]byte(nil), trans2SessionSetupRequest...)
	_, err = conn.Write(negotiateProtocolRequest)
	if err != nil {
		return err
	}
	reply := make([]byte, 1024)
	// let alone half packet
	if n, err := conn.Read(reply); err != nil {
		return err
	} else if n < 36 {
		// 响应长度不足属检测异常(畸形/蜜罐响应)：原逻辑 err==nil 时静默
		// 返回 nil，MS17010() 的 [-] 错误日志不触发，改为返回明确错误
		return fmt.Errorf("short negotiate protocol response (n=%d)", n)
	}

	if status := binary.LittleEndian.Uint32(reply[9:13]); status != 0 {
		// status != 0：无法进入后续检测，按"检测异常"上报(原为静默返回 nil)，
		// 与下面 session setup status!=0 的报错语义保持一致
		return fmt.Errorf("negotiate response status != 0 (0x%08x), can't determine whether target is vulnerable or not", status)
	}

	_, err = conn.Write(sessionSetupRequest)
	if err != nil {
		return err
	}
	n, err := conn.Read(reply)
	if err != nil {
		return err
	}
	if n < 36 {
		// 响应长度不足属检测异常，静默返回 nil 会掩盖异常，改为返回错误
		return fmt.Errorf("short session setup response (n=%d)", n)
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		//fmt.Printf("can't determine whether %s is vulnerable or not\n", ip)
		var Err = errors.New("can't determine whether target is vulnerable or not")
		return Err
	}

	// extract OS info
	var os string
	sessionSetupResponse := reply[36:n]
	// 先校验长度再取值：n==36 时空切片、n∈[37,44] 时不足 9 字节，
	// 原逻辑会越界 panic（畸形/蜜罐响应），这里改为返回错误
	if len(sessionSetupResponse) == 0 {
		return errors.New("ms17010 invalid session setup response: empty")
	}
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		if len(sessionSetupResponse) < 9 {
			return fmt.Errorf("ms17010 invalid session setup AndX response: length %d too short", len(sessionSetupResponse))
		}
		// find byte count
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount)+45 {
			fmt.Println("[-]", ip+":445", "ms17010 invalid session setup AndX response")
		} else {
			// two continous null bytes indicates end of a unicode string
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					os = string(sessionSetupResponse[10:i])
					os = strings.Replace(os, string([]byte{0x00}), "", -1)
					break
				}
			}
		}

	}
	userID := reply[32:34]
	treeConnect[32] = userID[0]
	treeConnect[33] = userID[1]
	// TODO change the ip in tree path though it doesn't matter
	_, err = conn.Write(treeConnect)
	if err != nil {
		return err
	}
	if n, err := conn.Read(reply); err != nil {
		return err
	} else if n < 36 {
		// 响应长度不足属检测异常，不再静默返回 nil
		return fmt.Errorf("short tree connect response (n=%d)", n)
	}

	treeID := reply[28:30]
	transNamedPipe[28] = treeID[0]
	transNamedPipe[29] = treeID[1]
	transNamedPipe[32] = userID[0]
	transNamedPipe[33] = userID[1]

	_, err = conn.Write(transNamedPipe)
	if err != nil {
		return err
	}
	if n, err := conn.Read(reply); err != nil {
		return err
	} else if n < 36 {
		// 响应长度不足属检测异常，不再静默返回 nil
		return fmt.Errorf("short trans named pipe response (n=%d)", n)
	}

	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		//fmt.Printf("%s\tMS17-010\t(%s)\n", ip, os)
		//if runtime.GOOS=="windows" {fmt.Printf("%s\tMS17-010\t(%s)\n", ip, os)
		//} else{fmt.Printf("\033[33m%s\tMS17-010\t(%s)\033[0m\n", ip, os)}
		result := fmt.Sprintf("[vul] MS17-010 %s\t(%s)", ip, os)
		common.LogSuccess(result)
		defer func() {
			if common.SC != "" {
				MS17010EXP(info)
			}
		}()
		// detect present of DOUBLEPULSAR SMB implant
		trans2SessionSetup[28] = treeID[0]
		trans2SessionSetup[29] = treeID[1]
		trans2SessionSetup[32] = userID[0]
		trans2SessionSetup[33] = userID[1]

		_, err = conn.Write(trans2SessionSetup)
		if err != nil {
			return err
		}
		if n, err := conn.Read(reply); err != nil {
			return err
		} else if n < 36 {
			// 响应长度不足属检测异常，不再静默返回 nil
			return fmt.Errorf("short trans2 session setup response (n=%d)", n)
		}

		if reply[34] == 0x51 {
			result := fmt.Sprintf("[vul] MS17-010 %s has DOUBLEPULSAR SMB IMPLANT", ip)
			common.LogSuccess(result)
		}

	} else {
		result := fmt.Sprintf("[*] OsInfo %s\t(%s)", ip, os)
		common.LogSuccess(result)
	}
	return err

}
