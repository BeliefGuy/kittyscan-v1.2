package Plugins

import (
	"bufio"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RTSP默认超时（秒）
var RtspTimeout int64 = 3

// RTSP默认路径（常用路径优先，按厂商分类）
var rtspPaths = []string{
	// 通用路径
	"/",
	"/live",
	"/stream",
	"/video",
	"/live/main",                // 通用主码流
	"/live/sub",                 // 通用子码流
	"/stream1",                  // 通用主码流
	"/stream2",                  // 通用子码流
	"/video1",                   // 通用主码流
	"/video2",                   // 通用子码流
	"/h264",
	"/media",
	"/cam",
	"/channel",
	"/rtsp/live",

	// 海康威视
	"/Streaming/Channels/101",   // 海康主码流
	"/Streaming/Channels/102",   // 海康子码流
	"/Streaming/Channels/101?transportmode=unicast&profile=Profile_1",
	"/h264/ch1/main/av_stream",  // 海康旧版
	"/1",                        // 海康部分版本
	"/ch01.264",                 // 海康
	"/ch01_0.264",               // 海康

	// 大华
	"/cam/realmonitor?channel=1&subtype=0", // 大华主码流
	"/cam/realmonitor?channel=1&subtype=1", // 大华子码流
	"/realmonitor",              // 大华

	// 宇视
	"/ucast/11",                 // 宇视
	"/media/video1",             // 宇视
	"/unicast/c10/s0/live",      // 宇视

	// 中威
	"/Streaming/Channels/1",     // 中威

	// 三星
	"/onvif/profile2/media.smp", // 三星高码流
	"/onvif/profile3/media.smp", // 三星低码流

	// 英飞拓
	"/1/1080p",                  // 英飞拓高码流
	"/1/D1",                     // 英飞拓低码流
	"/1/h264major",              // 英飞拓高码流
	"/1/h264minor",              // 英飞拓低码流

	// LG
	"/Master-0",                 // LG高码流
	"/Slave-0",                  // LG低码流

	// 派尔高
	"/h264",                     // 派尔高
	"/h264_2",                   // 派尔高第一码流

	// 安迅士 (AXIS)
	"/axis-media/media.amp",     // 安迅士
	"/onvif-media/media.amp",    // 安迅士组播

	// 非凡
	"/streaming/channels/101",   // 非凡

	// 金三立
	"/stream/av0_0",             // 金三立

	// 浪潮
	"/live.sdp",                 // 浪潮

	// Activecam
	"/live/main",                // Activecam主码流（已包含）

	// 华为
	"/LiveMedia/ch1/Media2",     // 华为

	// 华视安邦
	"/live/0/MAIN",              // 华视安邦主码流
	"/live/0/SUB",               // 华视安邦子码流

	// 科达
	"/id=0",                     // 科达V5
	"/realtime?id=0",            // 科达V7
}

// RTSP URL参数认证路径（雄迈等，用户名密码在URL参数中）
var rtspUrlAuthPaths = []string{
	"/user=admin&password=&channel=1&stream=0.sdp?real_stream",  // 雄迈主码流
	"/user=admin&password=&channel=1&stream=1.sdp?real_stream",  // 雄迈子码流
	"/user=admin&password=&channel=1&stream=0.sdp",              // 雄迈变体
}

// RtspScan 扫描RTSP服务
func RtspScan(info *common.HostInfo) (tmperr error) {
	// 先检测未授权访问（找到第一个就停止）；-nobr 下保留本纯检测
	vulnPath, flag := RtspCheckUnauthorized(info)
	if flag {
		// 输出完整URL（未授权，无用户名密码）
		result := fmt.Sprintf("[vul] rtsp://%s:%v%s Unauthorized Access", info.Host, info.Ports, vulnPath)
		common.LogSuccess(result)
		return nil
	}

	// 尝试URL参数认证（雄迈等设备）：内部先做未授权检测，
	// -nobr 只跳过其中的爆破循环（见 RtspBruteForceUrlAuth 内的 IsBrute 判断）
	vulnPath, flag = RtspBruteForceUrlAuth(info)
	if flag {
		return nil
	}

	// -nobr：跳过密码爆破（仅做漏洞检测），上面的未授权检测已执行完毕
	if common.IsBrute {
		return nil
	}

	// 如果未授权失败，尝试标准认证爆破
	// 先探测哪个路径返回401（需要认证）
	brutePath, authType := RtspFindAuthPath(info)
	if brutePath == "" {
		return fmt.Errorf("no rtsp path found")
	}

	// 使用全局字典进行爆破（只对找到的路径爆破）
	// -br 并发爆破：先按原语义组装 {user} 替换后的组合列表（user 主序、pass 次序与原双重循环一致）。
	type combo struct{ user, pass string }
	var combos []combo
	for _, user := range common.Userdict["rtsp"] {
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
	// 共享状态全部由 mu 保护；closed 保证 close(stop) 只执行一次（防重复 close panic）
	var (
		mu     sync.Mutex
		found  bool
		closed bool
		stop   = make(chan struct{})
	)
	start := time.Now()
	// 预算沿用原公式：组合数 × RtspTimeout 秒，只按 worker 数摊薄
	budget := time.Duration(len(combos)) * time.Duration(RtspTimeout) * time.Second / time.Duration(workers)
	// 预填充有缓冲 channel：容量=组合数，投递不阻塞、worker 提前退出也不会死锁
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
				select { // 已有结果/致命错误，立即退出
				case <-stop:
					return
				default:
				}
				if time.Since(start) > budget { // 预算兜底
					return
				}
				// RtspBruteForce 内部的 Basic/Digest（qop）协议逻辑一字未动
				flag, err := RtspBruteForce(info, brutePath, c.user, c.pass, authType)
				mu.Lock()
				if flag && err == nil {
					if !found {
						found = true
						tmperr = nil // 成功返回 nil，与原 return err(err==nil) 一致
						if !closed {
							closed = true
							close(stop)
						}
					}
					mu.Unlock()
					return
				}
				if found || closed { // 已有结果，抑制在途尝试的多余 [-] 日志
					mu.Unlock()
					return
				}
				// 失败日志与原 else 分支逐字一致（原模板即不带 err 字段）
				common.LogError(fmt.Sprintf("[-] rtsp %v:%v %v %v/%v", info.Host, info.Ports, brutePath, c.user, c.pass))
				tmperr = err
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
	return tmperr
}

// RtspCheckUnauthorized 检测RTSP未授权访问（找到第一个就停止）
func RtspCheckUnauthorized(info *common.HostInfo) (string, bool) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	// 合并所有路径
	allPaths := append(rtspPaths, rtspUrlAuthPaths...)

	for _, path := range allPaths {
		conn, err := net.DialTimeout("tcp", realhost, time.Duration(RtspTimeout)*time.Second)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(time.Duration(RtspTimeout) * time.Second))

		// 发送DESCRIBE请求（比OPTIONS更准确）
		request := fmt.Sprintf("DESCRIBE rtsp://%s%s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LibVLC/3.0.8\r\nAccept: application/sdp\r\n\r\n", realhost, path)
		_, err = conn.Write([]byte(request))
		if err != nil {
			conn.Close()
			continue
		}

		// 读取完整响应
		reader := bufio.NewReader(conn)
		response := ""
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			response += line
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		conn.Close()

		// 检查响应状态
		if strings.Contains(response, "200 OK") || strings.Contains(response, "200 ") {
			// 未授权访问成功，返回路径
			return path, true
		}
	}

	return "", false
}

// RtspFindAuthPath 探测哪个路径需要认证（返回第一个401的路径和认证类型）
func RtspFindAuthPath(info *common.HostInfo) (string, string) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	for _, path := range rtspPaths {
		conn, err := net.DialTimeout("tcp", realhost, time.Duration(RtspTimeout)*time.Second)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(time.Duration(RtspTimeout) * time.Second))

		// 发送DESCRIBE请求
		request := fmt.Sprintf("DESCRIBE rtsp://%s%s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LibVLC/3.0.8\r\nAccept: application/sdp\r\n\r\n", realhost, path)
		_, err = conn.Write([]byte(request))
		if err != nil {
			conn.Close()
			continue
		}

		// 读取完整响应
		reader := bufio.NewReader(conn)
		response := ""
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			response += line
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		conn.Close()

		// 检查响应状态
		if strings.Contains(response, "401") {
			// 需要认证，判断认证类型
			if strings.Contains(response, "WWW-Authenticate: Digest") {
				return path, "digest"
			} else if strings.Contains(response, "WWW-Authenticate: Basic") {
				return path, "basic"
			}
			return path, "basic" // 默认使用basic
		}
	}

	// 如果没有找到401，返回第一个路径
	if len(rtspPaths) > 0 {
		return rtspPaths[0], "basic"
	}
	return "", ""
}

// RtspBruteForceUrlAuth URL参数认证爆破（雄迈等设备）
func RtspBruteForceUrlAuth(info *common.HostInfo) (string, bool) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	// 先测试一个URL参数路径，看是否需要认证
	testPath := rtspUrlAuthPaths[0]
	conn, err := net.DialTimeout("tcp", realhost, time.Duration(RtspTimeout)*time.Second)
	if err != nil {
		return "", false
	}
	conn.SetDeadline(time.Now().Add(time.Duration(RtspTimeout) * time.Second))

	request := fmt.Sprintf("DESCRIBE rtsp://%s%s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LibVLC/3.0.8\r\nAccept: application/sdp\r\n\r\n", realhost, testPath)
	_, err = conn.Write([]byte(request))
	if err != nil {
		conn.Close()
		return "", false
	}

	// 读取响应
	reader := bufio.NewReader(conn)
	response := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		response += line
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	conn.Close()

	// 如果返回200，说明是未授权（URL参数中password为空）
	if strings.Contains(response, "200 OK") || strings.Contains(response, "200 ") {
		return testPath, true
	}

	// 如果返回401，尝试爆破URL参数中的密码
	if strings.Contains(response, "401") {
		// -nobr：到此未授权检测已完成（上面 200 分支），这里跳过口令爆破循环
		if common.IsBrute {
			return "", false
		}
		// -br 并发爆破：先按原语义组装 {user} 替换后的组合列表（user 主序、pass 次序与原三重循环一致）。
		// 原循环没有超时预算、也没有 [-] 失败日志，保持原样，只把遍历字典的循环外壳换成 worker 池。
		type combo struct{ user, pass string }
		var combos []combo
		for _, user := range common.Userdict["rtsp"] {
			for _, pass := range common.Passwords {
				pass = strings.Replace(pass, "{user}", user, -1)
				combos = append(combos, combo{user, pass})
			}
		}
		if len(combos) == 0 {
			return "", false
		}
		workers := common.BruteThread
		if workers < 1 {
			workers = 1
		}
		// 共享状态全部由 mu 保护；closed 保证 close(stop) 只执行一次（防重复 close panic）
		var (
			mu        sync.Mutex
			found     bool
			foundPath string
			closed    bool
			stop      = make(chan struct{})
		)
		// 预填充有缓冲 channel：容量=组合数，投递不阻塞、worker 提前退出也不会死锁
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
					select { // 已有结果，立即退出
					case <-stop:
						return
					default:
					}
					for _, path := range rtspUrlAuthPaths {
						select { // 已有结果，立即退出
						case <-stop:
							return
						default:
						}
						// 替换URL参数中的用户名和密码
						brutePath := strings.Replace(path, "admin", c.user, 1)
						brutePath = strings.Replace(brutePath, "password=", "password="+c.pass, 1)

						conn2, err := net.DialTimeout("tcp", realhost, time.Duration(RtspTimeout)*time.Second)
						if err != nil {
							continue
						}
						conn2.SetDeadline(time.Now().Add(time.Duration(RtspTimeout) * time.Second))

						request2 := fmt.Sprintf("DESCRIBE rtsp://%s%s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LibVLC/3.0.8\r\nAccept: application/sdp\r\n\r\n", realhost, brutePath)
						_, err = conn2.Write([]byte(request2))
						if err != nil {
							conn2.Close()
							continue
						}

						// 读取响应
						reader2 := bufio.NewReader(conn2)
						response2 := ""
						for {
							line, err := reader2.ReadString('\n')
							if err != nil {
								break
							}
							response2 += line
							if line == "\r\n" || line == "\n" {
								break
							}
						}
						conn2.Close()

						// 检查是否成功
						if strings.Contains(response2, "200 OK") || strings.Contains(response2, "200 ") {
							mu.Lock()
							if !found {
								found = true
								foundPath = brutePath
								// 输出完整URL（带用户名密码）；found 保护，成功日志只打一次
								result := fmt.Sprintf("[vul] rtsp://%s:%v%s Brute Success %s/%s", info.Host, info.Ports, brutePath, c.user, c.pass)
								common.LogSuccess(result)
								if !closed {
									closed = true
									close(stop)
								}
							}
							mu.Unlock()
							return
						}
					}
				}
			}()
		}
		wg.Wait()
		if found {
			return foundPath, true
		}
	}

	return "", false
}

// RtspBruteForce 尝试RTSP爆破（只对指定路径）
func RtspBruteForce(info *common.HostInfo, path string, user string, pass string, authType string) (bool, error) {
	if authType == "digest" {
		return RtspBruteForceDigest(info, path, user, pass)
	}
	return RtspBruteForceBasic(info, path, user, pass)
}

// RtspBruteForceBasic Basic认证爆破
func RtspBruteForceBasic(info *common.HostInfo, path string, user string, pass string) (bool, error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	conn, err := net.DialTimeout("tcp", realhost, time.Duration(RtspTimeout)*time.Second)
	if err != nil {
		return false, err
	}
	conn.SetDeadline(time.Now().Add(time.Duration(RtspTimeout) * time.Second))

	// 构造Basic认证头
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))

	// 发送带认证的DESCRIBE请求
	request := fmt.Sprintf("DESCRIBE rtsp://%s%s RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic %s\r\nUser-Agent: LibVLC/3.0.8\r\nAccept: application/sdp\r\n\r\n", realhost, path, auth)
	_, err = conn.Write([]byte(request))
	if err != nil {
		conn.Close()
		return false, err
	}

	// 读取响应
	reader := bufio.NewReader(conn)
	response := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		response += line
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	conn.Close()

	// 检查是否认证成功
	if strings.Contains(response, "200 OK") || strings.Contains(response, "200 ") {
		// 输出完整URL（带用户名密码）
		result := fmt.Sprintf("[vul] rtsp://%s:%v%s Brute Success %s/%s", info.Host, info.Ports, path, user, pass)
		common.LogSuccess(result)
		return true, nil
	}

	return false, fmt.Errorf("authentication failed")
}

// RtspBruteForceDigest Digest认证爆破
func RtspBruteForceDigest(info *common.HostInfo, path string, user string, pass string) (bool, error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	// 第一步：获取nonce和realm
	conn, err := net.DialTimeout("tcp", realhost, time.Duration(RtspTimeout)*time.Second)
	if err != nil {
		return false, err
	}
	conn.SetDeadline(time.Now().Add(time.Duration(RtspTimeout) * time.Second))

	request := fmt.Sprintf("DESCRIBE rtsp://%s%s RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: LibVLC/3.0.8\r\nAccept: application/sdp\r\n\r\n", realhost, path)
	_, err = conn.Write([]byte(request))
	if err != nil {
		conn.Close()
		return false, err
	}

	// 读取响应
	reader := bufio.NewReader(conn)
	response := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		response += line
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	conn.Close()

	// 提取nonce和realm
	nonce := extractDigestValue(response, "nonce")
	realm := extractDigestValue(response, "realm")
	if nonce == "" || realm == "" {
		return false, fmt.Errorf("failed to extract digest params")
	}

	// 第二步：发送带Digest认证的请求
	conn2, err := net.DialTimeout("tcp", realhost, time.Duration(RtspTimeout)*time.Second)
	if err != nil {
		return false, err
	}
	conn2.SetDeadline(time.Now().Add(time.Duration(RtspTimeout) * time.Second))

	// 计算Digest响应
	uri := fmt.Sprintf("rtsp://%s%s", realhost, path)
	responseHash := calcDigestResponse(user, realm, pass, "DESCRIBE", uri, nonce)

	// 构造Digest认证头
	authHeader := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`, user, realm, nonce, uri, responseHash)
	request2 := fmt.Sprintf("DESCRIBE rtsp://%s%s RTSP/1.0\r\nCSeq: 2\r\nAuthorization: %s\r\nUser-Agent: LibVLC/3.0.8\r\nAccept: application/sdp\r\n\r\n", realhost, path, authHeader)
	_, err = conn2.Write([]byte(request2))
	if err != nil {
		conn2.Close()
		return false, err
	}

	// 读取响应
	reader2 := bufio.NewReader(conn2)
	response2 := ""
	for {
		line, err := reader2.ReadString('\n')
		if err != nil {
			break
		}
		response2 += line
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	conn2.Close()

	// 检查是否认证成功
	if strings.Contains(response2, "200 OK") || strings.Contains(response2, "200 ") {
		// 输出完整URL（带用户名密码）
		result := fmt.Sprintf("[vul] rtsp://%s:%v%s Brute Success %s/%s", info.Host, info.Ports, path, user, pass)
		common.LogSuccess(result)
		return true, nil
	}

	return false, fmt.Errorf("authentication failed")
}

// extractDigestValue 从响应中提取Digest认证参数
func extractDigestValue(response, key string) string {
	re := regexp.MustCompile(key + `="([^"]+)"`)
	matches := re.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// calcDigestResponse 计算Digest认证的response值
func calcDigestResponse(username, realm, password, method, uri, nonce string) string {
	// HA1 = MD5(username:realm:password)
	ha1 := md5Hash(fmt.Sprintf("%s:%s:%s", username, realm, password))
	// HA2 = MD5(method:uri)
	ha2 := md5Hash(fmt.Sprintf("%s:%s", method, uri))
	// response = MD5(HA1:nonce:HA2)
	response := md5Hash(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))
	return response
}

// md5Hash 计算MD5哈希
func md5Hash(data string) string {
	h := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", h)
}
