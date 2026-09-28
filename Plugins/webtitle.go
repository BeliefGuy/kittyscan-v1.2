package Plugins

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shadow1ng/fscan/WebScan"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"golang.org/x/text/encoding/simplifiedchinese"
)

func WebTitle(info *common.HostInfo) error {
	if common.Scantype == "webpoc" {
		// webpoc 跳过 title/指纹抓取, 但 WebScan 需要完整 URL 才能定位目标,
		// 这里先补齐 URL(不发起HTTP请求), 否则 info.Url 为空会导致越界崩溃。
		EnsureUrl(info)
		WebScan.WebScan(info)
		return nil
	}
	// 先补齐协议再暂存用户输入的原始目标 URL(GOWebTitle 内部的 EnsureUrl 幂等, 重复调用无副作用)。
	// 后续 302 跨 host 跳转会用跳转结果覆盖 info.Url, POC 扫描必须固定打回这个原始 host。
	EnsureUrl(info)
	origUrl := info.Url
	err, CheckData := GOWebTitle(info)
	// 指纹识别与 [info]/[web] 日志展示仍使用跳转后的 URL, 跳转结果只用于展示。
	info.Infostr = WebScan.InfoCheck(info.Url, &CheckData)

	// 跨 host 跳转: 把 info.Url 还原为原始目标, 保证 POC 扫描打回用户输入的
	// 原始 host, 既不漏验原目标, 也避免向跳转后的外部/非授权域名发 POC 请求。
	// 同 host 跳转(仅 path/协议变化)不还原, 保持正常跟随后的 title 显示行为。
	if !sameHost(origUrl, info.Url) {
		info.Url = origUrl
	}

	if !common.NoPoc && err == nil {
		WebScan.WebScan(info)
	} else {
		errlog := fmt.Sprintf("[-] webtitle %v %v", info.Url, err)
		common.LogError(errlog)
	}
	return err
}

// sameHost 判断两个 URL 是否指向同一个 host(含端口)。
// 任一 URL 解析失败或 host 为空时视为不同 host, 保守地让 POC 打原始目标。
func sameHost(u1, u2 string) bool {
	p1, err1 := url.Parse(u1)
	p2, err2 := url.Parse(u2)
	if err1 != nil || err2 != nil || p1.Host == "" || p2.Host == "" {
		return false
	}
	return strings.EqualFold(p1.Host, p2.Host)
}

// EnsureUrl 补齐 info.Url (协议://host:port), 只做协议判断, 不发起HTTP请求。
func EnsureUrl(info *common.HostInfo) {
	if info.Url == "" {
		switch info.Ports {
		case "80":
			info.Url = fmt.Sprintf("http://%s", info.Host)
		case "443":
			info.Url = fmt.Sprintf("https://%s", info.Host)
		default:
			host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
			protocol := GetProtocol(host, common.Timeout)
			info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Ports)
		}
		return
	}
	if !strings.Contains(info.Url, "://") {
		host := strings.Split(info.Url, "/")[0]
		protocol := GetProtocol(host, common.Timeout)
		info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
	}
}

func GOWebTitle(info *common.HostInfo) (err error, CheckData []WebScan.CheckDatas) {
	EnsureUrl(info)

	err, result, CheckData := geturl(info, 1, CheckData)
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return
	}

	//有跳转
	if strings.Contains(result, "://") {
		info.Url = result
		err, result, CheckData = geturl(info, 3, CheckData)
		if err != nil {
			return
		}
	}

	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		err, result, CheckData = geturl(info, 1, CheckData)
		//有跳转
		if strings.Contains(result, "://") {
			info.Url = result
			err, _, CheckData = geturl(info, 3, CheckData)
			if err != nil {
				return
			}
		}
	}
	//是否访问图标
	//err, _, CheckData = geturl(info, 2, CheckData)
	if err != nil {
		return
	}
	return
}

func geturl(info *common.HostInfo, flag int, CheckData []WebScan.CheckDatas) (error, string, []WebScan.CheckDatas) {
	//flag 1 first try
	//flag 2 /favicon.ico
	//flag 3 302
	//flag 4 400 -> https

	Url := info.Url
	if flag == 2 {
		URL, err := url.Parse(Url)
		if err == nil {
			Url = fmt.Sprintf("%s://%s/favicon.ico", URL.Scheme, URL.Host)
		} else {
			Url += "/favicon.ico"
		}
	}
	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		return err, "", CheckData
	}
	// 随机选择 User-Agent
	req.Header.Set("User-agent", common.GetRandomUserAgent())
	req.Header.Set("Accept", common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if common.Cookie != "" {
		req.Header.Set("Cookie", common.Cookie)
	}
	//if common.Pocinfo.Cookie != "" {
	//	req.Header.Set("Cookie", "rememberMe=1;"+common.Pocinfo.Cookie)
	//} else {
	//	req.Header.Set("Cookie", "rememberMe=1")
	//}
	req.Header.Set("Connection", "close")

	// Web请求随机延迟 (100-300ms)
	common.WebDelay()

	var client *http.Client
	if flag == 1 {
		client = lib.ClientNoRedirect
	} else {
		client = lib.Client
	}

	resp, err := client.Do(req)
	if err != nil {
		return err, "https", CheckData
	}

	defer resp.Body.Close()
	var title string
	body, err := getRespBody(resp)
	if err != nil {
		return err, "https", CheckData
	}
	// GBK 等非 UTF-8 响应必须先解码再进 CheckData：中文指纹正则以 UTF-8 字节序
	// 匹配，直接喂原始 GBK 字节会令全部中文指纹漏报。解码在 append 之前做一次，
	// 下方取 title 复用同一已解码 body，避免重复解码。解码失败或结果仍非合法
	// UTF-8（如实际是 Big5 等其他编码）时保持原始字节，不丢弃响应、不报错。
	if !utf8.Valid(body) {
		if decoded, derr := simplifiedchinese.GBK.NewDecoder().Bytes(body); derr == nil && len(decoded) > 0 && utf8.Valid(decoded) {
			body = decoded
		}
	}
	CheckData = append(CheckData, WebScan.CheckDatas{Body: body, Headers: fmt.Sprintf("%s", resp.Header)})
	var reurl string
	if flag != 2 {
		title = gettitle(body)
		length := resp.Header.Get("Content-Length")
		if length == "" {
			length = fmt.Sprintf("%v", len(body))
		}
		redirURL, err1 := resp.Location()
		if err1 == nil {
			reurl = redirURL.String()
		}
		result := fmt.Sprintf("[web] %-25v code:%-3v len:%-6v title:%v", resp.Request.URL, resp.StatusCode, length, title)
		if reurl != "" {
			result += fmt.Sprintf(" 跳转url: %s", reurl)
		}
		common.LogSuccess(result)
	}
	if reurl != "" {
		return nil, reurl, CheckData
	}
	if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
		return nil, "https", CheckData
	}
	return nil, "", CheckData
}

func getRespBody(oResp *http.Response) ([]byte, error) {
	var reader io.Reader = oResp.Body
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		reader = gr
	}
	return io.ReadAll(reader)
}

func gettitle(body []byte) (title string) {
	re := regexp.MustCompile("(?ims)<title.*?>(.*?)</title>")
	find := re.FindSubmatch(body)
	if len(find) > 1 {
		title = string(find[1])
		title = strings.TrimSpace(title)
		title = strings.Replace(title, "\n", "", -1)
		title = strings.Replace(title, "\r", "", -1)
		title = strings.Replace(title, "&nbsp;", " ", -1)
		if len(title) > 100 {
			title = title[:100]
		}
		if title == "" {
			title = "\"\"" //空格
		}
	} else {
		title = "None" //没有title
	}
	return
}

func GetProtocol(host string, Timeout int64) (protocol string) {
	protocol = "http"
	//如果端口是80或443,跳过Protocol判断
	if strings.HasSuffix(host, ":80") || !strings.Contains(host, ":") {
		return
	} else if strings.HasSuffix(host, ":443") {
		protocol = "https"
		return
	}

	socksconn, err := common.WrapperTcpWithTimeout("tcp", host, time.Duration(Timeout)*time.Second)
	if err != nil {
		return
	}
	conn := tls.Client(socksconn, &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			defer func() {
				if err := recover(); err != nil {
					common.LogError(err)
				}
			}()
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	err = conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}
