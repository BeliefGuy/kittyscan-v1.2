package Plugins

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
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
	// 后续 302 跳转会用跳转结果覆盖 info.Url; 指纹识别与日志展示用跳转后的结果,
	// 而 POC 扫描打哪些基准由下方 pocBases 计算(原始 host 必打 + 同域子目录/跨域根目录追加)。
	EnsureUrl(info)
	origUrl := info.Url
	err, CheckData := GOWebTitle(info)
	// 指纹识别与 [info]/[web] 日志展示仍使用跳转后的 URL, 跳转结果只用于展示。
	info.Infostr = WebScan.InfoCheck(info.Url, &CheckData)

	if !common.NoPoc && err == nil {
		// 302 跳转派生的附加 POC 基准(默认开启, -no302base 关闭), 见 pocBases。
		bases := pocBases(origUrl, info.Url)
		if len(bases) > 1 && !common.Silent {
			fmt.Printf("[+] 追加POC基准: %s\n", strings.Join(bases[1:], ", "))
		}
		for _, base := range bases {
			WebScan.WebScanBase(info, base)
		}
	} else {
		errlog := fmt.Sprintf("[-] webtitle %v %v", info.Url, err)
		common.LogError(errlog)
	}
	info.Url = origUrl // 收尾还原(下游不消费, 保持状态确定)
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

// pocBases 计算一次 302 跳转探测后要执行 POC 扫描的基准 URL 列表。
// 语义(2026-09-28 设定, 第 1/2 条默认且不可关, 第 3/4 条由 -no302base 控制):
//  1. 原始根目录: scheme://host(与历史一致, 根之外的路径不再整体丢弃);
//  2. 原始 URL 自身子目录: path.Dir(原始路径), 非根时追加 —— 如
//     -u http://h/app/dev/api/login.html → http://h 与 http://h/app/dev/api;
//     这条不是 302 派生的, 关闭 -no302base 也保留;
//  3. 同 host 跳子目录 → 追加该目录前缀(如 http://h/dev); 跳到根级文件(/login.html)不追加;
//  4. 跨 host → 追加新 host 的根(忽略其路径深度, 如 http://2.2.2.2);
//  5. 同 host 时协议采用跳转后的可用协议(可能 http→https 升级), 避免降回原协议
//     因 301 不被跟随而漏报;
//  6. -no302base 时只保留第 1、2 条(第 5 条协议修正仍生效)。
//
// 注意第 4 条会向跳转后的外部主机发 POC 请求, 请自行确认其在授权范围内。
func pocBases(origUrl, jumpUrl string) []string {
	uo, err := url.Parse(origUrl)
	if err != nil || uo.Host == "" {
		return []string{origUrl}
	}
	// 同 host 跳转可能升级协议(http→https): 原始基准一并改用可用协议, 避免降回
	// 原协议因 301 不被跟随而漏报; 跨 host 时原始基准保持原协议。
	sch := uo.Scheme
	var uj *url.URL
	if jumpUrl != "" && jumpUrl != origUrl {
		if p, e := url.Parse(jumpUrl); e == nil && p.Host != "" {
			uj = p
			if sameHost(origUrl, jumpUrl) && p.Scheme != uo.Scheme {
				sch = p.Scheme
			}
		}
	}
	root := sch + "://" + uo.Host
	// 1) 原始根(历史行为); 2) 原始 URL 自身子目录 —— 非 302 派生, 永远参与,
	//    -no302base 不影响这条(例: .../app/dev/api/login.html → / 与 /app/dev/api/)
	bases := []string{root}
	if d := path.Dir(uo.Path); d != "" && d != "/" && d != "." {
		bases = append(bases, root+d)
	}
	if uj == nil || common.No302Base {
		return bases
	}
	if !sameHost(origUrl, jumpUrl) {
		// 3) 跨 host: 追加新 host 的根(忽略其路径深度)
		return appendUnique(bases, uj.Scheme+"://"+uj.Host)
	}
	// 4) 同 host 跳子目录: 追加该目录前缀
	if d := path.Dir(uj.Path); d != "" && d != "/" && d != "." {
		return appendUnique(bases, uj.Scheme+"://"+uj.Host+d)
	}
	return bases
}

// appendUnique 去重追加基准(同 host 跳回原目录时避免重复扫描)
func appendUnique(list []string, b string) []string {
	for _, x := range list {
		if x == b {
			return list
		}
	}
	return append(list, b)
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
