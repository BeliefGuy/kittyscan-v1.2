package lib

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

var (
	Client           *http.Client
	ClientNoRedirect *http.Client
	// dialTimout 不再是固定拨号超时, 改为拨号超时的下限兜底:
	// 实际拨号超时 = max(dialTimout, common.WebTimeout 秒), 见 InitHttpClient。
	// 保留该下限是防止 -wt 为 0/负数/极小值时建连立即失败。
	dialTimout = 2 * time.Second
	keepAlive  = 5 * time.Second
)

func Inithttp() {
	//common.Proxy = "http://127.0.0.1:8080"
	if common.PocNum == 0 {
		common.PocNum = 20
	}
	if common.WebTimeout == 0 {
		common.WebTimeout = 5
	}
	err := InitHttpClient(common.PocNum, common.Proxy, time.Duration(common.WebTimeout)*time.Second)
	if err != nil {
		panic(err)
	}
}

func InitHttpClient(ThreadsNum int, DownProxy string, Timeout time.Duration) error {
	type DialContext = func(ctx context.Context, network, addr string) (net.Conn, error)
	// 拨号(建连)超时跟随 -wt(common.WebTimeout), 取代原先硬编码的 5s,
	// 慢目标/高延迟链路在建连阶段不再被 5s 提前掐断(导致漏报)。
	// -wt 默认 5(见 common/flag.go), 默认拨号超时仍是 5s, 默认行为完全不变;
	// dialTimout 作为下限兜底, -wt 0/负数/极小值时不至于建连瞬间失败。
	dialTimeout := time.Duration(common.WebTimeout) * time.Second
	if dialTimeout < dialTimout {
		dialTimeout = dialTimout
	}
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlive,
	}

	// TLS最低版本配置
	tlsMinVersion := tls.VersionTLS10 // 默认TLS 1.0，兼容性最好
	switch common.TLSMinVer {
	case 10:
		tlsMinVersion = tls.VersionTLS10
	case 11:
		tlsMinVersion = tls.VersionTLS11
	case 12:
		tlsMinVersion = tls.VersionTLS12
	case 13:
		tlsMinVersion = tls.VersionTLS13
	}

	// 每主机最大连接数配置
	maxConnsPerHost := 10 // 默认10
	if common.MaxConns > 0 {
		maxConnsPerHost = common.MaxConns
	}

	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     maxConnsPerHost,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: ThreadsNum * 2,
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{MinVersion: uint16(tlsMinVersion), InsecureSkipVerify: true},
		// TLS 握手超时同样跟随 -wt(与拨号共用 dialTimeout, 下限 2s)。
		// 否则 -wt 调大后, HTTPS 目标仍会在握手层被 5s 掐断, 拨号超时的修复等于没做完整。
		TLSHandshakeTimeout: dialTimeout,
		DisableKeepAlives:   false,
	}

	if common.Socks5Proxy != "" {
		dialSocksProxy, err := common.Socks5Dailer(dialer)
		if err != nil {
			return err
		}
		if contextDialer, ok := dialSocksProxy.(proxy.ContextDialer); ok {
			tr.DialContext = contextDialer.DialContext
		} else {
			return errors.New("Failed type assertion to DialContext")
		}
	} else if DownProxy != "" {
		// 快捷方式(1/2)、纯端口/host:port 归一化与协议合法性校验统一在
		// common/Parse.go 的 -proxy 解析段完成(单一事实来源, 见那边注释),
		// 这里只负责把已归一化的 http:// 或 socks5:// 地址装到 Transport.Proxy。
		// 唯一调用链: Plugins/scanner.go Inithttp → InitHttpClient(common.Proxy),
		// common.Proxy 到这里必然是 Parse 处理过的完整 URL。
		u, err := url.Parse(DownProxy)
		if err != nil {
			return err
		}
		tr.Proxy = http.ProxyURL(u)
	}

	Client = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
	}
	ClientNoRedirect = &http.Client{
		Transport:     tr,
		Timeout:       Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	return nil
}

type Poc struct {
	Name   string  `yaml:"name"`
	Set    StrMap  `yaml:"set"`
	Sets   ListMap `yaml:"sets"`
	Rules  []Rules `yaml:"rules"`
	Groups RuleMap `yaml:"groups"`
	Detail Detail  `yaml:"detail"`
}

type MapSlice = yaml.MapSlice

type StrMap []StrItem
type ListMap []ListItem
type RuleMap []RuleItem

type StrItem struct {
	Key, Value string
}

type ListItem struct {
	Key   string
	Value []string
}

type RuleItem struct {
	Key   string
	Value []Rules
}

func (r *StrMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp yaml.MapSlice
	if err := unmarshal(&tmp); err != nil {
		return err
	}
	for _, one := range tmp {
		key, ok := one.Key.(string)
		if !ok {
			key = fmt.Sprintf("%v", one.Key)
		}
		value := fmt.Sprintf("%v", one.Value)
		*r = append(*r, StrItem{key, value})
	}
	return nil
}

//func (r *RuleItem) UnmarshalYAML(unmarshal func(interface{}) error) error {
//	var tmp yaml.MapSlice
//	if err := unmarshal(&tmp); err != nil {
//		return err
//	}
//	//for _,one := range tmp{
//	//	key,value := one.Key.(string),one.Value.(string)
//	//	*r = append(*r,StrItem{key,value})
//	//}
//	return nil
//}

func (r *RuleMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp1 yaml.MapSlice
	if err := unmarshal(&tmp1); err != nil {
		return err
	}
	var tmp = make(map[string][]Rules)
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	for _, one := range tmp1 {
		key, ok := one.Key.(string)
		if !ok {
			key = fmt.Sprintf("%v", one.Key)
		}
		value := tmp[key]
		*r = append(*r, RuleItem{key, value})
	}
	return nil
}

func (r *ListMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp yaml.MapSlice
	if err := unmarshal(&tmp); err != nil {
		return err
	}
	for _, one := range tmp {
		key, ok := one.Key.(string)
		if !ok {
			key = fmt.Sprintf("%v", one.Key)
		}
		var value []string
		if sliceVal, ok := one.Value.([]interface{}); ok {
			for _, val := range sliceVal {
				v := fmt.Sprintf("%v", val)
				value = append(value, v)
			}
		} else {
			// 如果不是切片，将整个值转换为字符串
			value = append(value, fmt.Sprintf("%v", one.Value))
		}
		*r = append(*r, ListItem{key, value})
	}
	return nil
}

type Rules struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	ContentType     string            `yaml:"Content-Type"` // 规则级 Content-Type(如 dahua-yml 把它与 path 平级放在规则上, 不在 headers 里), boundary 头靠它下发
	Body            string            `yaml:"body"`
	Search          string            `yaml:"search"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Expression      string            `yaml:"expression"`
	Continue        bool              `yaml:"continue"`
	// N2: xray output 段 —— 有序键值(StrMap 保留 yaml 顺序): 一项是提取表达式
	// '"regex".bsubmatch(response.body/raw_header)', 其余是 search["group"] 等变量赋值,
	// 求值结果写入 variableMap 供后续规则 {{var}} 替换。此前 yaml.v2 非严格反序列化会把它整段丢掉。
	Output StrMap `yaml:"output"`
	// xray 扩展字段: before_sleep 已实现(请求前先睡 N 秒); stop_if_* 见 WebScan/lib/check.go 的提示
	BeforeSleep    int  `yaml:"before_sleep"`
	StopIfMatch    bool `yaml:"stop_if_match"`
	StopIfMismatch bool `yaml:"stop_if_mismatch"`
}

type Detail struct {
	Author      string   `yaml:"author"`
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
}

func LoadMultiPoc(Pocs embed.FS, pocname string) []*Poc {
	var pocs []*Poc
	for _, f := range SelectPoc(Pocs, pocname) {
		if p, err := LoadPoc(f, Pocs); err == nil {
			pocs = append(pocs, p)
		} else {
			fmt.Println("[-] load poc ", f, " error:", err)
		}
	}
	return pocs
}

func LoadPoc(fileName string, Pocs embed.FS) (*Poc, error) {
	p := &Poc{}
	yamlFile, err := Pocs.ReadFile("pocs/" + fileName)

	if err != nil {
		fmt.Printf("[-] load poc %s error1: %v\n", fileName, err)
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		fmt.Printf("[-] load poc %s error2: %v\n", fileName, err)
		return nil, err
	}
	return p, err
}

func SelectPoc(Pocs embed.FS, pocname string) []string {
	entries, err := Pocs.ReadDir("pocs")
	if err != nil {
		fmt.Println(err)
	}
	var foundFiles []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), pocname) {
			foundFiles = append(foundFiles, entry.Name())
		}
	}
	return foundFiles
}

func LoadPocbyPath(fileName string) (*Poc, error) {
	p := &Poc{}
	data, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Printf("[-] load poc %s error3: %v\n", fileName, err)
		return nil, err
	}
	// L3: -pocpath 的 YAML 原为裸字节直接 yaml.Unmarshal, 带 BOM(UTF-8/UTF-16)
	// 的文件会解析失败; 先经 decodeBOMText 规整为 UTF-8 再解析。
	text, derr := decodeBOMText(data)
	if derr != nil {
		fmt.Printf("[-] load poc %s error4: %v\n", fileName, derr)
		return nil, derr
	}
	err = yaml.Unmarshal([]byte(text), p)
	if err != nil {
		fmt.Printf("[-] load poc %s error4: %v\n", fileName, err)
		return nil, err
	}
	return p, err
}

// decodeBOMText 将文件原始字节规整为 UTF-8 文本: UTF-16 LE(BOM FF FE)/
// UTF-16 BE(BOM FE FF) 整段转码为 UTF-8, UTF-8 BOM(EF BB BF) 剥离,
// 其余按原样当作 UTF-8 文本。与 common 包 decodeTextBytes 同口径——
// 该函数未导出且 common 不在本次授权改动文件内, 无法直接复用,
// 故在本包(lib)按同逻辑实现, 供 -pocpath YAML 读入点使用。
// 无 BOM 的 UTF-16 不做启发式猜测, 与 common 版本一致。
func decodeBOMText(data []byte) (string, error) {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return decodeUTF16Text(data[2:], binary.LittleEndian)
	}
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return decodeUTF16Text(data[2:], binary.BigEndian)
	}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	return string(data), nil
}

// decodeUTF16Text 将 UTF-16 字节流(已去 BOM)按 order 解码为 UTF-8 字符串。
// 奇数字节长、未配对代理项视为转码失败并返回错误(与 common.decodeUTF16 一致)。
func decodeUTF16Text(data []byte, order binary.ByteOrder) (string, error) {
	if len(data)%2 != 0 {
		return "", fmt.Errorf("UTF-16 decode failed: odd length %d byte(s)", len(data))
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = order.Uint16(data[i*2:])
	}
	runes := make([]rune, 0, len(units))
	for i := 0; i < len(units); i++ {
		u := units[i]
		switch {
		case u >= 0xD800 && u <= 0xDBFF:
			if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
				return "", fmt.Errorf("UTF-16 decode failed: unpaired surrogate 0x%04X at unit %d", u, i)
			}
			runes = append(runes, utf16.DecodeRune(rune(u), rune(units[i+1])))
			i++
		case u >= 0xDC00 && u <= 0xDFFF:
			return "", fmt.Errorf("UTF-16 decode failed: isolated low surrogate 0x%04X at unit %d", u, i)
		default:
			runes = append(runes, rune(u))
		}
	}
	return string(runes), nil
}
