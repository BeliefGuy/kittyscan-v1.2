package WebScan

import (
	"embed"
	"fmt"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"github.com/shadow1ng/fscan/common"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed pocs
var Pocs embed.FS
var once sync.Once
var AllPocs []*lib.Poc

// WebScan 以默认基准(scheme://host, 丢弃路径)执行 POC 扫描, 行为与历史一致。
func WebScan(info *common.HostInfo) {
	buf := strings.Split(info.Url, "/")
	// URL 为空或不合法时直接返回, 避免 buf[:3] 越界 panic
	if len(buf) < 3 || !strings.Contains(info.Url, "://") {
		errlog := fmt.Sprintf("[-] webpocinit invalid target url: %q", info.Url)
		common.LogError(errlog)
		return
	}
	WebScanBase(info, strings.Join(buf[:3], "/"))
}

// WebScanBase 以显式基准 URL 执行 POC 扫描。
// base 可含路径前缀(如 http://1.1.1.1/dev), 规则路径会拼接到该前缀之后,
// 供 302 跳转派生的附加基准使用(见 Plugins/webtitle.go 的 pocBases)。
func WebScanBase(info *common.HostInfo, base string) {
	once.Do(initpoc)
	var pocinfo = common.Pocinfo
	if base == "" || !strings.Contains(base, "://") {
		errlog := fmt.Sprintf("[-] webpocinit invalid base url: %q", base)
		common.LogError(errlog)
		return
	}
	pocinfo.Target = base

	if pocinfo.PocName != "" {
		Execute(pocinfo)
		return
	}
	// Infostr 为空说明本次没有指纹信息可用(-m webpoc 会跳过指纹识别直接调到这里)。
	// 此时必须按全量POC执行, 否则下面的循环一次都不会进入, 导致一个POC都不发。
	if len(info.Infostr) == 0 {
		Execute(pocinfo)
		return
	}
	for _, infostr := range info.Infostr {
		pocinfo.PocName = lib.CheckInfoPoc(infostr)
		Execute(pocinfo)
	}
}

func Execute(PocInfo common.PocInfo) {
	req, err := http.NewRequest("GET", PocInfo.Target, nil)
	if err != nil {
		errlog := fmt.Sprintf("[-] webpocinit %v %v", PocInfo.Target, err)
		common.LogError(errlog)
		return
	}
	// 随机选择 User-Agent
	req.Header.Set("User-agent", common.GetRandomUserAgent())
	req.Header.Set("Accept", common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if common.Cookie != "" {
		req.Header.Set("Cookie", common.Cookie)
	}
	pocs := filterPoc(PocInfo.PocName)
	lib.CheckMultiPoc(req, pocs, common.PocNum)
}

func initpoc() {
	var loaded, failed int
	if common.PocPath == "" {
		entries, err := Pocs.ReadDir("pocs")
		if err != nil {
			fmt.Printf("[-] init poc error: %v", err)
			return
		}
		for _, one := range entries {
			path := one.Name()
			if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
				poc, err := lib.LoadPoc(path, Pocs)
				if err == nil && poc != nil {
					AllPocs = append(AllPocs, poc)
					loaded++
				} else {
					failed++ // LoadPoc 内部已打印单条错误, 这里只计数
				}
			}
		}
	} else {
		// L5: 状态类回显包 -silent, 口径与本文件末尾加载汇总(if common.Silent
		// 提前返回)及全项目 if !common.Silent 一致
		if !common.Silent {
			fmt.Println("[+] load poc from " + common.PocPath)
		}
		err := filepath.Walk(common.PocPath,
			func(path string, info os.FileInfo, err error) error {
				if err != nil || info == nil {
					return err
				}
				if !info.IsDir() {
					if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
						poc, perr := lib.LoadPocbyPath(path)
						if perr == nil && poc != nil {
							AllPocs = append(AllPocs, poc)
							loaded++
						} else {
							failed++ // LoadPocbyPath 内部已打印单条错误, 这里只计数
						}
					}
				}
				return nil
			})
		if err != nil {
			fmt.Printf("[-] init poc error: %v", err)
		}
	}
	// T2: 加载汇总。输出通道用 fmt.Printf + !Silent 而非 common.LogError:
	// LogError 带 "已完成 x/y" 前缀, 且受 -debug(WaitTime, 默认 60s) 节流,
	// 扫描进行中调用可能被直接吞掉, 无法保证失败时"必须醒目"。
	// 也不能用 common.LogSuccess: 那会把统计行写进 -o 结果文件。
	// 这里直接判 Silent, -silent 下同样静默。
	if common.Silent {
		return
	}
	if failed > 0 {
		// 失败 >0: 橙色醒目提示(与 common.LogError 同款色), 损坏 POC 不会被扫描
		msg := fmt.Sprintf("[-] POC 加载完成: 成功 %d, 失败 %d（损坏的 POC 将不会被扫描）", loaded, failed)
		if common.Nocolor {
			fmt.Println(msg)
		} else {
			fmt.Printf("\033[38;5;208m%s\033[0m\n", msg)
		}
	} else {
		// 失败 ==0: 只输出一行成功计数, 不啰嗦
		fmt.Printf("[+] 成功加载 %d 个 POC\n", loaded)
	}
}

// aliasVariants 别名→POC 命名关键词变体: 指纹别名与 POC 命名存在拼写差异,
// 如别名 yongyou 对应 18 个以 yonyou 命名的用友 POC(以及 35 个 yongyou 命名的),
// 单一关键词会漏掉一半。别名本身也一并尝试, 已列出的变体按顺序全部参与匹配。
var aliasVariants = map[string][]string{
	"yongyou": {"yongyou", "yonyou"},
}

func filterPoc(pocname string) (pocs []*lib.Poc) {
	if pocname == "" {
		return AllPocs
	}
	// N4: 双侧小写 + 词边界匹配
	keywords := []string{strings.ToLower(pocname)}
	if variants, ok := aliasVariants[keywords[0]]; ok {
		keywords = variants
	}
	for _, poc := range AllPocs {
		name := strings.ToLower(poc.Name)
		for _, kw := range keywords {
			if containsToken(name, kw) {
				pocs = append(pocs, poc)
				break
			}
		}
	}
	if len(pocs) == 0 {
		fmt.Printf("[-] No POC matched for keyword: %s\n", pocname)
	}
	return
}

// containsToken 判断小写关键词 word 是否以"词边界"出现在小写字符串 s 中:
//   - 命中位置之前必须是非字母数字(或已到串首);
//   - 命中位置之后允许: 串尾 / 非字母数字 / 数字(版本号后缀, 如 thinkphp5、thinkphp5023
//     必须继续命中), 但不允许紧跟字母。
//
// 解决两个方向的问题:
//  1. 反向过匹配: 关键词 nexus 若用裸 Contains 会把 poc-yaml-nexusdb-cve-2020-24571
//     一并拉起, 词边界下 "nexus" 后面紧跟字母 d, 不算命中;
//  2. 大小写漏配已由调用侧 ToLower 双侧解决(如别名 jboss 命中 ...-Jboss-serialization-RCE)。
func containsToken(s, word string) bool {
	if word == "" {
		return false
	}
	from := 0
	for {
		i := strings.Index(s[from:], word)
		if i < 0 {
			return false
		}
		i += from
		after := i + len(word)
		beforeOK := i == 0 || !isAlNumByte(s[i-1])
		afterOK := after >= len(s) || !isAlphaByte(s[after]) // 数字视为版本后缀, 字母则视为另一个词
		if beforeOK && afterOK {
			return true
		}
		from = i + 1
	}
}

// isAlNumByte ASCII 字母数字判断(s 已 ToLower, 非 ASCII 字节视为边界)
func isAlNumByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// isAlphaByte ASCII 字母判断
func isAlphaByte(c byte) bool {
	return c >= 'a' && c <= 'z'
}
