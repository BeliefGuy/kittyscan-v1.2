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
	// 2026-09-29 多指纹并集去重(用户批准): 改前每指纹独立一轮 executePocs,
	// K 个无映射/0命中指纹 = K 轮完全重复的全量(实测 2 指纹 1539 vs 单轮 771),
	// 再乘 pocBases 基准数。现每基准只打一轮 = 各指纹 POC 集的去重并集:
	//   任一指纹解析为全量 → 并集=全量(全量⊇收敛集, 收敛轮被覆盖, 零漏报);
	//   全部有映射 → 并集=各收敛∪(generic 等重叠 POC 只打一次)。
	// -pocname(:45) 与无指纹兜底(:51)路径不变。
	executePocs(pocinfo, unionFingerprintPocs(info.Infostr))
}

func Execute(PocInfo common.PocInfo) {
	// -pocname(:45 提前 return)与无指纹全量(:51)路径: 纯 filterPoc 收敛,
	// 不并通用白名单、不回退 —— 用户显式点名/全量语义保持历史行为。
	executePocs(PocInfo, filterPoc(PocInfo.PocName))
}

// executePocs 以显式 POC 集执行扫描(请求构造与历史 Execute 完全一致)。
func executePocs(PocInfo common.PocInfo, pocs []*lib.Poc) {
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

// genericPocKeywords 通用 POC 固定白名单(2026-09-29 用户要求)。
// 与目标产品/指纹无关的基础暴露面探测: 指纹收敛时 filterPoc 的白名单筛选会把
// 这些 POC 全部滤掉, 导致"指纹命中的站点反而不测基础漏洞"; 收敛轮必须并入本
// 白名单(见 mergeGenericPocs)。按 Poc.Name 词边界匹配, 与 filterPoc 同口径。
// 新增通用类 POC 在此登记(词边界匹配防子串误拉)。
var genericPocKeywords = []string{
	"sensitive-file-exposure",  // .git/config 等敏感文件暴露
	"common-endpoint-exposure", // actuator 等通用端点暴露
	"backup-file",              // 备份文件探测
	"apache-phpinfo",           // phpinfo 暴露
	"swagger-ui-unauth",        // swagger API 文档未授权
}

// mergeGenericPocs 把通用白名单 POC 并入收敛集(去重)。
// 全量集(AllPocs)本身已含白名单, 对其调用是无副作用的 no-op。
// 只读全局 AllPocs、只改传入的局部切片, 并发安全(WebScanBase 每主机一 goroutine)。
func mergeGenericPocs(pocs []*lib.Poc) []*lib.Poc {
	have := make(map[*lib.Poc]struct{}, len(pocs))
	for _, p := range pocs {
		have[p] = struct{}{}
	}
	for _, p := range AllPocs {
		if _, ok := have[p]; ok {
			continue
		}
		name := strings.ToLower(p.Name)
		for _, kw := range genericPocKeywords {
			if containsToken(name, kw) {
				pocs = append(pocs, p)
				break
			}
		}
	}
	return pocs
}

// resolveFingerprintPocs 指纹 → 本轮 POC 执行集(2026-09-29 用户要求的两条策略):
//  1. 收敛结果合并固定通用白名单(指纹命中的站点不再跳过基础暴露面探测);
//  2. 指纹有映射但收敛 0 命中 → 回退全量(与无映射等价), 不再静默空转
//     (filterPoc 内会打印 [-] No POC matched 警告)。
//
// 别名为空(指纹无映射) → 全量, 与原行为一致。
// 注意: 仅指纹路径经此函数; -pocname 路径仍走 filterPoc 纯收敛(用户显式点名不兜底)。
func resolveFingerprintPocs(alias string) []*lib.Poc {
	if alias == "" {
		return AllPocs
	}
	pocs := filterPoc(alias)
	if len(pocs) == 0 {
		return AllPocs // 策略2: 有映射但 0 命中 → 全量
	}
	return mergeGenericPocs(pocs) // 策略1: 收敛 ∪ 通用白名单
}

// unionFingerprintPocs 多指纹 POC 集的去重并集(2026-09-29 用户批准的全量轮去重)。
// 任一指纹解析为全量(无映射或 0 命中回退)即短路返回全量——全量是所有收敛集的
// 超集, 收敛轮无需再跑; 全部有映射时返回各收敛∪(按 Poc 指针去重)。
// 只读 AllPocs 与局部切片, 并发安全(WebScanBase 每主机一 goroutine, 单线程内调用)。
func unionFingerprintPocs(infostr []string) []*lib.Poc {
	var union []*lib.Poc
	seen := make(map[*lib.Poc]struct{})
	for _, s := range infostr {
		pocs := resolveFingerprintPocs(lib.CheckInfoPoc(s))
		if len(pocs) == len(AllPocs) {
			return AllPocs // 任一全量 → 并集即全量, 短路
		}
		for _, p := range pocs {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			union = append(union, p)
		}
	}
	return union
}

func filterPoc(pocname string) (pocs []*lib.Poc) {
	// -full 强制全量(2026-09-29 用户批准改造): 最强覆盖, 跳过一切收敛——
	// 指纹收敛、-pocname 筛选一律失效, 每个 URL 执行全量 POC;
	// Shiro 全 key 行为不变(check.go:534 消费同一 PocFull)。
	// 需要按名字精准执行单 POC 时不要加 -full。
	if common.PocFull {
		return AllPocs
	}
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
