package lib

import (
	"crypto/md5"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/shadow1ng/fscan/WebScan/info"
	"github.com/shadow1ng/fscan/common"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ceyeApi    = "0864469ad49e2e7976b55c877b420854"
	ceyeDomain = "ldm1ue.ceye.io"
)

// ceyeOverrideOnce 保证 -ceye-key/-ceye-domain 覆盖只执行一次, 且并发 POC 扫描中
// 对所有 goroutine 可见(sync.Once 的 happens-before 语义)。
var ceyeOverrideOnce sync.Once

// applyCeyeOverride 在首次使用前把 -ceye-key/-ceye-domain 的命令行覆盖值写入包级
// ceyeApi/ceyeDomain: 覆盖值非空才替换, 留空(默认)保持内置凭据不变。
// 必须在 flag.Parse(common.Flag)之后生效, 因此不能放在 init() 里, 只能在
// newReverse/reverseCheck 这两处真正读取凭据的入口按需调用(幂等, 反复调用无副作用)。
func applyCeyeOverride() {
	ceyeOverrideOnce.Do(func() {
		if common.ApiKey != "" {
			ceyeApi = common.ApiKey
		}
		if common.CeyeDomain != "" {
			ceyeDomain = common.CeyeDomain
		}
	})
}

const maxRequestDisplay = 512
const maxResponseDisplay = 300 // 响应内容最大显示长度

type PocContext struct {
	Method       string
	URL          string
	Headers      string
	Body         string
	Matched      string
	ResponseBody string   // 新增：保存响应内容
	Links        []string // 新增：参考链接
}

const pocSep = "\033[31m↓-------------------------------------------------------------------------↓\033[0m"
const pocSepEnd = "\033[31m↑-------------------------------------------------------------------------↑\033[0m"

func (pc *PocContext) String() string {
	var sb strings.Builder
	// 请求行
	path := pc.URL
	if idx := strings.Index(pc.URL, "://"); idx >= 0 {
		path = pc.URL[idx+3:]
		if slashIdx := strings.Index(path, "/"); slashIdx >= 0 {
			path = path[slashIdx:]
		} else {
			path = "/"
		}
	}
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", pc.Method, path))
	// Host
	if idx := strings.Index(pc.URL, "://"); idx >= 0 {
		rest := pc.URL[idx+3:]
		if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
			sb.WriteString(fmt.Sprintf("Host: %s\n", rest[:slashIdx]))
		}
	}
	// Headers
	if pc.Headers != "" {
		sb.WriteString(pc.Headers)
	}
	// Body
	if pc.Body != "" {
		body := pc.Body
		if len(body) > maxRequestDisplay {
			body = body[:maxRequestDisplay] + fmt.Sprintf("... (%d bytes truncated)", len(pc.Body)-maxRequestDisplay)
		}
		sb.WriteString(body)
		if !strings.HasSuffix(body, "\n") {
			sb.WriteString("\n")
		}
	}
	// Match（黄色显示判断规则）
	sb.WriteString(fmt.Sprintf("\n\033[33mMatch: %s\033[0m\n", pc.Matched))
	// Response（青色显示匹配到的响应内容摘要）
	if pc.ResponseBody != "" {
		sb.WriteString(fmt.Sprintf("\n\033[36mResponse:\n%s\033[0m\n", pc.ResponseBody))
	}
	// Links（紫色显示参考链接）
	if len(pc.Links) > 0 {
		sb.WriteString("\n\033[35mReferences:\033[0m\n")
		for _, link := range pc.Links {
			sb.WriteString(fmt.Sprintf("  \033[35m- %s\033[0m\n", link))
		}
	}
	return sb.String()
}

type Task struct {
	Req *http.Request
	Poc *Poc
}

func CheckMultiPoc(req *http.Request, pocs []*Poc, workers int) {
	tasks := make(chan Task)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		go func() {
			for task := range tasks {
				ctx := &PocContext{}
				isVul, _, name := executePoc(task.Req, task.Poc, ctx)
				// 跳过需要反连但已禁用DNS的POC
				if name == "skip_nodns" {
					wg.Done()
					continue
				}
				if isVul {
					result := fmt.Sprintf("[vul] PocScan %s %s\n%s\n", task.Req.URL, task.Poc.Name, pocSep)
					detail := ctx.String()
					if name != "" && name != "skip_nodns" {
						detail += fmt.Sprintf("Name: %s\n", name)
					}
					common.LogSuccess(result + detail + pocSepEnd)
				}
				wg.Done()
			}
		}()
	}
	for _, poc := range pocs {
		task := Task{
			Req: req,
			Poc: poc,
		}
		wg.Add(1)
		tasks <- task
	}
	wg.Wait()
	close(tasks)
}

func executePoc(oReq *http.Request, p *Poc, ctx *PocContext) (bool, error, string) {
	c := NewEnvOption()
	c.UpdateCompileOptions(p.Set)
	if len(p.Sets) > 0 {
		var setMap StrMap
		for _, item := range p.Sets {
			if len(item.Value) > 0 {
				setMap = append(setMap, StrItem{item.Key, item.Value[0]})
			} else {
				setMap = append(setMap, StrItem{item.Key, ""})
			}
		}
		c.UpdateCompileOptions(setMap)
	}
	// N2: output 段里的变量(search/ck/...)也要先声明, 否则 output 表达式编译期就报 undeclared reference
	c.declareOutputVars(p)
	env, err := NewEnv(&c)
	if err != nil {
		fmt.Printf("[-] %s environment creation error: %s\n", p.Name, err)
		return false, err, ""
	}
	req, err := ParseRequest(oReq)
	if err != nil {
		fmt.Printf("[-] %s ParseRequest error: %s\n", p.Name, err)
		return false, err, ""
	}
	variableMap := make(map[string]interface{})
	defer func() { variableMap = nil }()
	variableMap["request"] = req
	for _, item := range p.Set {
		k, expression := item.Key, item.Value
		if expression == "newReverse()" {
			if !common.DnsLog {
				return false, nil, "skip_nodns"
			}
			variableMap[k] = newReverse()
			continue
		}
		err, _ = evalset(env, variableMap, k, expression)
		if err != nil {
			fmt.Printf("[-] %s evalset error: %v\n", p.Name, err)
		}
	}
	success := false
	//爆破模式,比如tomcat弱口令
	if len(p.Sets) > 0 {
		success, err = clusterpoc(oReq, p, variableMap, req, env, ctx)
		return success, nil, ""
	}

	DealWithRule := func(rule Rules) (bool, error) {
		Headers := cloneMap(rule.Headers)
		var (
			flag, ok bool
		)
		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", v1)
			for k2, v2 := range Headers {
				if !strings.Contains(v2, "{{"+k1+"}}") {
					continue
				}
				Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
			rule.Path = strings.ReplaceAll(rule.Path, "{{"+k1+"}}", value)
			rule.Body = strings.ReplaceAll(rule.Body, "{{"+k1+"}}", value)
			// N2: 规则级 Content-Type 里同样可能带 {{var}}(如 dahua 的 boundary)
			rule.ContentType = strings.ReplaceAll(rule.ContentType, "{{"+k1+"}}", value)
		}

		if oReq.URL.Path != "" && oReq.URL.Path != "/" {
			req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
		} else {
			req.Url.Path = rule.Path
		}
		// 某些poc没有区分path和query，需要处理
		req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")
		//req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")

		newRequest, err := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, string([]rune(req.Url.Path))), strings.NewReader(rule.Body))
		if err != nil {
			//fmt.Println("[-] newRequest error: ",err)
			return false, err
		}
		newRequest.Header = oReq.Header.Clone()
		for k, v := range Headers {
			newRequest.Header.Set(k, v)
		}
		// N2: 规则级 Content-Type(dahua-zhyq-video-fileupload.yml 等把 boundary 头与 path 平级放置)
		if rule.ContentType != "" {
			newRequest.Header.Set("Content-Type", rule.ContentType)
		}
		// 填充请求详情到上下文
		if ctx != nil && success == false {
			ctx.Method = rule.Method
			ctx.URL = fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path)
			var headerStr strings.Builder
			for k, v := range newRequest.Header {
				headerStr.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
			}
			ctx.Headers = headerStr.String()
			ctx.Body = rule.Body
		}
		Headers = nil
		// xray before_sleep: 请求前先等待 N 秒(上传后延迟访问等场景)
		if rule.BeforeSleep > 0 {
			time.Sleep(time.Duration(rule.BeforeSleep) * time.Second)
		}
		// N3: 时间盲注规则(response.duration >= X)需要比 -wt 更长的超时, 其余规则传 0 走默认 5s
		resp, err := DoRequestWithTimeout(newRequest, rule.FollowRedirects, RuleTimeout(rule.Expression, variableMap))
		newRequest = nil
		if err != nil {
			return false, err
		}
		variableMap["response"] = resp
		// 先判断响应页面是否匹配search规则
		if rule.Search != "" {
			result := doSearch(rule.Search, GetHeader(resp.Headers)+string(resp.Body))
			if len(result) > 0 { // 正则匹配成功
				for k, v := range result {
					variableMap[k] = v
				}
			} else {
				return false, nil
			}
		}
		out, err := Evaluate(env, rule.Expression, variableMap)
		if err != nil {
			return false, err
		}
		//如果false不继续执行后续rule
		// 如果最后一步执行失败，就算前面成功了最终依旧是失败
		flag, ok = out.Value().(bool)
		if !ok {
			flag = false
		}
		// N2: 规则命中后执行 output 段的变量提取, 写入 variableMap 供后续规则 {{var}} 替换
		if flag && len(rule.Output) > 0 {
			if err := applyOutput(env, variableMap, rule.Output); err != nil {
				return false, err
			}
		}
		// 记录匹配的表达式
		if flag && ctx != nil {
			ctx.Matched = strings.TrimSpace(rule.Expression)
			// 保存响应内容摘要（匹配关键词附近的字符）
			if resp != nil && len(resp.Body) > 0 {
				ctx.ResponseBody = extractResponseBody(string(resp.Body), rule.Expression)
			}
		}
		return flag, nil
	}

	DealWithRules := func(rules []Rules) bool {
		// 组内规则按顺序 AND 执行: 任一条未命中/出错即本组失败。
		// stop_if_mismatch(afrog/xray 语义: 本条未命中就停)与该默认行为一致, 无需额外分支。
		// stop_if_match(本条命中就停)是显式短路: 命中后跳过后续规则, 以当前状态判定本组命中,
		// 对应 afrog "找到就收工" 的 OR 型用法(多路径探测任一命中即确认)。
		successFlag := false
		for _, rule := range rules {
			flag, err := DealWithRule(rule)
			if err != nil {
				// cel 求值/请求错误此前被当作"不匹配"静默吞掉, 这里只在真出错时打日志
				common.LogError(fmt.Sprintf("[-] poc %s rule error: %v", p.Name, err))
			}
			if err != nil || !flag { //如果false不继续执行后续rule
				successFlag = false // 如果其中一步为flag，则直接break
				break
			}
			successFlag = true
			if rule.StopIfMatch {
				break
			}
		}
		return successFlag
	}

	if len(p.Rules) > 0 {
		success = DealWithRules(p.Rules)
	} else {
		for _, item := range p.Groups {
			name, rules := item.Key, item.Value
			success = DealWithRules(rules)
			if success {
				// 设置参考链接
				if ctx != nil && len(p.Detail.Links) > 0 {
					ctx.Links = p.Detail.Links
				}
				return success, nil, name
			}
		}
	}

	// 设置参考链接
	if success && ctx != nil && len(p.Detail.Links) > 0 {
		ctx.Links = p.Detail.Links
	}

	return success, nil, ""
}

// extractResponseBody 从响应体中提取匹配关键词附近的字符
func extractResponseBody(body string, expression string) string {
	if body == "" {
		return ""
	}

	// 从表达式中提取关键词（bcontains(b"xxx") 中的 xxx）
	keywords := extractKeywordsFromExpression(expression)

	// 如果没有找到关键词，返回响应体的前 maxResponseDisplay 字符
	if len(keywords) == 0 {
		if len(body) > maxResponseDisplay {
			return body[:maxResponseDisplay] + "..."
		}
		return body
	}

	// 查找第一个匹配的关键词在响应体中的位置
	for _, keyword := range keywords {
		idx := strings.Index(body, keyword)
		if idx >= 0 {
			// 计算截取范围（关键词前后各 maxResponseDisplay/2 字符）
			halfLen := maxResponseDisplay / 2
			start := idx - halfLen
			if start < 0 {
				start = 0
			}
			end := idx + len(keyword) + halfLen
			if end > len(body) {
				end = len(body)
			}

			// 构建摘要
			var sb strings.Builder
			if start > 0 {
				sb.WriteString("...")
			}
			sb.WriteString(body[start:end])
			if end < len(body) {
				sb.WriteString("...")
			}
			return sb.String()
		}
	}

	// 没有匹配到关键词，返回响应体的前 maxResponseDisplay 字符
	if len(body) > maxResponseDisplay {
		return body[:maxResponseDisplay] + "..."
	}
	return body
}

// extractKeywordsFromExpression 从表达式中提取 bcontains(b"xxx") 中的关键词
func extractKeywordsFromExpression(expression string) []string {
	var keywords []string
	// 匹配 bcontains(b"xxx") 或 bcontains(bytes("xxx"))
	re := regexp.MustCompile(`bcontains\(b"([^"]+)"\)|bcontains\(bytes\("([^"]+)"\)\)`)
	matches := re.FindAllStringSubmatch(expression, -1)
	for _, match := range matches {
		if len(match) > 1 {
			if match[1] != "" {
				keywords = append(keywords, match[1])
			} else if match[2] != "" {
				keywords = append(keywords, match[2])
			}
		}
	}
	return keywords
}

func doSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	if err != nil {
		fmt.Println("[-] regexp.Compile error: ", err)
		return nil
	}
	result := r.FindStringSubmatch(body)
	names := r.SubexpNames()
	if len(result) > 1 && len(names) > 1 {
		paramsMap := make(map[string]string)
		for i, name := range names {
			if i > 0 && i <= len(result) {
				if strings.HasPrefix(re, "Set-Cookie:") && strings.Contains(name, "cookie") {
					paramsMap[name] = optimizeCookies(result[i])
				} else {
					paramsMap[name] = result[i]
				}
			}
		}
		return paramsMap
	}
	return nil
}

func optimizeCookies(rawCookie string) (output string) {
	// Parse the cookies
	parsedCookie := strings.Split(rawCookie, "; ")
	for _, c := range parsedCookie {
		nameVal := strings.Split(c, "=")
		if len(nameVal) >= 2 {
			switch strings.ToLower(nameVal[0]) {
			case "expires", "max-age", "path", "domain", "version", "comment", "secure", "samesite", "httponly":
				continue
			}
			output += fmt.Sprintf("%s=%s; ", nameVal[0], strings.Join(nameVal[1:], "="))
		}
	}

	return
}

// applyOutput 按顺序执行规则 output 段(xray 变量提取), 结果写入 variableMap:
// 值形如 '"regex".bsubmatch(response.body)' 的先求值得到 map(如 search), 其余形如
// search["group"] / replaceAll(...) 的继续求值得到字符串(如 ck/id), 后续规则即可用 {{ck}} 替换。
// 输出顺序由 StrMap 按 yaml 顺序保留 —— 赋值项必须排在它的提取项之后(与 xray 语义一致)。
func applyOutput(env *cel.Env, variableMap map[string]interface{}, output StrMap) error {
	for _, item := range output {
		k, expr := item.Key, item.Value
		if strings.TrimSpace(expr) == "" {
			continue
		}
		out, err := Evaluate(env, expr, variableMap)
		if err != nil {
			return fmt.Errorf("output %q 求值失败: %v", k, err)
		}
		if mv, ok := out.Value().(map[string]string); ok {
			// 提取结果是 map: 该键不能参与 {{var}} 替换(check.go 替换逻辑按 map[string]string 跳过),
			// 只作为 search["group"] 引用的数据源
			variableMap[k] = mv
			continue
		}
		// 字符串结果: 从 raw_header 提取时值可能带行尾 \r(CRLF), 去掉避免拼进 Cookie/URL
		variableMap[k] = strings.TrimRight(fmt.Sprintf("%v", out), "\r")
	}
	return nil
}

func newReverse() *Reverse {
	applyCeyeOverride() // 首次使用前应用 -ceye-key/-ceye-domain 覆盖(留空则保持内置默认)
	if !common.DnsLog {
		return &Reverse{}
	}
	letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	randSource := rand.New(rand.NewSource(time.Now().UnixNano()))
	sub := RandomStr(randSource, letters, 8)
	//if true {
	//	//默认不开启dns解析
	//	return &Reverse{}
	//}
	urlStr := fmt.Sprintf("http://%s.%s", sub, ceyeDomain)
	u, _ := url.Parse(urlStr)
	return &Reverse{
		Url:                urlStr,
		Domain:             u.Hostname(),
		Ip:                 u.Host,
		IsDomainNameServer: false,
	}
}

func clusterpoc(oReq *http.Request, p *Poc, variableMap map[string]interface{}, req *Request, env *cel.Env, ctx *PocContext) (success bool, err error) {
	var strMap StrMap
	var tmpnum int
	for i, rule := range p.Rules {
		if !isFuzz(rule, p.Sets) {
			success, err = clustersend(oReq, variableMap, req, env, rule, ctx)
			if err != nil {
				return false, err
			}
			if success {
				continue
			} else {
				return false, err
			}
		}
		setsMap := Combo(p.Sets)
		ruleHash := make(map[string]struct{})
	look:
		for j, item := range setsMap {
			//shiro默认只跑10key
			if p.Name == "poc-yaml-shiro-key" && !common.PocFull && j >= 10 {
				if item[1] == "cbc" {
					continue
				} else {
					if tmpnum == 0 {
						tmpnum = j
					}
					if j-tmpnum >= 10 {
						break
					}
				}
			}
			rule1 := cloneRules(rule)
			var flag1 bool
			var tmpMap StrMap
			var payloads = make(map[string]interface{})
			var tmpexpression string
			for i, one := range p.Sets {
				key, expression := one.Key, item[i]
				if key == "payload" {
					tmpexpression = expression
				}
				_, output := evalset1(env, variableMap, key, expression)
				payloads[key] = output
			}
			for _, one := range p.Sets {
				flag := false
				key := one.Key
				value := fmt.Sprintf("%v", payloads[key])
				for k2, v2 := range rule1.Headers {
					if strings.Contains(v2, "{{"+key+"}}") {
						rule1.Headers[k2] = strings.ReplaceAll(v2, "{{"+key+"}}", value)
						flag = true
					}
				}
				if strings.Contains(rule1.Path, "{{"+key+"}}") {
					rule1.Path = strings.ReplaceAll(rule1.Path, "{{"+key+"}}", value)
					flag = true
				}
				if strings.Contains(rule1.Body, "{{"+key+"}}") {
					rule1.Body = strings.ReplaceAll(rule1.Body, "{{"+key+"}}", value)
					flag = true
				}
				// N2: 规则级 Content-Type(如 dahua 的 multipart boundary)里的 {{var}} 也要替换,
				// 否则该规则既不算 fuzz 规则, boundary 也不会被替换就直接发出去
				if strings.Contains(rule1.ContentType, "{{"+key+"}}") {
					rule1.ContentType = strings.ReplaceAll(rule1.ContentType, "{{"+key+"}}", value)
					flag = true
				}
				if flag {
					flag1 = true
					if key == "payload" {
						var flag2 bool
						for k, v := range variableMap {
							if strings.Contains(tmpexpression, k) {
								flag2 = true
								tmpMap = append(tmpMap, StrItem{k, fmt.Sprintf("%v", v)})
							}
						}
						if flag2 {
							continue
						}
					}
					tmpMap = append(tmpMap, StrItem{key, value})
				}
			}
			if !flag1 {
				continue
			}
			has := md5.Sum([]byte(fmt.Sprintf("%v", rule1)))
			md5str := fmt.Sprintf("%x", has)
			if _, ok := ruleHash[md5str]; ok {
				continue
			}
			ruleHash[md5str] = struct{}{}
			success, err = clustersend(oReq, variableMap, req, env, rule1, ctx)
			if err != nil {
				return false, err
			}
			if success {
				// 设置参考链接
				if ctx != nil && len(p.Detail.Links) > 0 {
					ctx.Links = p.Detail.Links
				}
				if rule.Continue {
					result := fmt.Sprintf("[vul] PocScan %s://%s%s %s\n%s\n", req.Url.Scheme, req.Url.Host, req.Url.Path, p.Name, pocSep)
					common.LogSuccess(result + ctx.String() + pocSepEnd)
					continue
				}
				strMap = append(strMap, tmpMap...)
				if i == len(p.Rules)-1 {
					result := fmt.Sprintf("[vul] PocScan %s://%s%s %s\n%s\n", req.Url.Scheme, req.Url.Host, req.Url.Path, p.Name, pocSep)
					common.LogSuccess(result + ctx.String() + pocSepEnd)
					//防止后续继续打印poc成功信息
					return false, nil
				}
				break look
			}
		}
		if !success {
			break
		}
		if rule.Continue {
			//防止后续继续打印poc成功信息
			return false, nil
		}
	}
	return success, nil
}

func isFuzz(rule Rules, Sets ListMap) bool {
	for _, one := range Sets {
		key := one.Key
		for _, v := range rule.Headers {
			if strings.Contains(v, "{{"+key+"}}") {
				return true
			}
		}
		if strings.Contains(rule.Path, "{{"+key+"}}") {
			return true
		}
		if strings.Contains(rule.Body, "{{"+key+"}}") {
			return true
		}
		// N2: 规则级 Content-Type 里引用 set 变量的规则同样要按 fuzz 规则逐组合发送
		if strings.Contains(rule.ContentType, "{{"+key+"}}") {
			return true
		}
	}
	return false
}

func Combo(input ListMap) (output [][]string) {
	if len(input) > 1 {
		output = Combo(input[1:])
		output = MakeData(output, input[0].Value)
	} else {
		for _, i := range input[0].Value {
			output = append(output, []string{i})
		}
	}
	return
}

func MakeData(base [][]string, nextData []string) (output [][]string) {
	for i := range base {
		for _, j := range nextData {
			output = append(output, append([]string{j}, base[i]...))
		}
	}
	return
}

func clustersend(oReq *http.Request, variableMap map[string]interface{}, req *Request, env *cel.Env, rule Rules, ctx *PocContext) (bool, error) {
	for k1, v1 := range variableMap {
		_, isMap := v1.(map[string]string)
		if isMap {
			continue
		}
		value := fmt.Sprintf("%v", v1)
		for k2, v2 := range rule.Headers {
			if strings.Contains(v2, "{{"+k1+"}}") {
				rule.Headers[k2] = strings.ReplaceAll(v2, "{{"+k1+"}}", value)
			}
		}
		rule.Path = strings.ReplaceAll(strings.TrimSpace(rule.Path), "{{"+k1+"}}", value)
		rule.Body = strings.ReplaceAll(strings.TrimSpace(rule.Body), "{{"+k1+"}}", value)
		// N2: 规则级 Content-Type 里同样可能带 {{var}}
		rule.ContentType = strings.ReplaceAll(rule.ContentType, "{{"+k1+"}}", value)
	}
	if oReq.URL.Path != "" && oReq.URL.Path != "/" {
		req.Url.Path = fmt.Sprint(oReq.URL.Path, rule.Path)
	} else {
		req.Url.Path = rule.Path
	}
	// 某些poc没有区分path和query，需要处理
	req.Url.Path = strings.ReplaceAll(req.Url.Path, " ", "%20")
	//req.Url.Path = strings.ReplaceAll(req.Url.Path, "+", "%20")
	//
	newRequest, err := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(rule.Body))
	if err != nil {
		//fmt.Println("[-] newRequest error:",err)
		return false, err
	}
	newRequest.Header = oReq.Header.Clone()
	for k, v := range rule.Headers {
		newRequest.Header.Set(k, v)
	}
	// N2: 规则级 Content-Type(dahua-zhyq-video-fileupload.yml 等把 boundary 头与 path 平级放置)
	if rule.ContentType != "" {
		newRequest.Header.Set("Content-Type", rule.ContentType)
	}
	// 填充请求详情到上下文
	if ctx != nil {
		ctx.Method = rule.Method
		ctx.URL = fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path)
		var headerStr strings.Builder
		for k, v := range newRequest.Header {
			headerStr.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
		}
		ctx.Headers = headerStr.String()
		ctx.Body = rule.Body
	}
	// xray before_sleep: 请求前先等待 N 秒
	if rule.BeforeSleep > 0 {
		time.Sleep(time.Duration(rule.BeforeSleep) * time.Second)
	}
	// N3: 时间盲注规则需要比 -wt 更长的超时, 其余规则传 0 走默认 5s
	resp, err := DoRequestWithTimeout(newRequest, rule.FollowRedirects, RuleTimeout(rule.Expression, variableMap))
	newRequest = nil
	if err != nil {
		return false, err
	}
	variableMap["response"] = resp
	// 先判断响应页面是否匹配search规则
	if rule.Search != "" {
		result := doSearch(rule.Search, GetHeader(resp.Headers)+string(resp.Body))
		if result != nil && len(result) > 0 { // 正则匹配成功
			for k, v := range result {
				variableMap[k] = v
			}
			//return false, nil
		} else {
			return false, nil
		}
	}
	out, err := Evaluate(env, rule.Expression, variableMap)
	if err != nil {
		if strings.Contains(err.Error(), "Syntax error") {
			fmt.Println(rule.Expression, err)
		} else {
			// "no such key" 等 cel 求值错误此前只静默返回, 这里打出来便于排查失效 POC
			common.LogError(fmt.Sprintf("[-] poc expression evaluate error: %v, expression: %s", err, strings.TrimSpace(rule.Expression)))
		}
		return false, err
	}
	//fmt.Println(fmt.Sprintf("%v, %s", out, out.Type().TypeName()))
	if fmt.Sprintf("%v", out) == "false" { //如果false不继续执行后续rule
		return false, err // 如果最后一步执行失败，就算前面成功了最终依旧是失败
	}
	// N2: 规则命中后执行 output 段的变量提取, 写入 variableMap 供后续规则 {{var}} 替换
	if len(rule.Output) > 0 {
		if oerr := applyOutput(env, variableMap, rule.Output); oerr != nil {
			common.LogError(fmt.Sprintf("[-] poc output evaluate error: %v", oerr))
			return false, oerr
		}
	}
	// 记录匹配的表达式
	if ctx != nil {
		ctx.Matched = strings.TrimSpace(rule.Expression)
		// 保存响应内容摘要（匹配关键词附近的字符）
		if resp != nil && len(resp.Body) > 0 {
			ctx.ResponseBody = extractResponseBody(string(resp.Body), rule.Expression)
		}
	}
	return true, err
}

func cloneRules(tags Rules) Rules {
	cloneTags := Rules{}
	cloneTags.Method = tags.Method
	cloneTags.Path = tags.Path
	cloneTags.Body = tags.Body
	cloneTags.Search = tags.Search
	cloneTags.FollowRedirects = tags.FollowRedirects
	cloneTags.Expression = tags.Expression
	cloneTags.Headers = cloneMap(tags.Headers)
	// N2: 新增字段必须一并克隆, 否则 fuzz 组合规则会丢 output/规则级 Content-Type 等
	cloneTags.ContentType = tags.ContentType
	cloneTags.Output = tags.Output
	cloneTags.BeforeSleep = tags.BeforeSleep
	cloneTags.StopIfMatch = tags.StopIfMatch
	cloneTags.StopIfMismatch = tags.StopIfMismatch
	return cloneTags
}

func cloneMap(tags map[string]string) map[string]string {
	cloneTags := make(map[string]string)
	for k, v := range tags {
		cloneTags[k] = v
	}
	return cloneTags
}

func evalset(env *cel.Env, variableMap map[string]interface{}, k string, expression string) (err error, output string) {
	out, err := Evaluate(env, expression, variableMap)
	if err != nil {
		variableMap[k] = expression
	} else {
		switch value := out.Value().(type) {
		case *UrlType:
			variableMap[k] = UrlTypeToString(value)
		case int64:
			variableMap[k] = int(value)
		default:
			variableMap[k] = fmt.Sprintf("%v", out)
		}
	}
	return err, fmt.Sprintf("%v", variableMap[k])
}

func evalset1(env *cel.Env, variableMap map[string]interface{}, k string, expression string) (err error, output string) {
	out, err := Evaluate(env, expression, variableMap)
	if err != nil {
		variableMap[k] = expression
	} else {
		variableMap[k] = fmt.Sprintf("%v", out)
	}
	return err, fmt.Sprintf("%v", variableMap[k])
}

func CheckInfoPoc(infostr string) string {
	// N4: 双侧 ToLower —— 指纹规则产出的 "JBoss"/"Nexus" 等与 PocData.Name("Jboss"/"Nexus")
	// 此前因大小写敏感的 Contains 匹配不上, 导致该指纹映射不到别名。
	infoLower := strings.ToLower(infostr)
	for _, poc := range info.PocDatas {
		if strings.Contains(infoLower, strings.ToLower(poc.Name)) {
			return poc.Alias
		}
	}
	return ""
}

func GetHeader(header map[string]string) (output string) {
	for name, values := range header {
		line := fmt.Sprintf("%s: %s\n", name, values)
		output = output + line
	}
	output = output + "\r\n"
	return
}
