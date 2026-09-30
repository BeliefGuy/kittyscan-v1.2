package common

import (
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var Num int64
var End int64
var Results = make(chan *string)
var LogSucTime int64
var LogErrTime int64
var WaitTime int64
var Silent bool
var Nocolor bool
var JsonOutput bool
var LogWG sync.WaitGroup

// logPending 统计"已提交但尚未写完"的日志条数, 供中断(Ctrl+C)收尾有界轮询。
// 与 LogWG 的区别: 中断时在途任务仍可能调用 LogSuccess(LogWG.Add(1)), 而
// WaitGroup 的正向 Add 在计数为 0 时必须先于 Wait 发生——中断路径上并发的
// Add+Wait 属于 WaitGroup 误用(可能触发 "WaitGroup misuse" panic), 且计数恰为
// 0 时 Wait 会立即返回(根本没等)。故另设 atomic 计数, 轮询天然无此问题。
// 生命周期与 Results 一一对应: LogSuccess 发送前 +1, SaveLog 写盘完成后 -1。
var logPending int64

type JsonText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ansiRe 匹配 ANSI CSI 转义序列（含颜色码 \033[31m 及通用 CSI 序列），
// 写文件前用于剥离，保证 -o 输出文件不含 ANSI 污染（M4）。
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// logTypePrefixes 是 -json 输出已知的日志前缀 → 类型名映射（M1）。
// 按前缀逐个 HasPrefix 判断，取出括号内真正的类型名，剩余部分为 text；
// 未知前缀统一走 "msg"。
var logTypePrefixes = []struct {
	prefix string // 原始前缀，如 "[port]"
	name   string // 类型名，如 "port"
}{
	{"[port]", "port"},
	{"[web]", "web"},
	{"[info]", "info"},
	{"[vul]", "vul"},
	{"[-]", "-"},
	{"[*]", "*"},
	{"[error]", "error"},
}

// init 启动日志协程。LogSucTime 的读写点全部在本文件内(LogSuccess 写、
// LogError 读), 统一走 atomic, 消除跨 goroutine data race。
func init() {
	log.SetOutput(io.Discard)
	atomic.StoreInt64(&LogSucTime, time.Now().Unix())
	go SaveLog()
}

func LogSuccess(result string) {
	// pending++ 必须是第一条语句: 保证"提交已开始"永远先于计数可见,
	// 中断收尾轮询不会在提交间隙误判 logPending==0
	atomic.AddInt64(&logPending, 1)
	LogWG.Add(1)
	atomic.StoreInt64(&LogSucTime, time.Now().Unix())
	Results <- &result
}

// DrainLogs 有界等待在途任务与日志落盘: 轮询直到 Num==End(所有已派发任务执行
// 完毕)且 logPending==0(已提交日志全部写出), 或超过 timeout 返回 false。
// 专供 main.go 的中断收尾使用, 必定有界返回——若在途任务存在历史遗留的永久阻塞,
// 超时后由调用方直接退出, 不会引入 Ctrl+C 永久挂起。
// 调用方须先置停止标志(Plugins.RequestStop)再调用, 保证 Num 不再增长。
func DrainLogs(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		// 先读 End 再读 Num: End 单调不减且恒 <= Num, 反序读取可避免
		// "先读 Num 后读 End 期间恰有派发" 造成的假相等。
		end := atomic.LoadInt64(&End)
		num := atomic.LoadInt64(&Num)
		if num == end && atomic.LoadInt64(&logPending) == 0 {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func SaveLog() {
	for result := range Results {
		if !Silent {
			if Nocolor {
				fmt.Println(*result)
			} else {
				switch {
				case strings.HasPrefix(*result, "[port]"):
					fmt.Println(*result) // 端口 → 白色
				case strings.HasPrefix(*result, "[web]"):
					fmt.Printf("\033[38;5;114m%s\033[0m\n", *result) // Web探测 → 护眼绿
				case strings.HasPrefix(*result, "[info]"):
					color.Green(*result) // 指纹识别 → 绿色
				case strings.HasPrefix(*result, "[vul]"):
					color.Red(*result) // 漏洞发现 → 红色
				default:
					fmt.Println(*result) // 其他 → 白色
				}
			}
			os.Stdout.Sync() // 强制刷出控制台缓冲，防止 Windows cmd 卡住
		}
		if IsSave {
			WriteFile(*result, Outputfile)
		}
		// 写盘完成后再-1: 保证 logPending==0 时该条结果确实已落盘
		atomic.AddInt64(&logPending, -1)
		LogWG.Done()
	}
}

func WriteFile(result string, filename string) {
	fl, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		return
	}
	// M4: 落盘前先剥离 ANSI 转义序列（如 POC 分隔线内嵌的 \033[31m），
	// 无论来源如何，写入文件的内容都干净；控制台彩色显示走 Println/color，完全不受影响。
	result = ansiRe.ReplaceAllString(result, "")
	if JsonOutput {
		// M1: 按已知前缀逐个判断，取出括号内真正的类型名，剩余部分为 text；
		// 未知前缀走 msg。不再用 result[4:] 硬编码偏移定位（前缀长度不一导致错位）。
		scantype := "msg"
		text := result
		for _, p := range logTypePrefixes {
			if strings.HasPrefix(result, p.prefix) {
				scantype = p.name
				text = strings.TrimLeft(result[len(p.prefix):], " \t")
				break
			}
		}
		jsonText := JsonText{
			Type: scantype,
			Text: text,
		}
		jsonData, err := json.Marshal(jsonText)
		if err != nil {
			fmt.Println(err)
			jsonText = JsonText{
				Type: "msg",
				Text: result,
			}
			jsonData, err = json.Marshal(jsonText)
			if err != nil {
				fmt.Println(err)
				jsonData = []byte(result)
			}
		}
		// M2: 输出格式为 NDJSON —— 每行一个独立合法的 JSON 对象。
		// 行尾只追加单个 '\n'（不再追加 ",\n"），不写 BOM、不写数组的 '['/']' 包裹，
		// 首次创建的空文件从第一行起就是合法 JSON 行；每行可被 json.loads 单独解析，
		// O_APPEND 重复运行追加安全，进程被 kill/Ctrl+C 也不会留下半截文件。
		jsonData = append(jsonData, '\n')
		_, err = fl.Write(jsonData)
	} else {
		_, err = fl.Write([]byte(result + "\n"))
	}
	fl.Close()
	if err != nil {
		fmt.Printf("Write %s error, %v\n", filename, err)
	}
}

func LogError(errinfo interface{}) {
	if WaitTime == 0 {
		// M3: 打印整体受 -silent 控制；本分支不涉及节流状态变量。
		if !Silent {
			// L8: Num/End 读写两侧现已均走 atomic——写侧 Plugins/scanner.go 已改为
			// atomic.AddInt64, 与本处 atomic.LoadInt64 配对, 消除跨文件数据竞争;
			// 32 位构建下读取也不撕裂。
			msg := fmt.Sprintf("已完成 %v/%v %v", atomic.LoadInt64(&End), atomic.LoadInt64(&Num), errinfo)
			if Nocolor {
				fmt.Println(msg)
			} else {
				fmt.Printf("\033[38;5;208m%s\033[0m\n", msg) // 爆破进度 → 橙色
			}
			os.Stdout.Sync()
		}
	} else if (time.Now().Unix()-atomic.LoadInt64(&LogSucTime)) > WaitTime && (time.Now().Unix()-atomic.LoadInt64(&LogErrTime)) > WaitTime {
		// M3: 打印受 -silent 控制，但节流状态 LogErrTime 的更新保持原位，不破坏节流语义。
		if !Silent {
			msg := fmt.Sprintf("已完成 %v/%v %v", atomic.LoadInt64(&End), atomic.LoadInt64(&Num), errinfo)
			if Nocolor {
				fmt.Println(msg)
			} else {
				fmt.Printf("\033[38;5;208m%s\033[0m\n", msg) // 爆破进度 → 橙色
			}
			os.Stdout.Sync()
		}
		// L8: LogErrTime 写侧同样在本文件内, 走 atomic 与读侧配对
		atomic.StoreInt64(&LogErrTime, time.Now().Unix())
	}
}

func CheckErrs(err error) bool {
	if err == nil {
		return false
	}
	errs := []string{
		"closed by the remote host", "too many connections",
		"i/o timeout", "EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
	}
	for _, key := range errs {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(key)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 爆破错误分级判定(2026-09-29, 用户批准的"连续超时计数方案")
//
// 背景: 原 CheckErrs 把 "i/o timeout" 与致命错误混为一谈 —— 公网慢链路上
// 爆破的第一次握手超时就 signalStop 砍掉整台主机(实测默认字典只试 1~5 次),
// 完整字典永远跑不完。
//
// 新语义(逻辑流程不变, 只改超时的处置):
//   - 致命错误(连接被拒/关闭/协议不符等, 重试无意义) → 与原来一样立即停;
//   - 超时类错误 → 跳过本组合继续下一组合(下一次连接本身就是一次重试),
//     连续达到 TimeoutStopThreshold=3 次超时才判定目标不可达并按原流程停;
//   - 任意非超时结果(认证拒绝/成功/其他错误) → 清零连续超时计数。
//
// ErrJudge 用法: 每个爆破插件在 Scan 函数外层作用域声明一次(所有 worker 共享,
// 绝不能声明在 worker goroutine 内部), 在原 CheckErrs(err) 的调用点替换为
// judge.ShouldStop(err), 停机分支(signalStop/close(stop))保持原样。
// 非并发安全: 必须在调用方已持 mu 的临界区内调用(与原 CheckErrs 调用点一致)。
// ---------------------------------------------------------------------------

// TimeoutStopThreshold 连续超时多少次后判定目标不可达, 终止该目标的爆破。
const TimeoutStopThreshold = 3

// IsTimeoutErr 判定"超时类"错误: 语义是"对端在超时窗口内没响应"。
// 命中即值得重试, 不应立即砍掉整台主机的爆破。
// 关键词顺序无要求; Windows ConnectEx 超时文案 "did not properly respond"
// 与 Go 的 "i/o timeout"/"deadline exceeded" 一并归入本类。
// 注: 必须先于 CheckErrs 判定 —— Windows 的超时文案同时含 "A connection
// attempt failed"(在原致命列表里), 不分流会退化回旧行为。
func IsTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, key := range []string{
		"i/o timeout",
		"timeout",
		"deadline exceeded",
		"did not properly respond",
	} {
		if strings.Contains(s, key) {
			return true
		}
	}
	return false
}

// CheckErrsFatal 非超时且命中原 CheckErrs 致命列表 → 立即停。
// 超时类错误恒返回 false(交给 ErrJudge 计数)。
func CheckErrsFatal(err error) bool {
	if err == nil || IsTimeoutErr(err) {
		return false
	}
	return CheckErrs(err)
}

// ErrJudge 单次爆破调用(一台 host:port)的错误分级判定器。
// 记录连续超时次数, 语义见文件内说明。零值可用。
type ErrJudge struct {
	consecutiveTimeouts int
}

// ShouldStop 该错误是否应终止本次爆破。
//   - err==nil(成功或"认证拒绝但无错误") → 清零计数, false;
//   - 超时类 → 计数+1, 达到 TimeoutStopThreshold 才 true;
//   - 其他错误 → 清零计数, 命中致命列表 true(与原 CheckErrs 语义一致)。
func (j *ErrJudge) ShouldStop(err error) bool {
	if err == nil {
		j.consecutiveTimeouts = 0
		return false
	}
	if IsTimeoutErr(err) {
		j.consecutiveTimeouts++
		return j.consecutiveTimeouts >= TimeoutStopThreshold
	}
	j.consecutiveTimeouts = 0
	return CheckErrs(err)
}
