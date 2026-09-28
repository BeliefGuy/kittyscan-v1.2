package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
	"github.com/tomatome/grdp/protocol/pdu"
	"github.com/tomatome/grdp/protocol/rfb"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Brutelist struct {
	user string
	pass string
}

func RdpScan(info *common.HostInfo) (tmperr error) {
	if common.IsBrute {
		return
	}

	var wg sync.WaitGroup
	// R3/R4: signal 原为裸 bool —— worker 成功置位(rdp.go 成功分支)、wg.Wait 协程
	// 置位与主协程自旋读三方无任何同步, `-race` 实测构成两对独立 DATA RACE。
	// 改为 atomic.Bool: 写点 Store、自旋读 Load。
	var signal atomic.Bool
	var num = 0
	var all = len(common.Userdict["rdp"]) * len(common.Passwords)
	var mutex sync.Mutex
	// brlist 带缓冲（容量=字典项总数）：任一 worker 成功置 signal 后，主协程仍可投递剩余
	// 凭据而不被阻塞，保证 close(brlist) 与 wg.Wait() 在成功/失败两条路径上都能执行到。
	brlist := make(chan Brutelist, all)
	port, _ := strconv.Atoi(info.Ports)

	for i := 0; i < common.BruteThread; i++ {
		wg.Add(1)
		go worker(info.Host, common.Domain, port, &wg, brlist, &signal, &num, all, &mutex, common.Timeout)
	}

	for _, user := range common.Userdict["rdp"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			brlist <- Brutelist{user, pass}
		}
	}
	close(brlist)
	go func() {
		wg.Wait()
		signal.Store(true) // R4: wg.Wait 后的置位改为原子写
	}()
	// R3: 自旋读用 Load; 每次轮询让步 1ms, 避免原 `for !signal {}` 纯空转
	// 烧满一个 CPU 核。不改变退出条件(成功置位 或 全部 worker 完成), 也不引入
	// 任何超时语义(本循环原本就没有超时)。
	for !signal.Load() {
		time.Sleep(time.Millisecond)
	}

	return tmperr
}

func worker(host, domain string, port int, wg *sync.WaitGroup, brlist chan Brutelist, signal *atomic.Bool, num *int, all int, mutex *sync.Mutex, timeout int64) {
	defer wg.Done()
	for one := range brlist {
		if signal.Load() {
			return
		}
		go incrNum(num, mutex)
		user, pass := one.user, one.pass
		flag, err := RdpConn(host, domain, user, pass, port, timeout)
		if flag == true && err == nil {
			var result string
			if domain != "" {
				result = fmt.Sprintf("[vul] RDP %v:%v:%v\\%v %v", host, port, domain, user, pass)
			} else {
				result = fmt.Sprintf("[vul] RDP %v:%v:%v %v", host, port, user, pass)
			}
			common.LogSuccess(result)
			signal.Store(true) // R3: 成功置位改为原子写
			return
		} else {
			// R5: *num 写侧 incrNum 持 mutex, 读侧这里加同一把锁后再读,
			// 消除"worker 无锁读 vs incrNum 持锁写"的数据竞争。
			mutex.Lock()
			cur := *num
			mutex.Unlock()
			errlog := fmt.Sprintf("[-] (%v/%v) rdp %v:%v %v %v %v", cur, all, host, port, user, pass, err)
			common.LogError(errlog)
		}
	}
}

func incrNum(num *int, mutex *sync.Mutex) {
	mutex.Lock()
	*num = *num + 1
	mutex.Unlock()
}

func RdpConn(ip, domain, user, password string, port int, timeout int64) (bool, error) {
	target := fmt.Sprintf("%s:%d", ip, port)
	g := NewClient(target, glog.NONE)
	err := g.Login(domain, user, password, timeout)

	if err == nil {
		return true, nil
	}

	return false, err
}

type Client struct {
	Host string // ip:port
	tpkt *tpkt.TPKT
	x224 *x224.X224
	mcs  *t125.MCSClient
	sec  *sec.Client
	pdu  *pdu.Client
	vnc  *rfb.RFB
}

// glogInit: R1/R2 —— glog.SetLevel/SetLogger 修改的是 grdp glog 包的**全局**
// 变量(level/logger, 见 glog/log.go:29-36), 是给全局打补丁而非给 client 实例配置。
// 并发 worker 每次 NewClient 都调用会形成写-写竞争(`-race` 实测 727 处 DATA RACE
// 里最频繁的两个触发点)。两个函数对本项目而言进程内只需执行一次:
// RdpConn 是唯一 NewClient 调用点且恒传 glog.NONE, Once 收敛与原语义一致。
// happens-before: 所有 glog.Info/Error 读取(含 grdp 库内与其自启协程)都发生在
// 各自 NewClient 的 once.Do 返回之后, 与首次写入构成同步, 不再有并发读写。
// 只改调用侧, 不改 grdp 库源码(模块缓存只读)。
var glogInit sync.Once

func NewClient(host string, logLevel glog.LEVEL) *Client {
	glogInit.Do(func() {
		glog.SetLevel(logLevel)
		logger := log.New(os.Stdout, "", 0)
		glog.SetLogger(logger)
	})
	return &Client{
		Host: host,
	}
}

func (g *Client) Login(domain, user, pwd string, timeout int64) error {
	conn, err := common.WrapperTcpWithTimeout("tcp", g.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("[dial err] %v", err)
	}
	defer conn.Close()
	// Q1: grdp 全库不调用 SetDeadline，x224/StartNLA 及后续 pdu 读取都是阻塞读，
	// 卡死的目标会让单次尝试无限挂死。连接建立后给底层 conn 设绝对 deadline：
	// grdp 的所有读写（含握手、认证）都会在预算内报错返回。
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	_ = conn.SetDeadline(deadline)
	glog.Info(conn.LocalAddr().String())

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)
	//g.sec.SetClientAutoReconnect()

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)

	//g.x224.SetRequestedProtocol(x224.PROTOCOL_SSL)
	//g.x224.SetRequestedProtocol(x224.PROTOCOL_RDP)

	err = g.x224.Connect()
	if err != nil {
		return fmt.Errorf("[x224 connect err] %v", err)
	}
	glog.Info("wait connect ok")
	// Q1: 原 wg.Wait() 无超时：grdp 部分读错误路径（如 recvExtendedHeader/recvData 读失败）
	// 只静默 return、done 事件可能永远不来，单次尝试会永久挂死。改为带剩余预算的 select：
	// 事件正常到达则按原逻辑返回，超时未到则按超时返回，保证在 timeout 内必返回；
	// 不再用 WaitGroup，也避免了"事件永不触发时等待协程泄漏"。
	done := make(chan struct{})
	var doneOnce sync.Once

	g.pdu.On("error", func(e error) {
		err = e
		glog.Error("error", e)
		g.pdu.Emit("done")
	})
	g.pdu.On("close", func() {
		err = errors.New("close")
		glog.Info("on close")
		g.pdu.Emit("done")
	})
	g.pdu.On("success", func() {
		err = nil
		glog.Info("on success")
		g.pdu.Emit("done")
	})
	g.pdu.On("ready", func() {
		glog.Info("on ready")
		g.pdu.Emit("done")
	})
	g.pdu.On("update", func(rectangles []pdu.BitmapData) {
		glog.Info("on update:", rectangles)
	})
	g.pdu.On("done", func() {
		doneOnce.Do(func() {
			close(done)
		})
	})
	select {
	case <-done:
		return err
	case <-time.After(time.Until(deadline)):
		// 超时分支不读 err，避免与事件回调里的 err 写入产生数据竞争
		return fmt.Errorf("[rdp timeout] exceed %vs", timeout)
	}
}
