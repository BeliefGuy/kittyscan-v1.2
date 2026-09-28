package common

import (
	"flag"
	"fmt"
)

func Banner() {
	banner := "\033[36m" + `      ╱|、
     (˚ˎ 。7
      |、˜〵         K1ttySc4n v 1.2
      じしˍ,)ノ` + "\033[38;5;208m" + `      modified by laxy` + "\033[36m" + `
     ┌─────┐
     │🐾🐾 │
     │🐾🐾 │
     └─────┘
             
` + "\033[0m"
	print(banner)
}

func Flag(Info *HostInfo) {
	Banner()
	flag.StringVar(&Info.Host, "h", "", "扫描目标IP/域名/CIDR，例如: -h 192.168.1.1 或 -h 192.168.1.0/24 或 -h 192.168.1.1,192.168.1.2")
	flag.StringVar(&NoHosts, "hn", "", "排除指定主机不扫描，例如: -hn 192.168.1.1/24")
	flag.StringVar(&Ports, "p", DefaultPorts, "指定扫描端口（默认143个常用端口），例如: -p 22 或 -p 1-65535 或 -p 22,80,3306")
	flag.StringVar(&PortAdd, "pa", "", "追加端口到默认列表，例如: -pa 3389")
	flag.StringVar(&NoPorts, "pn", "", "排除指定端口，例如: -pn 445")
	flag.StringVar(&Scantype, "m", "all", "指定扫描类型，例如: -m ssh 或 -m redis 或 -m all")
	flag.StringVar(&URL, "u", "", "直接指定URL进行Web扫描，例如: -u http://192.168.1.1:8080")
	flag.StringVar(&UrlFile, "uf", "", "URL文件批量扫描，例如: -uf urls.txt")
	flag.StringVar(&HostFile, "hf", "", "IP/域名文件批量扫描，例如: -hf ip.txt")
	flag.StringVar(&Userfile, "userf", "", "用户名字典文件，例如: -userf user.txt")
	flag.StringVar(&Passfile, "pwdf", "", "密码字典文件，例如: -pwdf pass.txt")
	flag.StringVar(&PortFile, "portf", "", "端口字典文件，例如: -portf ports.txt")
	flag.StringVar(&UserAdd, "usera", "", "追加用户名到默认列表，例如: -usera testuser")
	flag.StringVar(&PassAdd, "pwda", "", "追加密码到默认列表，例如: -pwda P@ssw0rt1")
	flag.StringVar(&Username, "user", "", "指定用户名，例如: -user admin")
	flag.StringVar(&Password, "pwd", "", "指定密码，例如: -pwd 123456")
	flag.StringVar(&Command, "c", "", "SSH/WmiExec远程执行命令，例如: -c whoami")
	flag.StringVar(&SshKey, "sshkey", "", "SSH密钥文件，例如: -sshkey id_rsa")
	flag.StringVar(&Domain, "domain", "", "SMB域，例如: -domain WORKGROUP")
	flag.StringVar(&Path, "path", "", "Fcgi/SMB远程文件路径，例如: -path /www/wwwroot/index.php")
	flag.StringVar(&RedisFile, "rf", "", "Redis写入SSH公钥文件，例如: -rf id_rsa.pub")
	flag.StringVar(&RedisShell, "rs", "", "Redis写入计划任务反弹Shell，例如: -rs 192.168.1.1:6666")
	flag.StringVar(&Outputfile, "o", "output.txt", "输出文件名，例如: -o output.txt")
	flag.StringVar(&PocPath, "pocpath", "", "自定义POC目录，例如: -pocpath /path/to/pocs")
	flag.StringVar(&Pocinfo.PocName, "pocname", "", "按名称筛选POC，例如: -pocname weblogic")
	flag.StringVar(&Proxy, "proxy", "", "设置代理：http://仅HTTP(Web/POC)出口，socks5://全局代理(TCP+Web)，例如: -proxy http://127.0.0.1:8080")
	flag.StringVar(&Cookie, "cookie", "", "设置POC请求Cookie，例如: -cookie rememberMe=login")
	flag.StringVar(&SC, "sc", "", "MS17-010执行Shellcode，例如: -sc add")
	flag.StringVar(&Hash, "hash", "", "SMB NTLM Hash，例如: -hash aad3b435b51404eeaad3b435b51404ee")
	flag.BoolVar(&NoPing, "np", false, "跳过存活探测直接扫描端口")
	flag.BoolVar(&Ping, "ping", false, "使用Ping替代ICMP探测存活")
	flag.BoolVar(&NoPoc, "nopoc", false, "跳过Web漏洞扫描（仅做端口和服务检测）")
	flag.BoolVar(&IsBrute, "nobr", false, "跳过密码爆破（漏洞检测照常执行）")
	flag.BoolVar(&IsWmi, "wmi", false, "在135端口发现时额外尝试WMI命令执行")
	flag.BoolVar(&Noredistest, "noredis", false, "跳过Redis未授权写入测试")
	flag.BoolVar(&PocFull, "full", false, "POC全量扫描（如Shiro测试全部Key）")
	flag.BoolVar(&DnsLog, "dns", true, "使用DnsLog进行无回显漏洞检测（默认开启）")
	flag.BoolVar(&NoDnsLog, "nodns", false, "禁用DnsLog反连检测")
	flag.StringVar(&ApiKey, "ceye-key", "", "覆盖ceye反连API Key（留空则使用内置默认值），例如: -ceye-key 0123456789abcdef0123456789abcdef")
	flag.StringVar(&CeyeDomain, "ceye-domain", "", "覆盖ceye二级域名（留空则使用内置默认值），例如: -ceye-domain abc.ceye.io")
	flag.BoolVar(&SynScan, "syn", false, "使用SYN半连接扫描（需管理员/root权限）")
	flag.BoolVar(&Silent, "silent", false, "静默模式（不输出扫描过程）")
	flag.BoolVar(&Nocolor, "nocolor", false, "禁用彩色输出")
	flag.BoolVar(&JsonOutput, "json", false, "JSON格式输出结果")
	flag.BoolVar(&TmpSave, "no", false, "不保存结果到文件")
	flag.Int64Var(&Timeout, "time", 3, "连接超时时间（秒），例如: -time 5")
	flag.Int64Var(&WebTimeout, "wt", 5, "Web请求超时时间（秒），例如: -wt 10")
	flag.IntVar(&Threads, "t", 100, "并发线程数，例如: -t 500")
	flag.IntVar(&BruteThread, "br", 1, "单目标爆破并发数（默认1=串行，全部爆破模块生效），例如: -br 5")
	flag.IntVar(&PocNum, "num", 20, "POC并发数，例如: -num 50")
	flag.IntVar(&LiveTop, "top", 10, "显示存活主机TOP数，例如: -top 20")
	flag.IntVar(&TLSMinVer, "tls", 10, "TLS最低版本(10/11/12/13)，例如: -tls 12")
	flag.IntVar(&MaxConns, "maxconns", 10, "每主机最大连接数，例如: -maxconns 20")
	flag.BoolVar(&NoDelay, "nodelay", false, "禁用随机扫描延迟")
	flag.Int64Var(&WaitTime, "debug", 60, "进度日志输出间隔（秒），例如: -debug 30")
	flag.Parse()

	// 记录用户是否显式指定过 -p（flag.Visit 只遍历实际传入的参数），
	// 供 -m 模式端口收敛与 -h host:port 覆盖判断使用
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "p" {
			UserSetPort = true
		}
	})

	// 处理 -nodns 参数：如果指定了 -nodns，则禁用反连检测
	if NoDnsLog {
		DnsLog = false
	}
}

func FlagEn(Info *HostInfo) {
	Banner()
	flag.StringVar(&Info.Host, "h", "", "IP address of the host, e.g.: -h 192.168.11.11 | -h 192.168.11.0/24 | -h 192.168.11.11,192.168.11.12")
	flag.StringVar(&NoHosts, "hn", "", "the hosts no scan, e.g.: -hn 192.168.1.1/24")
	flag.StringVar(&Ports, "p", DefaultPorts, "Select a port, e.g.: -p 22 | -p 1-65535 | -p 22,80,3306")
	flag.StringVar(&PortAdd, "pa", "", "add port base DefaultPorts, e.g.: -pa 3389")
	flag.StringVar(&NoPorts, "pn", "", "the ports no scan, e.g.: -pn 445")
	flag.StringVar(&Scantype, "m", "all", "Select scan type, e.g.: -m ssh | -m redis | -m all")
	flag.StringVar(&URL, "u", "", "direct URL for web scan, e.g.: -u http://192.168.1.1:8080")
	flag.StringVar(&UrlFile, "uf", "", "URL file for batch scan, e.g.: -uf urls.txt")
	flag.StringVar(&HostFile, "hf", "", "host file, e.g.: -hf ip.txt")
	flag.StringVar(&Userfile, "userf", "", "username file, e.g.: -userf user.txt")
	flag.StringVar(&Passfile, "pwdf", "", "password file, e.g.: -pwdf pass.txt")
	flag.StringVar(&PortFile, "portf", "", "port file, e.g.: -portf ports.txt")
	flag.StringVar(&UserAdd, "usera", "", "add a user base DefaultUsers, e.g.: -usera user")
	flag.StringVar(&PassAdd, "pwda", "", "add a password base DefaultPasses, e.g.: -pwda password")
	flag.StringVar(&Username, "user", "", "username, e.g.: -user admin")
	flag.StringVar(&Password, "pwd", "", "password, e.g.: -pwd 123456")
	flag.StringVar(&Command, "c", "", "exec command (ssh|wmiexec), e.g.: -c whoami")
	flag.StringVar(&SshKey, "sshkey", "", "sshkey file, e.g.: -sshkey id_rsa")
	flag.StringVar(&Domain, "domain", "", "smb domain, e.g.: -domain WORKGROUP")
	flag.StringVar(&Path, "path", "", "fcgi、smb remote file path, e.g.: -path /www/wwwroot/index.php")
	flag.StringVar(&RedisFile, "rf", "", "redis file to write sshkey file, e.g.: -rf id_rsa.pub")
	flag.StringVar(&RedisShell, "rs", "", "redis shell to write cron file, e.g.: -rs 192.168.1.1:6666")
	flag.StringVar(&Outputfile, "o", "output.txt", "Outputfile, e.g.: -o output.txt")
	flag.StringVar(&PocPath, "pocpath", "", "poc file path, e.g.: -pocpath /path/to/pocs")
	flag.StringVar(&Pocinfo.PocName, "pocname", "", "use the pocs these contain pocname, e.g.: -pocname weblogic")
	flag.StringVar(&Proxy, "proxy", "", "set proxy: http:// for web/poc only, socks5:// for global (tcp+web), e.g.: -proxy http://127.0.0.1:8080")
	flag.StringVar(&Cookie, "cookie", "", "set poc cookie, e.g.: -cookie rememberMe=login")
	flag.StringVar(&SC, "sc", "", "ms17 shellcode, e.g.: -sc add")
	flag.StringVar(&Hash, "hash", "", "hash, e.g.: -hash aad3b435b51404eeaad3b435b51404ee")
	flag.BoolVar(&NoPing, "np", false, "not to ping")
	flag.BoolVar(&Ping, "ping", false, "using ping replace icmp")
	flag.BoolVar(&NoPoc, "nopoc", false, "not to scan web vul")
	flag.BoolVar(&IsBrute, "nobr", false, "not to Brute password (vuln detection still runs)")
	flag.BoolVar(&IsWmi, "wmi", false, "start wmi")
	flag.BoolVar(&Noredistest, "noredis", false, "no redis sec test")
	flag.BoolVar(&PocFull, "full", false, "poc full scan, as: shiro 100 key")
	flag.BoolVar(&DnsLog, "dns", true, "using dnslog poc (default: true)")
	flag.BoolVar(&NoDnsLog, "nodns", false, "disable dnslog poc")
	flag.StringVar(&ApiKey, "ceye-key", "", "override ceye API key for reverse connection (empty = built-in default), e.g.: -ceye-key 0123456789abcdef0123456789abcdef")
	flag.StringVar(&CeyeDomain, "ceye-domain", "", "override ceye subdomain for reverse connection (empty = built-in default), e.g.: -ceye-domain abc.ceye.io")
	flag.BoolVar(&SynScan, "syn", false, "SYN scan (requires admin/root)")
	flag.BoolVar(&Silent, "silent", false, "silent scan")
	flag.BoolVar(&Nocolor, "nocolor", false, "no color")
	flag.BoolVar(&JsonOutput, "json", false, "json output")
	flag.BoolVar(&TmpSave, "no", false, "not to save output log")
	flag.Int64Var(&Timeout, "time", 3, "Set timeout, e.g.: -time 5")
	flag.Int64Var(&WebTimeout, "wt", 5, "Set web timeout, e.g.: -wt 10")
	flag.IntVar(&Threads, "t", 100, "Thread nums, e.g.: -t 500")
	flag.IntVar(&BruteThread, "br", 1, "Brute threads (default 1 = serial, effective for all brute modules), e.g.: -br 5")
	flag.IntVar(&PocNum, "num", 20, "poc rate, e.g.: -num 50")
	flag.IntVar(&LiveTop, "top", 10, "show live len top, e.g.: -top 20")
	flag.IntVar(&TLSMinVer, "tls", 10, "TLS min version(10/11/12/13), e.g.: -tls 12")
	flag.IntVar(&MaxConns, "maxconns", 10, "max connections per host, e.g.: -maxconns 20")
	flag.BoolVar(&NoDelay, "nodelay", false, "disable random scan delay")
	flag.Int64Var(&WaitTime, "debug", 60, "every time to LogErr, e.g.: -debug 30")
	flag.Parse()

	// 记录用户是否显式指定过 -p（flag.Visit 只遍历实际传入的参数），
	// 供 -m 模式端口收敛与 -h host:port 覆盖判断使用
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "p" {
			UserSetPort = true
		}
	})

	// 处理 -nodns 参数：如果指定了 -nodns，则禁用反连检测
	if NoDnsLog {
		DnsLog = false
	}
}

func ShowHelp() {
	fmt.Println(`--------------------------------------
用法: kittyscan.exe [选项]
      -help 显示本中文帮助，-hen 显示英文帮助

目标:
  -h  string   扫描目标IP/域名/CIDR
                例: -h 192.168.1.1
                例: -h 192.168.1.0/24
                例: -h 192.168.1.1,192.168.1.2
  -hn string   排除指定主机
                例: -hn 192.168.1.1/24
  -hf string   从文件批量读取目标
                例: -hf ip.txt

存活探测:
  -np          跳过存活探测直接扫描端口
  -ping        使用Ping替代ICMP探测存活

端口:
  -p  string   指定扫描端口（默认143个常用端口）
                例: -p 22
                例: -p 1-65535
                例: -p 22,80,3306
  -pa string   追加端口到默认列表
                例: -pa 3389
  -pn string   排除指定端口
                例: -pn 445
  -portf string  从文件读取端口
                例: -portf ports.txt

扫描类型:
  -m  string   指定扫描类型（默认 all）
                例: -m all        全扫描（端口+服务+Web）
                例: -m ssh        仅SSH爆破
                例: -m redis      仅Redis未授权/爆破
                例: -m mysql      仅MySQL爆破
                例: -m web        仅Web漏洞扫描
                例: -m finger     仅Web指纹识别（自动跳过POC与爆破）
                例: -m fingeronly 仅Web指纹识别且跳过端口扫描（直接按Web端口探测）
                例: -m portscan   仅端口扫描
                例: -m icmp       仅存活探测
                例: -m ms17010    仅MS17-010检测

Web扫描:
  -u  string   直接指定URL进行扫描
                例: -u http://192.168.1.1:8080
  -uf string   URL文件批量扫描
                例: -uf urls.txt
  -pocname string  按名称筛选POC
                例: -pocname weblogic
  -pocpath string  自定义POC目录
                例: -pocpath /path/to/pocs
  -full        POC全量扫描（如Shiro全部Key）
  -dns         使用DnsLog检测无回显漏洞（默认开启）
  -nodns       禁用DnsLog反连检测
  -ceye-key string  覆盖ceye反连API Key（留空则使用内置默认值）
                例: -ceye-key 0123456789abcdef0123456789abcdef
  -ceye-domain string  覆盖ceye二级域名（留空则使用内置默认值）
                例: -ceye-domain abc.ceye.io
  -nopoc       跳过Web漏洞扫描（仅做端口和服务检测）
  -cookie string  设置请求Cookie
                例: -cookie rememberMe=login
  -proxy string   设置代理（按协议区分作用域，原 -socks5 已并入本参数）
                http://   → 仅 HTTP(Web/POC) 出口，端口/爆破等TCP流量直连
                socks5:// → 全局代理，所有TCP拨号(端口/服务/爆破)与Web/POC请求均走代理(自动跳过ICMP探测)
                例: -proxy http://127.0.0.1:8080
                例: -proxy socks5://127.0.0.1:1080
                例: -proxy 127.0.0.1:8080    (默认HTTP)
                例: -proxy 8080              (默认127.0.0.1)
                例: -proxy 1                 (Burp默认，仅HTTP)
                例: -proxy 2                 (SOCKS5默认，全局)
  -num int     POC并发数（默认20）
                例: -num 50

账号爆破:
  -user string   指定用户名
                例: -user admin
  -pwd  string   指定密码
                例: -pwd 123456
  -userf string  从文件读取用户名
                例: -userf user.txt
  -pwdf string   从文件读取密码
                例: -pwdf pass.txt
  -usera string  追加用户名到默认列表
                例: -usera testuser
  -pwda string   追加密码到默认列表
                例: -pwda P@ssw0rt1
  -nobr        跳过密码爆破（漏洞检测照常执行）

特殊功能:
  -c  string   SSH/WmiExec远程执行命令
                例: -c whoami
  -sshkey string  SSH密钥文件
                例: -sshkey id_rsa
  -domain string  SMB域
                例: -domain WORKGROUP
  -sc  string   MS17-010 Shellcode
                例: -sc add
  -hash string   SMB NTLM Hash
                例: -hash aad3b435b51404eeaad3b435b51404ee
  -rf  string   Redis写入SSH公钥文件
                例: -rf id_rsa.pub
  -rs  string   Redis写入计划任务反弹Shell
                例: -rs 192.168.1.1:6666
  -path string  Fcgi/SMB远程文件路径
                例: -path /www/wwwroot/index.php
  -noredis     跳过Redis未授权写入测试
  -wmi         135端口发现时额外尝试WMI命令执行
  -syn         SYN半连接扫描（需管理员/root权限）

性能调优:
  -t  int       并发线程数（默认100）
                例: -t 500
  -time int     连接超时秒（默认3）
                例: -time 5
  -wt  int      Web请求超时秒（默认5）
                例: -wt 10
  -br  int      单目标爆破并发数（默认1=串行，全部爆破模块生效）
                例: -br 5
  -num int      POC并发数（默认20）
                例: -num 50
  -tls int      TLS最低版本（默认10）
                例: -tls 12   (更安全)
                例: -tls 13   (最新)
  -maxconns int 每主机最大连接数（默认10）
                例: -maxconns 20
  -nodelay     禁用随机扫描延迟（默认开启延迟）
                Web请求延迟100-300ms，爆破延迟50-100ms

输出控制:
  -o  string    输出文件（默认 output.txt）
                例: -o output.txt
  -no           不保存结果到文件
  -json         JSON格式输出
  -silent       静默模式
  -nocolor      禁用彩色输出
  -top int      显示存活主机TOP数（默认10）
                例: -top 20
  -debug int    进度日志间隔秒（默认60）
                例: -debug 30

常用示例:
  kittyscan.exe -h 192.168.1.0/24
  kittyscan.exe -h 192.168.1.1 -m ssh -t 100
  kittyscan.exe -h 192.168.1.1 -p 80,443,8080 -m all
  kittyscan.exe -hf ip.txt -p 22,3306,6379
  kittyscan.exe -u http://192.168.1.1:8080 -pocname struts2
  kittyscan.exe -h 192.168.1.0/24 -m ssh -user admin -pwdf pass.txt
  kittyscan.exe -h 192.168.1.0/24 -nodns          禁用反连检测`)
}

func ShowHelpEn() {
	fmt.Println(`--------------------------------------
Usage: kittyscan.exe [options]
       (-hen shows this English help, -help shows Chinese help)

Target:
  -h  string   Target IP/domain/CIDR
                e.g.: -h 192.168.1.1
                e.g.: -h 192.168.1.0/24
                e.g.: -h 192.168.1.1,192.168.1.2
  -hn string   Exclude hosts from scan
                e.g.: -hn 192.168.1.1/24
  -hf string   Host file for batch scan
                e.g.: -hf ip.txt

Live Check:
  -np          Skip alive detection, scan ports directly
  -ping        Use ping instead of ICMP for alive detection

Ports:
  -p  string   Ports to scan (default: 143 common ports)
                e.g.: -p 22
                e.g.: -p 1-65535
                e.g.: -p 22,80,3306
  -pa string   Add ports to defaults
                e.g.: -pa 3389
  -pn string   Exclude ports
                e.g.: -pn 445
  -portf string  Port file
                e.g.: -portf ports.txt

Scan Type:
  -m  string   Scan type (default: all)
                e.g.: -m all / -m ssh / -m redis / -m web
                e.g.: -m finger (fingerprint only, no poc/brute)
                e.g.: -m fingeronly (same, skip port scan)
                e.g.: -m portscan / -m icmp / -m ms17010

Web Scan:
  -u  string   Direct URL
                e.g.: -u http://192.168.1.1:8080
  -uf string   URL file
                e.g.: -uf urls.txt
  -pocname string  Filter POCs by name
                e.g.: -pocname weblogic
  -pocpath string  Custom POC directory
                e.g.: -pocpath /path/to/pocs
  -full        Full POC scan
  -dns         DnsLog blind detection (default: enabled)
  -nodns       Disable DnsLog detection
  -ceye-key string  Override ceye API key for reverse connection (empty = built-in default)
                e.g.: -ceye-key 0123456789abcdef0123456789abcdef
  -ceye-domain string  Override ceye subdomain for reverse connection (empty = built-in default)
                e.g.: -ceye-domain abc.ceye.io
  -nopoc       Skip web vuln scan (ports/service detection only)
  -cookie string  Set cookie
                e.g.: -cookie rememberMe=login
  -proxy string   Set proxy (scope depends on scheme; former -socks5 merged into this flag)
                http://   -> HTTP(Web/POC) egress only; port scan/brute TCP traffic stays direct
                socks5:// -> global proxy; all TCP dials (ports/services/brute) and web/poc requests go through it (ICMP probe auto-disabled)
                e.g.: -proxy http://127.0.0.1:8080
                e.g.: -proxy socks5://127.0.0.1:1080
                e.g.: -proxy 127.0.0.1:8080    (default HTTP)
                e.g.: -proxy 8080              (default 127.0.0.1)
                e.g.: -proxy 1                 (Burp default, http only)
                e.g.: -proxy 2                 (SOCKS5 default, global)
  -num int     POC concurrency (default: 20)
                e.g.: -num 50

Brute Force:
  -user string   Username
                e.g.: -user admin
  -pwd  string   Password
                e.g.: -pwd 123456
  -userf string  Username file
                e.g.: -userf user.txt
  -pwdf string   Password file
                e.g.: -pwdf pass.txt
  -usera string  Add usernames to defaults
                e.g.: -usera testuser
  -pwda string   Add passwords to defaults
                e.g.: -pwda P@ssw0rt1
  -nobr        Skip brute force (vuln detection still runs)

Special:
  -c  string   SSH/WmiExec command
                e.g.: -c whoami
  -sshkey string  SSH key file
                e.g.: -sshkey id_rsa
  -domain string  SMB domain
                e.g.: -domain WORKGROUP
  -sc  string   MS17-010 shellcode
                e.g.: -sc add
  -hash string   SMB NTLM Hash
                e.g.: -hash aad3b435b51404eeaad3b435b51404ee
  -rf  string   Redis write SSH pubkey
                e.g.: -rf id_rsa.pub
  -rs  string   Redis write crontab reverse shell
                e.g.: -rs 192.168.1.1:6666
  -path string  Fcgi/SMB remote file path
                e.g.: -path /www/wwwroot/index.php
  -noredis     Skip redis unauthorized test
  -wmi         Try WMI exec when port 135 is found
  -syn         SYN scan (requires admin/root)

Performance:
  -t  int       Threads (default: 100)
                e.g.: -t 500
  -time int     Timeout seconds (default: 3)
                e.g.: -time 5
  -wt  int      Web timeout seconds (default: 5)
                e.g.: -wt 10
  -br  int      Per-host brute threads (default: 1 = serial, effective for all brute modules)
                e.g.: -br 5
  -num int      POC concurrency (default: 20)
                e.g.: -num 50
  -tls int      TLS min version (default: 10)
                e.g.: -tls 12   (more secure)
                e.g.: -tls 13   (latest)
  -maxconns int Max connections per host (default: 10)
                e.g.: -maxconns 20
  -nodelay     Disable random scan delay (enabled by default)
                Web delay 100-300ms, Brute delay 50-100ms

Output:
  -o  string    Output file (default: output.txt)
                e.g.: -o output.txt
  -no           Do not save to file
  -json         JSON format output
  -silent       Silent mode
  -nocolor      Disable colored output
  -top int      Show live hosts TOP count (default: 10)
                e.g.: -top 20
  -debug int    Progress log interval (default: 60)
                e.g.: -debug 30

Examples:
  kittyscan.exe -h 192.168.1.0/24
  kittyscan.exe -h 192.168.1.1 -m ssh -t 100
  kittyscan.exe -hf ip.txt -p 22,3306,6379
  kittyscan.exe -u http://192.168.1.1:8080 -pocname struts2
  kittyscan.exe -h 192.168.1.0/24 -m ssh -user admin -pwdf pass.txt
  kittyscan.exe -h 192.168.1.0/24 -nodns         Disable DnsLog`)
}
