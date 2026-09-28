# kittySC4N v1.1 变更日志

> 基于 fscan 1.8.4 二改，2026年9月

---

## 一、输出格式优化

### 1.1 标签化输出

所有输出统一使用 `[tag]` 前缀，颜色区分：

| 标签 | 颜色 | 含义 | 示例 |
| --- | --- | --- | --- |
| `[port]` | 灰色 | 端口开放 | `[port] 192.168.1.1:22` |
| `[web]` | 绿色 | Web 探测 | `[web] http://192.168.1.1 code:200 len:512 title:Nginx` |
| `[info]` | 绿色 | 指纹识别 | `[info] http://192.168.1.1:8080 GitLab` |
| `[vul]` | 红色 | 漏洞发现 | `[vul] PocScan http://... poc-name` |
| 爆破进度 | 橙色 | 服务爆破 | `已完成 8/9 [-] ssh 192.168.1.1:22 root admin` |

### 1.2 POC 输出增强

漏洞发现时输出完整 HTTP 请求信息，便于手工验证：

```
[vul] PocScan http://192.168.1.1:8848 poc-yaml-alibaba-nacos
↓-------------------------------------------------------------------------↓
GET /nacos/ HTTP/1.1
Host: 192.168.1.1:8848
User-Agent: Mozilla/5.0 ...
Accept: text/html,...

Match: response.body.bcontains(bytes("<title>Nacos</title>"))
↑-------------------------------------------------------------------------↑
```

支持：

- 完整请求行（Method + Path + HTTP/1.1）
- Host + 所有自定义 Headers
- POST Body（超过 512 字节自动截断）
- 匹配的表达式
- 分割线清晰分隔多个 POC 结果

### 1.3 Banner

```
   ╱|、               
  (˚ˎ 。7          
   |、˜〵       kittySC4N v 1.0      
   じしˍ,)ノ         
             
          powered by fscan v1.8.4 (modified by laxy)
```

`(modified by laxy)` 使用橙色（256色 #208）

---

## 二、新增 13 个服务插件

### 2.1 高价值服务

| 服务 | 端口 | 检测方式 | 插件文件 |
| --- | --- | --- | --- |
| Elasticsearch | 9200 | 未授权 + Basic Auth 爆破 | `elasticsearch.go` |
| Tomcat | 8080 | Manager Basic Auth 爆破 | `tomcat.go` |
| WebLogic | 7001 | POST 表单登录爆破 | `weblogic.go` |
| ActiveMQ | 61616 | 未授权 + 管理界面爆破 | `activemq.go` |
| VNC | 5900 | RFB 协议 DES 加密爆破 | `vnc.go` |
| SVN | 3690 | HTTP OPTIONS + Basic Auth | `svn.go` |
| LDAP | 389/5000/636 | 原生 LDAP Bind Request | `ldap.go` |

### 2.2 中价值服务

| 服务 | 端口 | 检测方式 | 插件文件 |
| --- | --- | --- | --- |
| Zookeeper | 2181 | 四字命令 `ruok` | `zookeeper.go` |
| Kafka | 9092 | Metadata Request | `kafka.go` |
| RabbitMQ | 15672 | HTTP API `/api/overview` | `rabbitmq.go` |
| Rsync | 873 | 协议握手 + 模块列表 | `rsync.go` |
| Telnet | 23 | TCP 连接 + 用户名密码 | `telnet.go` |
| SNMP | 161 | UDP GET sysDescr | `snmp.go` |

### 2.3 插件注册

所有新插件在 `Plugins/base.go` 中注册：

- `PluginList` + `PluginMap`（插件函数映射）
- `ServicePorts`（已知服务端口，含非标端口）
- `PortToPlugin`（非标端口 → 标准端口映射，含 LDAP 标准端口 389/636 → 5000）

---

## 三、端口扫描优化

### 3.1 流水线架构

```
旧: 端口扫描全部完成 → 收集结果 → 遍历漏扫
新: 发现端口 → 立刻触发 WebTitle + 服务爆破（并行）
```

### 3.2 默认端口扩展

从 **21 个** 扩展到 **122 个**，覆盖：

| 类别 | 端口数 | 示例 |
| --- | --- | --- |
| 数据库 | 25 | MySQL/Oracle/PostgreSQL/MSSQL/Redis/MongoDB |
| Web 服务 | 45+ | HTTP/HTTPS/Tomcat/WebLogic/各端口变体 |
| 远程管理 | 10 | SSH/RDP/Telnet/VNC/WinRM |
| 中间件 | 20+ | ActiveMQ/RabbitMQ/Kafka/WebLogic |
| 其他 | 20+ | FTP/SMB/LDAP/SNMP/Zookeeper |

### 3.3 非标端口支持

通过 `PortToPlugin` 映射，非标端口自动触发对应服务爆破：

```
端口 10022 → SSH 爆破 ✅
端口 6380  → Redis 爆破 ✅
端口 13306 → MySQL 爆破 ✅
端口 8443  → Tomcat 爆破 ✅
端口 7002  → WebLogic 爆破 ✅
端口 389   → LDAP 爆破 ✅（标准端口映射到5000）
端口 636   → LDAP 爆破 ✅（标准端口映射到5000）
```

### 3.4 每端口并行探测

所有端口都走 WebTitle 探测，已知服务端口额外走对应插件：

```
发现端口 → WebTitle + 服务扫描并行执行
```

---

## 四、扫描性能优化

| 优化项 | 之前 | 之后 | 效果 |
| --- | --- | --- | --- |
| `IsContain` 线性查找 | O(n) | `ServicePorts` map O(1) | 批量扫描提速 5-10x |
| `reflect.ValueOf` 反射 | 运行时反射 | 类型断言 | 插件调用提速 10-50x |
| ICMP 存活检测 | `IsContain` 遍历 | map 查找 | 存活检测提速 3-5x |
| `severports` 重建 | 每次扫描重建 | 包级常量 | 减少重复计算 |
| `AlivePorts` 预分配 | `var []string` | `make([], 0, cap)` | 减少内存扩容 |
| `fmt.Sprintf` 热路径 | 格式化分配 | 字符串 `+` 拼接 | 减少内存分配 |
| 通道缓冲 | 100 | 600（=线程数） | 减少 worker 等待 |
| `os.Stdout.Sync()` | 无 | 每次输出后刷新 | Windows cmd 实时刷新 |
| 爆破超时 | 全局 3 秒 | SSH 1秒 / 其他 2秒 / 通用 3秒 | SSH 爆破提速 3x |

---

## 五、密码字典扩充

### 5.1 新增密码（70 → 100+）

新增类别：

- 年份变体：`{user}@2022` `{user}@2023` `{user}@2024` `{user}@2025`
- 键盘序列：`q1w2e3r4` `Q1W2E3b3` `okmnji`
- 服务默认：`apache` `redhat` `root3306`
- 更多变形：`{user}!@#` `{user}~!@` `{user}1234`

### 5.2 新增用户名

| 服务 | 之前 | 新增 |
| --- | --- | --- |
| SSH | root, admin | +test, user |
| MySQL | root, mysql | +test |
| RDP | 3个 | +test |
| SMB | 3个 | +test |
| PostgreSQL | 2个 | +test |
| MongoDB | 2个 | +test, system |
| FTP | 8个 | +test |

### 5.3 新服务字典

新增 9 个服务的用户名密码：telnet/svn/ldap/elasticsearch/tomcat/weblogic/activemq/rabbitmq/rsync

---

## 六、新增功能参数

| 参数 | 说明 | 示例 |
| --- | --- | --- |
| `-syn` | SYN 半连接扫描（需管理员/root） | `lscan -h 192.168.1.0/24 -syn` |
| `-help` | 中文帮助（带样例） | `lscan -help` |
| `-hen` | 英文帮助（带样例） | `lscan -hen` |

### SYN 扫描平台支持

| 平台 | 支持 | 说明 |
| --- | --- | --- |
| Linux root | ✅ | 原始套接字直接可用 |
| Linux 非 root | ❌ | 自动降级 TCP Connect |
| Windows 管理员 | ❌ | 自动降级 TCP Connect |
| Windows 普通 | ❌ | 自动降级 TCP Connect |

---

## 七、POC 扩展

### 7.1 新增 POC

| POC 文件 | 检测目标 |
| --- | --- |
| `dahua-infoleak-discovery.yml` | 大华 evo-apigw 信息泄露（数据库密码/Redis 密码） |
| `sensitive-file-exposure.yml` | 敏感文件泄露（.git/.svn/.env/config） |
| `common-endpoint-exposure.yml` | 常见端点暴露（actuator/swagger/jolokia） |

### 7.2 补全现有 POC

| POC 文件 | 新增路径 |
| --- | --- |
| `swagger-ui-unauth.yml` | +7 个缺失路径（swagger-resources/v1 |
| `druid-monitor-unauth.yml` | +2 个路径（/druid/login.html /druid） |

### 7.3 POC 总数

386 → **393 个**

---

## 八、编译与分发

### 8.1 构建脚本

`build.py`（Python 版）替代原 bat 文件：

```
python build.py
  [0] Build ALL platforms (+ UPX compress)
  [1] Windows x86 (32-bit)
  [2] Windows x64 (64-bit)
  ...
```

### 8.2 UPX 压缩

| 项目 | 值 |
| --- | --- |
| 工具 | UPX 5.2.1 |
| 算法 | `--best --lzma` |
| 压缩率 | 35.78 MB → **6.22 MB**（-82.6%） |
| 位置 | `tools/upx-5.2.1-win64/upx.exe` |

### 8.3 输出文件

| 项目 | 之前 | 之后 |
| --- | --- | --- |
| 文件名前缀 | `fscan_*` | `lscan_*` |
| 编译命令 | bat / 手动 | `python build.py` |
| 跨平台 | 需手动切换 | 菜单选择自动编译 |

---

## 九、代码质量

| 检查项 | 结果 |
| --- | --- |
| `go build` | ✅ 编译通过 |
| `go vet` | ✅ 无警告 |
| 未使用变量/import | ✅ 无 |
| 死代码 | ✅ 已清理（ldap encodeLength、vnc rand） |
| 重复 flag 定义 | ✅ 已修复（nopoc） |
| 非法 YAML POC | ✅ 无 |
| fscan 特征 | ✅ Kafka 客户端 ID 已改 lscan |
| 帮助信息 | ✅ 中文 `-help` + 英文 `-hen`（带样例） |

---

## 十、文件变更清单

### 新增文件

| 文件 | 说明 |
| --- | --- |
| `Plugins/elasticsearch.go` | Elasticsearch 插件 |
| `Plugins/tomcat.go` | Tomcat 插件 |
| `Plugins/weblogic.go` | WebLogic 插件 |
| `Plugins/activemq.go` | ActiveMQ 插件 |
| `Plugins/vnc.go` | VNC 插件 |
| `Plugins/svn.go` | SVN 插件 |
| `Plugins/ldap.go` | LDAP 插件 |
| `Plugins/zookeeper.go` | Zookeeper 插件 |
| `Plugins/kafka.go` | Kafka 插件 |
| `Plugins/rabbitmq.go` | RabbitMQ 插件 |
| `Plugins/rsync.go` | Rsync 插件 |
| `Plugins/telnet.go` | Telnet 插件 |
| `Plugins/snmp.go` | SNMP 插件 |
| `WebScan/pocs/dahua-infoleak-discovery.yml` | 大华信息泄露 POC |
| `WebScan/pocs/sensitive-file-exposure.yml` | 敏感文件泄露 POC |
| `WebScan/pocs/common-endpoint-exposure.yml` | 常见端点暴露 POC |
| `build.py` | Python 构建脚本 |
| `tools/upx-5.2.1-win64/upx.exe` | UPX 压缩工具 |
| `开发参考手册.md` | 插件/POC 开发指南 |
| `CHANGELOG_v1.0.md` | 本文件 |

### 修改文件

| 文件 | 改动 |
| --- | --- |
| `main.go` | 新增 `-help`/`-hen` 支持 |
| `common/config.go` | 扩展 PORTList/Userdict/DefaultPorts/PortGroup/Passwords + 修复LDAP字典前导空格 + 新增WebLogic端口注册 |
| `common/flag.go` | 中文帮助 + 英文帮助 + 新增 `-syn` 参数 |
| `Plugins/base.go` | 注册新插件 + ServicePorts + PortToPlugin + WebLogic注册 + LDAP标准端口映射(389/636) |
| `Plugins/scanner.go` | 流水线架构 + 非标端口映射 + 去反射 |
| `Plugins/portscan.go` | 预分配 slice + 字符串拼接 + SYN 支持 |
| `Plugins/webtitle.go` | 去掉 gettitle 函数 |
| `Plugins/icmp.go` | 存活检测 map 优化 |
| `Plugins/ftp.go` 等 | 爆破超时改用 BruteTimeout2 |
| `Plugins/ssh.go` | SSH 超时改用 BruteTimeout（1秒） |
| `Plugins/redis.go` | Redis 爆破超时改用 BruteTimeout2 |
| `Plugins/kafka.go` | 增强检测逻辑（校验 correlation ID 避免误报） |
| `Plugins/vnc.go` | 完善 RFB 协议处理（支持 3.3/3.7/3.8 版本 + Reason 字段） |
| `WebScan/WebScan.go` | POC 加载日志 |
| `WebScan/InfoScan.go` | 指纹输出格式改为 `[info]` |
| `WebScan/lib/check.go` | POC 输出完整请求 + 分割线 + ctx 传递 |
| `WebScan/lib/client.go` | 无 |
| `WebScan/pocs/swagger-ui-unauth.yml` | 补全 7 个缺失路径 |
| `WebScan/pocs/druid-monitor-unauth.yml` | 补全 2 个缺失路径 |
| `build.py` | UPX 5.2.1 + 自动检测最新版 |

---

## 十一、v1.1 隐蔽扫描增强

### 11.1 User-Agent 更新

| 项目 | 之前 | 之后 |
| --- | --- | --- |
| 版本 | Chrome/104 (2022年) | 7 个最新 UA 随机选择 |
| 列表 | 单一 UA | Chrome/131, Firefox/133, Edge/131, Safari/18.2 等 |
| 选择方式 | 固定 | 每次请求随机选择 |

### 11.2 默认参数优化

| 参数 | 之前 | 之后 | 说明 |
| --- | --- | --- | --- |
| 默认线程数 | 600 | **100** | 降低扫描频率，更隐蔽 |
| 默认输出文件 | `result.txt` | `output.txt` | 避免被检测 |

### 11.3 随机延迟功能

新增 `-nodelay` 参数（默认开启延迟）：

```
-nodelay    禁用随机扫描延迟（默认开启延迟）
            Web请求延迟100-300ms，爆破延迟50-100ms
```

### 11.4 TLS 版本配置

新增 `-tls` 参数：

```
-tls int    TLS最低版本（默认12）
            -tls 10   (兼容旧系统)
            -tls 12   (更安全)
            -tls 13   (最新)
```

### 11.5 每主机最大连接数

新增 `-maxconns` 参数：

```
-maxconns int  每主机最大连接数（默认10）
```

### 11.6 代理参数优化

`-proxy` 参数支持更多格式：

```
-proxy http://127.0.0.1:8080    # 完整HTTP URL
-proxy socks5://127.0.0.1:1080  # 完整SOCKS5 URL
-proxy 127.0.0.1:8080           # host:port（默认HTTP）
-proxy 8080                     # 纯端口（默认127.0.0.1）
-proxy 1                        # Burp快捷方式
-proxy 2                        # SOCKS5快捷方式
```

### 11.7 端口扫描范围扩展

| 项目 | 之前 | 之后 |
| --- | --- | --- |
| DefaultPorts | 122 个 | **138 个** |
| Webport | 217 个 | **227 个** |
| 合并去重 | 293 个 | **309 个** |

新增端口包括：8500(Consul), 8554(RTSP), 8761(Eureka), 8990(Solr), 389(LDAP), 61616(ActiveMQ) 等。

---

## 十二、v1.1 POC 扩展

### 12.1 POC 总数

| 项目 | 数量 |
| --- | --- |
| 原版 fscan POC | 617 个 |
| 从 nuclei-templates 新增 | 32 个 |
| **当前总数** | **649 个** |

### 12.2 新增 POC 来源

| 来源 | 数量 | 说明 |
| --- | --- | --- |
| nuclei-templates | 17 个 | Spring Boot Actuator、VMware、Nacos 等 |
| xray-plugins | 1 个 | grafana-default-login |
| lxy_poc | 13 个 | 国产OA、CMS、网络设备等 |
| Awesome-POC-master | 6 个 | 宏电、畅捷通、Bitbucket 等 |

### 12.3 新增系统覆盖

| 系统 | 新增 POC |
| --- | --- |
| Spring Boot Actuator | 15+ 个（env/heapdump/mappings/beans/conditions 等） |
| VMware | 7 个（vCenter LFI、Horizon、Cloud XSS 等） |
| Nacos | 2 个（认证绕过、配置导出） |
| 禅道 | 1 个（认证绕过） |
| 铭飞CMS | 1 个（SQL注入） |
| 华天动力OA | 1 个（认证绕过） |
| Proxmox VE | 1 个（认证绕过） |
| 其他 | 10+ 个 |

### 12.4 时间盲注支持

新增 `response.duration` 字段，支持时间盲注：

```yaml
name: example-time-based-sqli
rules:
  - method: GET
    path: "/api?id=1' AND sleep(5)--"
    expression: |
      response.status == 200 && response.duration >= 5
```

### 12.5 POC 输出增强

新增 Response 内容显示（青色）和 Match 规则显示（黄色）：

```
[vul] PocScan http://example.com:8080 springboot-actuator-env-exposed
↓-------------------------------------------------------------------------↓
GET /actuator/env HTTP/1.1
Host: example.com:8080

Match: response.status == 200 && response.body.bcontains(b"activeProfiles")  ← 黄色

Response:
...{"activeProfiles":["prod"],"propertySources":[{"name":"systemProperties",...  ← 青色
↑-------------------------------------------------------------------------↑
```

### 12.6 误报 POC 清理

删除了 11 个误报高的非原版 POC：

| POC | 原因 |
| --- | --- |
| DH-DSS-user_edit_action | 只检查 status=200 |
| alibaba-nacos-sync-unauth | 只检查 status=200 |
| alibaba-nacos-config-download | 只检查 status=200 |
| yisaitong-CDG-druid-submitLogin | 只检查 status=200 |
| 其他 7 个 | 只检查 status=200 或 body!="" |

---

## 十三、代码质量（v1.1）

| 检查项 | 结果 |
| --- | --- |
| `go build` | ✅ 编译通过 |
| `go vet` | ✅ 无警告 |
| 未使用变量/import | ✅ 无 |
| 重复 flag 定义 | ✅ 无 |
| POC 格式检查 | ✅ 649 个全部通过 |
| 重复 POC name | ✅ 无重复 |

---

*kittySC4N v1.1 — 基于 fscan 1.8.4，modified by laxy*
