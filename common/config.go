package common

import "time"

var version = "1.2"
var Userdict = map[string][]string{
	"ftp":           {"ftp", "admin", "www", "web", "root", "db", "wwwroot", "data", "test"},
	"mysql":         {"root", "mysql", "test"},
	"mssql":         {"sa", "sql"},
	"smb":           {"administrator", "admin", "guest", "test"},
	"rdp":           {"administrator", "admin", "guest", "test"},
	"postgresql":    {"postgres", "admin", "test"},
	"ssh":           {"root", "admin", "test", "user"},
	"mongodb":       {"root", "admin", "test", "system"},
	"oracle":        {"sys", "system", "admin", "test", "web", "orcl"},
	"telnet":        {"root", "admin", "guest"},
	"svn":           {"admin", "web", "test", "guest", "svn"},
	"ldap":          {"administrator", "admin", "guest", "test"},
	"winrm":         {"administrator", "admin", "guest", "test", "user"},
	"elasticsearch": {"elastic", "admin"},
	"tomcat":        {"admin", "manager", "tomcat", "root", "both", "role", "j2deployer"},
	"weblogic":      {"weblogic", "admin", "guest", "system", "portaladmin"},
	"activemq":      {"admin", "user", "test", "guest", "activemq"},
	"rabbitmq":      {"guest", "admin", "rabbitmq"},
	"rsync":         {"root", "admin", "test"},
	"rtsp":          {"admin", "root", "user", "guest", "test", "operator", "default", "super", "viewer", "anonymous", "hikvision", "dahua"},
	"snmp":          {"public", "private", "admin", "manager", "community", "snmp", "monitor", "secret", "read", "write", "all", "any", "network", "system", "cisco", "switch", "router"},
}

var Passwords = []string{
	// 高频密码
	"123456", "admin", "admin123", "root", "", "password", "123123", "654321",
	"111111", "123", "1", "pass123", "pass@123", "admin@123", "Admin@123",
	"admin123!@#", "P@ssw0rd!", "P@ssw0rd", "Passw0rd", "password123", "11111111", "00000000",
	// 数字序列
	"1234", "12345", "1234567", "12345678", "123456789", "1234567890",
	"123321", "666666", "888888", "8888888", "88888888", "000000", "0000",
	"987654321", "7654321", "147258369",
	// 键盘序列
	"qwe123", "123qwe", "123qwe!@#", "1qaz2wsx", "1qaz@WSX", "!QAZ2wsx",
	"1qaz!QAZ", "2wsx@WSX", "qweasdzxc", "qwer123", "qwerty", "qazwsx",
	"1q2w3e", "1q2w3e4r", "123qaz", "123asd", "123456qwerty",
	"q1w2e3r4", "Q1W2E3b3", "okmnji",
	// 字母数字混合
	"abc123", "abc123456", "a123456", "a12345", "a123456.", "a123123",
	"a11111", "Aa1234", "Aa1234.", "Aa12345", "Aa123456", "Aa123456.",
	"Aa123123", "Aa123456!", "Aa123456789", "A123456s!", "sa123456",
	"Charge123", "123456~a", "123456!a",
	// 服务相关
	"sysadmin", "system", "apache", "ftp", "mysql", "oracle", "postgres",
	"web", "test", "test123", "test12345", "test123456", "user",
	"root3306", "redhat",
	// {user} 变体（密码=用户名的各种变形）
	"{user}", "{user}1", "{user}111", "{user}123", "{user}1234", "{user}12345",
	"{user}123456", "{user}@123", "{user}@12345", "{user}@123456",
	"{user}_123", "{user}_12345", "{user}_123456",
	"{user}#123", "{user}#12345", "{user}#123456",
	"{user}@111", "{user}@2019", "{user}@2022", "{user}@2023",
	"{user}@2024", "{user}@2025", "{user}@123#4",
	"{user}!@#", "{user}!@#$", "{user}!@#123", "{user}~!@",
	"{user}2022", "{user}2023", "{user}2024", "{user}2025",
	"{user}123!@#",
}
var PORTList = map[string]int{
	"ftp":           21,
	"ssh":           22,
	"telnet":        23,
	"findnet":       135,
	"netbios":       139,
	"smb":           445,
	"rsync":         873,
	"snmp":          161,
	"mssql":         1433,
	"oracle":        1521,
	"zookeeper":     2181,
	"mysql":         3306,
	"rdp":           3389,
	"svn":           3690,
	"ldap":          5000,
	"psql":          5432,
	"vnc":           5900,
	"winrm":         5985,
	"activemq":      8161,
	"redis":         6379,
	"tomcat":        8080,
	"weblogic":      7001,
	"fcgi":          9000,
	"kafka":         9092,
	"elasticsearch": 9200,
	"mem":           11211,
	"rabbitmq":      15672,
	"mgo":           27017,
	"rtsp":          554,
	"ms17010":       1000001,
	"cve20200796":   1000002,
	"web":           1000003,
	"webonly":       1000003,
	"webpoc":        1000003,
	"finger":        1000003,
	"fingeronly":    1000003,
	"smb2":          1000004,
	"wmiexec":       1000005,
	// wmiinfo/smbinfo/hostname: 值与 ParseScantype switch 的收敛端口协调
	// (wmiinfo→135, smbinfo→445, hostname→135; switch 里 hostname 扫描 135,137,139,445)
	"wmiinfo":  135,
	"smbinfo":  445,
	"hostname": 135,
	"all":      0,
	"portscan": 0,
	"icmp":     0,
	"main":     0,
}
var PortGroup = map[string]string{
	"ftp":           "21,2121,2122",
	"ssh":           "22,1022,2222,10022,22222",
	"telnet":        "23",
	"findnet":       "135",
	"netbios":       "139",
	"smb":           "445,1445,4445",
	"rsync":         "873",
	"snmp":          "161",
	"mssql":         "1433,1434,2433,14330",
	"oracle":        "1521,1522,1523,1524,1525,1526,2483,2484",
	"zookeeper":     "2181",
	"mysql":         "3306,3307,13306,23306,33060",
	"rdp":           "3389,13389,23389,33389",
	"svn":           "3690",
	"ldap":          "389,5000,636",
	"psql":          "5432,5433,5434,25432",
	"vnc":           "5900",
	"winrm":         "5985",
	"activemq":      "8161",
	"redis":         "6379,6380,16379,26379",
	"tomcat":        "8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8443,9080,9443",
	"weblogic":      "7001,7002,9060,9080",
	"fcgi":          "9000",
	"kafka":         "9092",
	"elasticsearch": "9200,9201,9300",
	"mem":           "11211",
	"rabbitmq":      "15672",
	"mgo":           "27017,27018,27019",
	"ms17010":       "445",
	"cve20200796":   "445",
	"service":       "21,22,23,135,139,445,873,161,1433,1521,2181,3306,3389,3690,5000,5432,5900,5985,61616,6379,7001,7002,8080,9000,9092,9200,11211,15672,27017,1022,2222,10022,6380,16379,26379,33060,13306,23306,1522,1523,2483,2484,5433,25432,14330,2433,1434,27018,27019,4445,2121,13389,23389",
	"db":            "1433,1521,3306,5432,6379,11211,27017,33060,14330,2483,5433,27018",
	"web":           "80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,443,800,801,808,880,888,889,1000,1010,1080,1081,1082,1099,1118,1888,2008,2020,2100,2375,2379,3000,3008,3128,3505,5555,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,10250,12018,12443,14000,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,21000,21501,21502,28018,20880",
	"all":           "1-65535",
	"main":          "21,22,23,80,81,135,139,443,445,873,161,1433,1521,2181,3306,3389,3690,5000,5432,5900,5985,61616,6379,7001,8000,8080,8089,9000,9092,9200,11211,15672,27017,1022,2222,10022,6380,16379,33060,13306,1522,2483,5433,25432,14330,2433,1434,27018,27019,4445,2121,13389,23389,8443,9080,9443",
}
var Outputfile = "output.txt"
var IsSave = true
var Webport = "80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,443,800,801,808,880,888,889,1000,1010,1080,1081,1082,1099,1118,1888,2008,2020,2100,2375,2379,3000,3008,3128,3505,5555,6080,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8500,8554,8580,8600,8649,8700,8761,8765,8787,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,8990,8991,8992,8993,8994,8995,9000,9001,9002,9003,9004,9005,9006,9007,9008,9009,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,10250,12018,12443,14000,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,21000,21501,21502,28018,20880"
var DefaultPorts = "21,22,23,80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,110,111,135,139,143,161,389,443,445,465,512,513,514,554,587,636,873,993,995,1022,1080,1099,1433,1434,1445,1521,1522,1523,1524,1525,1526,2049,2121,2122,2181,2222,2433,2483,2484,3306,3307,3389,3690,4433,4445,4848,5000,5432,5433,5434,5555,5900,5901,5902,5985,5986,6379,6380,6443,7001,7002,7003,8000,8001,8008,8009,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8161,8443,8554,8834,8880,8888,8889,8983,9000,9001,9060,9080,9090,9091,9092,9099,9200,9201,9300,9418,9443,9877,9999,10000,10001,10022,10250,11211,12018,12443,13306,13389,14330,15672,16379,22222,23306,23389,25432,26379,27017,27018,27019,27020,33060,33389,61616"

type HostInfo struct {
	Host    string
	Ports   string
	Url     string
	Infostr []string
}

type PocInfo struct {
	Target  string
	PocName string
}

var (
	Ports string
	// UserSetPort 记录用户是否通过 -p 显式指定过端口(在 flag 解析后由 flag.Visit 置位)。
	// 用于模式端口收敛(-m xxx)与 host:port 覆盖判断: 用户显式给了 -p 就以用户端口为准。
	UserSetPort   bool
	Path          string
	Scantype      string
	Command       string
	SshKey        string
	Domain        string
	Username      string
	Password      string
	Proxy         string
	Timeout       int64 = 3
	BruteTimeout  int64 = 2 // SSH 爆破超时
	BruteTimeout2 int64 = 2 // 其他服务爆破超时
	WebTimeout    int64 = 5
	TmpSave       bool
	NoPing        bool
	Ping          bool
	Pocinfo       PocInfo
	NoPoc         bool
	IsBrute       bool
	No302Base     bool
	RedisFile     string
	RedisShell    string
	Userfile      string
	Passfile      string
	HostFile      string
	PortFile      string
	PocPath       string
	Threads       int
	URL           string
	UrlFile       string
	Urls          []string
	NoPorts       string
	NoHosts       string
	SC            string
	PortAdd       string
	UserAdd       string
	PassAdd       string
	BruteThread   int
	LiveTop       int
	Socks5Proxy   string // 全局SOCKS5代理地址, 由 -proxy socks5:// 自动派生(原 -socks5 参数已并入 -proxy); proxy.go/WebScan 拨号层据此走代理
	Hash          string
	HashBytes     []byte
	HostPort      []string
	IsWmi         bool
	Noredistest   bool
	SynScan       bool
	TLSMinVer     int  // TLS最低版本: 0=自动, 10=TLS1.0, 11=TLS1.1, 12=TLS1.2, 13=TLS1.3
	MaxConns      int  // 每主机最大连接数
	ScanDelay     bool // 是否启用扫描延迟（默认开启，用-nodelay禁用）
	NoDelay       bool // 禁用扫描延迟
)

var (
	// 内置多个最新 User-Agent，随机选择
	UserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
	}
	UserAgent = UserAgents[0] // 默认使用第一个
	Accept    = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
	DnsLog    = true // 默认开启反连检测
	NoDnsLog  bool   // 禁用反连检测
	PocNum    int
	PocFull   bool
	// CeyeDomain / ApiKey 是 -ceye-domain / -ceye-key 的覆盖值(flag 默认空=使用
	// WebScan/lib 包内置的 ceye 凭据)。语义: CeyeDomain 即 ceye 二级域名,
	// ApiKey 即 ceye.io 反连记录查询 API token(-ceye-key 的值)。
	// 这两个变量原本就紧挨 DnsLog/NoDnsLog 且全项目无引用(死变量), 现复用为
	// 反连凭据覆盖入口, 不再另增 CeyeKey, 避免出现语义重复的变量。
	CeyeDomain string
	ApiKey     string
	Cookie     string
)

// GetRandomUserAgent 随机返回一个 User-Agent
func GetRandomUserAgent() string {
	return UserAgents[time.Now().UnixNano()%int64(len(UserAgents))]
}

// RandomDelay 随机延迟（用于隐蔽扫描）
// minMs: 最小延迟毫秒数
// maxMs: 最大延迟毫秒数
func RandomDelay(minMs, maxMs int) {
	// 如果禁用了延迟，直接返回
	if NoDelay {
		return
	}
	delay := minMs + int(time.Now().UnixNano()%int64(maxMs-minMs+1))
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

// WebDelay Web请求随机延迟 (100-300ms)
func WebDelay() {
	RandomDelay(100, 300)
}

// BruteDelay 爆破请求随机延迟 (50-100ms)
func BruteDelay() {
	RandomDelay(50, 100)
}
