package common

import (
	"errors"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"strings"
	"time"
)

func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return WrapperTCP(network, address, d)
}

func WrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
	//get conn
	var conn net.Conn
	if Socks5Proxy == "" {
		var err error
		conn, err = forward.Dial(network, address)
		if err != nil {
			return nil, err
		}
	} else {
		dailer, err := Socks5Dailer(forward)
		if err != nil {
			return nil, err
		}
		conn, err = dailer.Dial(network, address)
		if err != nil {
			return nil, err
		}
	}
	return conn, nil

}

func Socks5Dailer(forward *net.Dialer) (proxy.Dialer, error) {
	proxyAddr := Socks5Proxy
	var auth *proxy.Auth

	// 处理不同格式的代理地址
	if strings.Contains(proxyAddr, "://") {
		// 完整URL格式: socks5://user:pass@host:port 或 socks5://host:port
		u, err := url.Parse(proxyAddr)
		if err != nil {
			return nil, err
		}
		if strings.ToLower(u.Scheme) != "socks5" {
			return nil, errors.New("Only support socks5")
		}
		proxyAddr = u.Host
		if u.User.String() != "" {
			auth = &proxy.Auth{
				User:     u.User.Username(),
				Password: "",
			}
			if password, ok := u.User.Password(); ok {
				auth.Password = password
			}
		}
	} else if !strings.Contains(proxyAddr, ":") {
		// 纯端口号格式: 1080
		proxyAddr = "127.0.0.1:" + proxyAddr
	}
	// host:port 格式直接使用

	var dailer proxy.Dialer
	var err error
	if auth != nil {
		dailer, err = proxy.SOCKS5("tcp", proxyAddr, auth, forward)
	} else {
		dailer, err = proxy.SOCKS5("tcp", proxyAddr, nil, forward)
	}

	if err != nil {
		return nil, err
	}
	return dailer, nil
}
