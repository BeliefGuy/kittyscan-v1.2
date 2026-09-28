package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/common"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func RabbitmqScan(info *common.HostInfo) (tmperr error) {
	// 未授权检测（默认 guest/guest）
	flag, _ := RabbitmqUnauth(info)
	if flag {
		return
	}
	if common.IsBrute {
		return
	}
	starttime := time.Now().Unix()
	for _, user := range common.Userdict["rabbitmq"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := RabbitmqConn(info, user, pass)
			if flag && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] rabbitmq %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["rabbitmq"])*len(common.Passwords)) * common.BruteTimeout2) {
					return err
				}
			}
		}
	}
	return tmperr
}

func RabbitmqUnauth(info *common.HostInfo) (flag bool, err error) {
	flag = false
	// 尝试默认的 guest/guest 访问
	realhost := fmt.Sprintf("http://%s:%v/api/overview", info.Host, info.Ports)
	client := &http.Client{Timeout: time.Duration(common.BruteTimeout2) * time.Second}
	req, err := http.NewRequest("GET", realhost, nil)
	if err != nil {
		return
	}
	req.SetBasicAuth("guest", "guest")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	// 未授权访问：guest/guest 可以访问管理 API
	if resp.StatusCode == 200 {
		if strings.Contains(bodyStr, "\"rabbitmq_version\"") {
			flag = true
			result := fmt.Sprintf("[vul] RabbitMQ %s:%v unauthorized (guest/guest)", info.Host, info.Ports)
			common.LogSuccess(result)
			return
		}
	}

	// 尝试无认证访问（某些配置可能不需要认证）
	req2, err := http.NewRequest("GET", realhost, nil)
	if err != nil {
		return
	}
	resp2, err := client.Do(req2)
	if err != nil {
		return
	}
	defer resp2.Body.Close()
	body2, _ := ioutil.ReadAll(resp2.Body)
	bodyStr2 := string(body2)

	if resp2.StatusCode == 200 && strings.Contains(bodyStr2, "\"rabbitmq_version\"") {
		flag = true
		result := fmt.Sprintf("[vul] RabbitMQ %s:%v unauthorized (no auth)", info.Host, info.Ports)
		common.LogSuccess(result)
		return
	}

	return
}

func RabbitmqConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	realhost := fmt.Sprintf("http://%s:%v/api/overview", info.Host, info.Ports)
	client := &http.Client{Timeout: time.Duration(common.BruteTimeout2) * time.Second}
	req, err := http.NewRequest("GET", realhost, nil)
	if err != nil {
		return
	}
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	// 认证成功：返回 200 且包含 RabbitMQ 特征字段
	// /api/overview 返回的 JSON 包含 rabbitmq_version, cluster_name, erlang_version 等
	if resp.StatusCode == 200 {
		// 检查是否包含 RabbitMQ 特征字段（排除错误页面）
		if strings.Contains(bodyStr, "\"rabbitmq_version\"") ||
			strings.Contains(bodyStr, "\"cluster_name\"") && strings.Contains(bodyStr, "\"erlang_version\"") {
			flag = true
			result := fmt.Sprintf("[vul] RabbitMQ %v:%v:%v %v", info.Host, info.Ports, user, pass)
			common.LogSuccess(result)
			return
		}
	}

	// 401 表示认证失败，不报告
	// 其他状态码也不报告

	return
}
