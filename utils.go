package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

func sumMD5(str string) string {
	hash := md5.New()
	hash.Write([]byte(str))
	return hex.EncodeToString(hash.Sum(nil))
}

func sumRequestMd5(request WebFingerprint) string {
	hash := md5.New()
	requestMust := map[string]interface{}{
		"path":    request.Path,
		"method":  request.RequestMethod,
		"headers": request.RequestHeaders,
		"body":    request.RequestData,
	}
	data, _ := json.Marshal(requestMust)
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

func getFaviconHash(target string) string {
	faviconUrl := target + "/favicon.ico"
	response, err := http.Get(faviconUrl)
	if err != nil {
		return ""
	}
	defer response.Body.Close()

	// 检查响应状态码
	if response.StatusCode != http.StatusOK {
		return ""
	}

	// 读取favicon的文件内容
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return ""
	}

	// 计算favicon的hash值
	hash := md5.Sum(body)
	return hex.EncodeToString(hash[:])
}

func checkPort(host string, port string) bool {
	address := fmt.Sprintf("%s:%s", host, port)
	timeout := 3 * time.Second

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}

	conn.Close()
	return true
}
