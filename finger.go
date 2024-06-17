package main

import (
	"gopkg.in/yaml.v3"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Fingerprint struct {
	Path           string            `yaml:"path"`
	RequestMethod  string            `yaml:"request_method"`
	RequestHeaders map[string]string `yaml:"request_headers"`
	RequestData    string            `yaml:"request_data"`
	StatusCode     int               `yaml:"status_code"`
	Headers        map[string]string `yaml:"headers"`
	Keyword        []string          `yaml:"keyword"`
	FaviconHash    []string          `yaml:"favicon_hash"`
}

type WebFingerprintYaml struct {
	Name        string        `yaml:"name"`
	Priority    int           `yaml:"priority"`
	NucleiTags  [][]string    `yaml:"nuclei_tags"`
	Fingerprint []Fingerprint `yaml:"fingerprint"`
}

type WebFingerprint struct {
	Path           string            `yaml:"path"`
	RequestMethod  string            `yaml:"request_method"`
	RequestHeaders map[string]string `yaml:"request_headers"`
	RequestData    string            `yaml:"request_data"`
	ResponseMatch  []Response        `yaml:"response_match"`
}

type Response struct {
	StatusCode   int               `yaml:"status_code"`
	Headers      map[string]string `yaml:"headers"`
	Keyword      []string          `yaml:"keyword"`
	FaviconHash  []string          `yaml:"favicon_hash"`
	WebFingerTag WebFingerTag      `yaml:"web_finger_tag"`
}

type WebFingerTag struct {
	Name       string     `yaml:"name"`
	Priority   int        `yaml:"priority"`
	NucleiTags [][]string `yaml:"nuclei_tags"`
}

type CheckResult struct {
	Target   string         `yaml:"target"`
	Tags     []WebFingerTag `yaml:"tags"`
	IsPassed bool           `yaml:"is_passed"`
}

var webFingerprints = make(map[string]*WebFingerprint)

func readFingerprint(dir string) error {
	//var fingerprints []WebFingerprintYaml

	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".yaml" {
			filePath := filepath.Join(dir, file.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}

			var fp WebFingerprintYaml
			err = yaml.Unmarshal(data, &fp)
			if err != nil {
				return err
			}

			for _, fingerprint := range fp.Fingerprint {

				responseMatch := Response{
					StatusCode:  fingerprint.StatusCode,
					Headers:     fingerprint.Headers,
					Keyword:     fingerprint.Keyword,
					FaviconHash: fingerprint.FaviconHash,
					WebFingerTag: WebFingerTag{
						Name:       fp.Name,
						Priority:   fp.Priority,
						NucleiTags: fp.NucleiTags,
					},
				}
				wfp := WebFingerprint{
					Path:           fingerprint.Path,
					RequestMethod:  fingerprint.RequestMethod,
					RequestHeaders: fingerprint.RequestHeaders,
					RequestData:    fingerprint.RequestData,
					ResponseMatch: []Response{
						responseMatch,
					},
				}
				hash := sumRequestMd5(wfp)

				if _, ok := webFingerprints[hash]; !ok {

					webFingerprints[hash] = &wfp
					continue
				} else {
					webFingerprints[hash].ResponseMatch = append(webFingerprints[hash].ResponseMatch, responseMatch)
				}
			}

			//fingerprints = append(fingerprints, fp)
		}
	}

	return nil
}

func AnalyzeWebFingerprint(target string, wg *sync.WaitGroup, sem chan struct{}, results chan<- CheckResult) {
	defer wg.Done()

	// Acquire a semaphore
	sem <- struct{}{}
	defer func() { <-sem }()

	//tags := []string{}
	// 指纹数量
	if len(webFingerprints) > 0 {
		timeCount := 0
		// 最后识别完成返回的结构
		result := CheckResult{
			Target:   target,
			IsPassed: true,
			Tags:     make([]WebFingerTag, 0),
		}
		// 生成URL对象方便后续拼接
		baseURL, err := url.Parse(target)
		if baseURL.Scheme == "" {
			baseURL, err = url.Parse("http://" + target)
		}
		if err != nil {
			slog.Error("Error parsing URL", "error", err)
		}
		target = baseURL.String()
		// 如果URL不合法则跳出
		if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
			slog.Error("Invalid URL scheme", "scheme", baseURL.Scheme)
			result.IsPassed = false
			results <- result
			return
		}

		for _, fp := range webFingerprints {
			// 超时3次数则跳出
			if timeCount > 3 {
				break
				result.IsPassed = false
			}
			// 拼接URL
			baseURL.Path = fp.Path
			finalURL := baseURL.String()
			req, err := http.NewRequest(strings.ToUpper(fp.RequestMethod), finalURL, strings.NewReader(fp.RequestData))
			if err != nil {
				slog.Error("Error creating request", "error", err)
				continue
			}
			// 设置请求头
			for key, value := range fp.RequestHeaders {
				req.Header.Set(key, value)
			}
			if fp.RequestHeaders["User-Agent"] == "" {
				req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/134.0")
			}

			// 超时时间为10s
			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				// 处理连接超时与端口未开放
				timeCount += 1
				slog.Error("Error sending request", "error", err)
				continue
			}
			defer resp.Body.Close()
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				slog.Error("Error reading response body", "error", err)
				continue
			}
			bodyString := string(bodyBytes)
			for _, responseMatch := range fp.ResponseMatch {
				if responseMatch.StatusCode == resp.StatusCode || responseMatch.StatusCode == 0 {

					match := false
					if len(responseMatch.Keyword) != 0 {
						match = true
					}
					for _, keyword := range responseMatch.Keyword {
						if strings.Contains(keyword, "phpmyadmin") {
							slog.String("bodyString", "phpmyadmin")
						}
						if !strings.Contains(bodyString, keyword) {
							match = false
							break
						}
					}

					if match {
						//tags = append(tags, responseMatch.WebFingerTag.Name)
						result.Tags = append(result.Tags, responseMatch.WebFingerTag)
						//results <- responseMatch.WebFingerTag.Name
						break
					}
				}
			}
		}
		results <- result
	}
}
