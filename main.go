package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func checkTarget(target string, fp WebFingerprintYaml, wg *sync.WaitGroup, sem chan struct{}, results chan<- string) {

	defer wg.Done()

	// Acquire a semaphore
	sem <- struct{}{}
	defer func() { <-sem }()

	for _, f := range fp.Fingerprint {
		url := target + f.Path
		req, err := http.NewRequest(strings.ToUpper(f.RequestMethod), url, strings.NewReader(f.RequestData))
		if err != nil {
			fmt.Println("Error creating request:", err)
			continue
		}

		for key, value := range f.RequestHeaders {
			req.Header.Set(key, value)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error making request:", err)
			continue
		}
		defer resp.Body.Close()

		faviconHash := getFaviconHash(target)

		if resp.StatusCode == f.StatusCode || f.StatusCode == 0 {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Error reading response body:", err)
				continue
			}
			bodyString := string(bodyBytes)

			match := true
			//关键词全匹配
			if len(f.Keyword) != 0 {
				for _, keyword := range f.Keyword {
					if !strings.Contains(bodyString, keyword) {
						match = false
						break
					}
				}
			}
			//图标匹配一个即可
			if len(f.FaviconHash) != 0 {
				match = false
				for _, hash := range f.FaviconHash {
					if hash == faviconHash {
						match = true
						break
					}
				}
			}

			if match {
				results <- fp.Name
				break
			}
		}
	}
}

func readYAMLFiles(dir string) ([]WebFingerprintYaml, error) {
	var fingerprints []WebFingerprintYaml

	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".yaml" {
			filePath := filepath.Join(dir, file.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				return nil, err
			}

			var fp WebFingerprintYaml
			err = yaml.Unmarshal(data, &fp)
			if err != nil {
				return nil, err
			}

			fingerprints = append(fingerprints, fp)
		}
	}

	return fingerprints, nil
}

//func singleTargtCheck(target string) {
//	var wg sync.WaitGroup
//	results := make(chan map[string][]string, 1)
//	sem := make(chan struct{}, 10) // Limit to 10 concurrent goroutines
//	wg.Add(1)
//	go AnalyzeWebFingerprint(target, &wg, sem, results)
//
//	go func() {
//		wg.Wait()
//		close(results)
//	}()
//
//	for result := range results {
//		fmt.Printf("Match found: %s\n", result)
//	}
//}

func multipleCheck(targets []string) error {

	var wg sync.WaitGroup
	results := make(chan CheckResult, 1)
	sem := make(chan struct{}, 10) // Limit to 10 concurrent goroutines
	startTime := time.Now()
	fmt.Println("Scanning targets count:", len(targets))
	for _, target := range targets {
		wg.Add(1)
		go AnalyzeWebFingerprint(target, &wg, sem, results)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		marshal, _ := json.Marshal(result)
		fmt.Printf("Match found: %s\n", marshal)
	}
	elapsedTime := time.Now().Sub(startTime)
	fmt.Println("Scan completed in", elapsedTime)

	return nil
}

func main() {
	target := flag.String("u", "", "Target URL to scan")
	targetFile := flag.String("uf", "", "File containing target URLs to scan")
	flag.Parse()

	err := readFingerprint("web_fingerprint")
	if err != nil {
		fmt.Println("Error reading YAML files:", err)
		os.Exit(1)
	}

	if *target != "" {
		multipleCheck([]string{*target})
		//fmt.Println("Scanning target:", *target)
		//startTime := time.Now()
		//singleTargtCheck(*target)
		//elapsedTime := time.Now().Sub(startTime)
		//fmt.Println("Scan completed in", elapsedTime)
	} else if *targetFile != "" {
		bytes, err := os.ReadFile(*targetFile)
		if err != nil {
			fmt.Println("Error reading target file:", err)
			os.Exit(1)
		}

		var targets []string

		for _, line := range strings.Split(string(bytes), "\n") {
			targets = append(targets, strings.TrimSpace(line))
		}
		multipleCheck(targets)
	} else {
		flag.Usage()
	}

	//startTime := time.Now()
	//
	//var wg sync.WaitGroup
	//results := make(chan string, len(fingerprints))
	//sem := make(chan struct{}, 10) // Limit to 10 concurrent goroutines
	//wg.Add(1)
	//go AnalyzeWebFingerprint(*target, &wg, sem, results)
	//
	//go func() {
	//	wg.Wait()
	//	close(results)
	//}()
	//
	//for result := range results {
	//	fmt.Printf("Match found: %s\n", result)
	//}
	//endTime := time.Now()
	//elapsedTime := endTime.Sub(startTime)
	//fmt.Printf("Scan completed in %s\n", elapsedTime)
}
