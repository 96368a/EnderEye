package main

import (
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

type WebFingerprint struct {
	Name        string        `yaml:"name"`
	Priority    int           `yaml:"priority"`
	NucleiTags  [][]string    `yaml:"nuclei_tags"`
	Fingerprint []Fingerprint `yaml:"fingerprint"`
}

func readYAMLFiles(dir string) ([]WebFingerprint, error) {
	var fingerprints []WebFingerprint

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

			var fp WebFingerprint
			err = yaml.Unmarshal(data, &fp)
			if err != nil {
				return nil, err
			}

			fingerprints = append(fingerprints, fp)
		}
	}

	return fingerprints, nil
}

func checkTarget(target string, fp WebFingerprint, wg *sync.WaitGroup, sem chan struct{}, results chan<- string) {

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

		if resp.StatusCode == f.StatusCode || f.StatusCode == 0 {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Println("Error reading response body:", err)
				continue
			}
			bodyString := string(bodyBytes)

			match := false
			if len(f.Keyword) != 0 {
				match = true
			}
			for _, keyword := range f.Keyword {
				if !strings.Contains(bodyString, keyword) {
					match = false
					break
				}
			}

			if match {
				results <- fp.Name
				break
			}
		}
	}
}

func main() {
	target := flag.String("t", "", "Target URL to scan")
	flag.Parse()

	if *target == "" {
		fmt.Println("Please provide a target URL using the -t flag")
		os.Exit(1)
	}

	fingerprints, err := readYAMLFiles("web_fingerprint")
	if err != nil {
		fmt.Println("Error reading YAML files:", err)
		os.Exit(1)
	}

	startTime := time.Now()

	var wg sync.WaitGroup
	results := make(chan string, len(fingerprints))
	sem := make(chan struct{}, 10) // Limit to 10 concurrent goroutines

	for _, fp := range fingerprints {
		wg.Add(1)
		go checkTarget(*target, fp, &wg, sem, results)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		fmt.Printf("Match found: %s\n", result)
	}
	endTime := time.Now()
	elapsedTime := endTime.Sub(startTime)
	fmt.Printf("Scan completed in %s\n", elapsedTime)
}
