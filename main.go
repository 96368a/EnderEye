package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

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

func multipleCheck(targets []string, autoPoc bool) error {

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
		if autoPoc {
			tags := []string{}
			for _, tag := range result.Tags {
				tags = append(tags, tag.Name)
			}
			if len(tags) > 0 {
				afrogSingleScan(result.Target, strings.Join(tags, ","))
			}
		}
	}
	elapsedTime := time.Now().Sub(startTime)
	fmt.Println("Scan completed in", elapsedTime)

	return nil
}

func main() {
	target := flag.String("u", "", "Target URL to scan")
	targetFile := flag.String("uf", "", "File containing target URLs to scan")
	autoPoc := flag.Bool("auto", false, "Auto poc")
	flag.Parse()

	err := readFingerprint("web_fingerprint")
	if err != nil {
		fmt.Println("Error reading YAML files:", err)
		os.Exit(1)
	}

	if *target != "" {
		multipleCheck([]string{*target}, *autoPoc)
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
		multipleCheck(targets, *autoPoc)
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
