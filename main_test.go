package main

import (
	"os"
	"strings"
	"testing"
)

func Test_singleTargtCheck(t *testing.T) {
	err := readFingerprint("web_fingerprint")
	if err != nil {
		t.Errorf("readFingerprint() error = %v", err)
	}
	targets := []string{"http://127.0.0.1", "http://demo.ruoyi.vip/"}
	for _, target := range targets {
		multipleCheck([]string{target}, false)
	}
}

func Test_multipleCheck(t *testing.T) {
	// 读取指纹
	err := readFingerprint("web_fingerprint")
	if err != nil {
		t.Errorf("readFingerprint() error = %v", err)
	}
	// 读取目标URL列表
	bytes, err := os.ReadFile("urls.txt")
	if err != nil {
		t.Errorf("os.ReadFile() error = %v", err)
		os.Exit(1)
	}

	var targets []string

	for _, line := range strings.Split(string(bytes), "\n") {
		targets = append(targets, strings.TrimSpace(line))
	}
	err = multipleCheck(targets, true)
	if err != nil {
		t.Errorf("multipleCheck() error = %v", err)
	}
}
