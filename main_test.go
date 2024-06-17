package main

import (
	"testing"
)

func Test_singleTargtCheck(t *testing.T) {
	err := readFingerprint("web_fingerprint")
	if err != nil {
		t.Errorf("readFingerprint() error = %v", err)
	}
	targets := []string{"http://127.0.0.1", "http://demo.ruoyi.vip/"}
	for _, target := range targets {
		singleTargtCheck(target)
	}
}

func Test_multipleCheck(t *testing.T) {
	err := readFingerprint("web_fingerprint")
	if err != nil {
		t.Errorf("readFingerprint() error = %v", err)
	}
	err = multipleCheck("urls.txt")
	if err != nil {
		t.Errorf("multipleCheck() error = %v", err)
	}
}
