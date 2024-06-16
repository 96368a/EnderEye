package main

import (
	"testing"
	"time"
)

func Test_readFingerprint(t *testing.T) {

	startTime := time.Now()
	fingerprints, err := readFingerprint("web_fingerprint")
	if err != nil {
		t.Errorf("readFingerprint() error = %v", err)
	}
	if len(fingerprints) == 0 {
		t.Errorf("readFingerprint() error = %v", "no fingerprints")
	}
	endTime := time.Now()
	elapsedTime := endTime.Sub(startTime)
	t.Logf("readFingerprint() elapsed time = %v", elapsedTime)
}

func Test_readYAMLFiles(t *testing.T) {

	startTime := time.Now()
	fingerprints, err := readYAMLFiles("web_fingerprint")
	if err != nil {
		t.Errorf("readYAMLFiles() error = %v", err)
	}
	if len(fingerprints) == 0 {
		t.Errorf("readYAMLFiles() error = %v", "no fingerprints")
	}
	endTime := time.Now()
	elapsedTime := endTime.Sub(startTime)
	t.Logf("readYAMLFiles() elapsed time = %v", elapsedTime)
}
