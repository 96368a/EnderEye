package main

import "testing"

func Test_singleScan(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "test1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			afrogSingleScan("avbn.233c.cn", "")
		})
	}
}
