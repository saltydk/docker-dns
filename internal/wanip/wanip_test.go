package wanip

import (
	"net"
	"testing"
)

func TestIsValidWANIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		version int
		want    bool
	}{
		{name: "public v4", ip: "8.8.8.8", version: 4, want: true},
		{name: "private v4", ip: "192.168.1.1", version: 4, want: false},
		{name: "loopback v4", ip: "127.0.0.1", version: 4, want: false},
		{name: "public v6", ip: "2001:4860:4860::8888", version: 6, want: true},
		{name: "loopback v6", ip: "::1", version: 6, want: false},
		{name: "v6 checked as v4", ip: "2001:4860:4860::8888", version: 4, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isValidWANIP(net.ParseIP(tc.ip), tc.version)
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}
