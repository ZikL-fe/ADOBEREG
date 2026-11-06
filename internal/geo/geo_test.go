package geo

import (
	"testing"
	"time"
)

func TestForProxy(t *testing.T) {
	cases := map[string]string{
		"socks5h://p9mx1124350-region-US-sid-AAAAAAAA-t-10:pw@us.arxlabs.io:3010": "US",
		"socks5h://p9mx-region-JP:pw@us.arxlabs.io:3010":                          "JP",
		"http://user-region-sg-sid-x:pw@h:1":                                      "SG",
		"socks5h://user:pw@us.example.io:3010":                                    "US",
		"socks5h://user-region-ZZ:pw@h:1":                                         "US",
	}
	for proxy, want := range cases {
		if got := ForProxy(proxy).Country; got != want {
			t.Errorf("%s -> %s, want %s", proxy, got, want)
		}
	}
}

func TestOffsetFollowsDST(t *testing.T) {
	us := ForCountry("US")
	if got := us.Offset(time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)); got != 240 {
		t.Errorf("NY summer offset = %d, want 240", got)
	}
	if got := us.Offset(time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)); got != 300 {
		t.Errorf("NY winter offset = %d, want 300", got)
	}
	if got := ForCountry("JP").Offset(time.Now()); got != -540 {
		t.Errorf("Tokyo offset = %d, want -540", got)
	}
}

func TestAcceptLanguage(t *testing.T) {
	if got := ForCountry("US").AcceptLanguage(); got != "en-US,en;q=0.9" {
		t.Errorf("US = %q", got)
	}
	if got := ForCountry("JP").AcceptLanguage(); got != "ja,en-US;q=0.9,en;q=0.8" {
		t.Errorf("JP = %q", got)
	}
}
