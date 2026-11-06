package transport

import (
	"strings"
	"testing"
)

func TestProxyStaysSocks5h(t *testing.T) {
	cases := []struct{ in, prefix string }{
		{"socks5://user:pw@us.example.io:3010", "socks5h://"},
		{"socks5h://user:pw@us.example.io:3010", "socks5h://"},
		{"http://user:pw@us.arxlabs.io:3010", "socks5h://"},
		{"user:pw@us.example.io:3010", "socks5h://"},
	}
	for _, c := range cases {
		if got := CanonProxy(c.in); !strings.HasPrefix(got, c.prefix) {
			t.Fatalf("canon %q -> %q", c.in, got)
		}
		if strings.Contains(c.in, "://") {
			if got := NormalizeProxy(c.in); !strings.HasPrefix(got, c.prefix) {
				t.Fatalf("norm %q -> %q", c.in, got)
			}
		}
	}
	plain := "http://user:pw@h.example.io:8000"
	if got := NormalizeProxy(plain); got != plain {
		t.Fatalf("plain http changed: %s", got)
	}
}

func TestSingleLineProxyGetsFreshSID(t *testing.T) {
	cases := []struct {
		in, wantRegion string
	}{
		{"socks5h://user-region-US-sid-AAAAAAAA-t-10:pw@us.example.io:3010", "region-US"},
		{"socks5h://user:pw@us.example.io:3010", "region-US"},
		{"user:pw@us.example.io:3010", "region-US"},
		{"us.example.io:3010:user:pw", "region-US"},
		{"http://user-region-JP:pw@h.example.io:8000", "region-JP"},
		{"socks5h://p9mx-region-JP:pw@us.arxlabs.io:3010", "region-JP"},
	}
	for _, c := range cases {
		a, b := FreshUniqueSID(c.in), FreshUniqueSID(c.in)
		if a == b {
			t.Fatalf("%q: two calls gave the same proxy %q", c.in, a)
		}
		if ExtractStickySID(a) == "" || !strings.Contains(a, "@") {
			t.Fatalf("%q -> %q (want sticky id + creds)", c.in, a)
		}
		if strings.Contains(c.in, "region-JP") && !strings.Contains(a, "region-JP") {
			t.Fatalf("%q -> %q (lost region-JP)", c.in, a)
		}
		if c.wantRegion != "region-US" && strings.Contains(a, "region-US") && !strings.Contains(c.in, "region-US") {
			t.Fatalf("%q -> %q (forced US, should keep %s)", c.in, a, c.wantRegion)
		}
		t.Logf("%-70s -> %s", c.in, a)
	}
}

func TestVendorStickyFormats(t *testing.T) {
	cases := []struct {
		name, in, wantSub string // substring that must appear after rewrite
		wantKind          string // dash|session|under
	}{
		{"arxlabs", "us.arxlabs.io:3010:9esb-region-US-sid-wxa9njGh-t-5:pw", "-sid-", "dash"},
		{"1024proxy", "us.1024proxy.io:3000:fcer-region-US-sid-Skjk8MPH-t-5:pw", "-sid-", "dash"},
		{"bestgo", "us.rrp.bestgo.work:10000:USER-zone-custom-region-US-session-17755136-sessTime-5-sessAuto-1:pw", "-session-", "session"},
		{"trustsource", "us.rotgb.trustsource.live:10000:USER-zone-custom-region-US:pw", "-session-", "session"},
		{"ipwo", "us.ipwo.net:7878:al123_custom_zone_US_sid_12393933_time_10:pw", "_sid_", "under"},
		{"iprocket", "us.iprocket.io:9595:com76625210-res-US:pw", "-session-", "session"},
		{"udeal", "us.udealproxy.com:6666:userId-8245-custom-23160-region-us:pw", "-session-", "session"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := FreshUniqueSID(c.in)
			b := FreshUniqueSID(c.in)
			if !strings.Contains(a, c.wantSub) {
				t.Fatalf("missing %s in %s", c.wantSub, a)
			}
			sidA, sidB := ExtractStickySID(a), ExtractStickySID(b)
			if sidA == "" || sidB == "" || sidA == sidB {
				t.Fatalf("bad sids %q %q from %s / %s", sidA, sidB, a, b)
			}
			// must NOT leave both old and new markers for bestgo
			if c.name == "bestgo" && strings.Contains(a, "session-17755136") {
				t.Fatalf("old session id left in place: %s", a)
			}
			if c.name == "arxlabs" && strings.Contains(a, "wxa9njGh") {
				t.Fatalf("template sid left: %s", a)
			}
			if c.name == "ipwo" && strings.Contains(a, "12393933") {
				t.Fatalf("template sid left: %s", a)
			}
			// sticky reuse keeps id
			c2 := ApplyStickySID(c.in, sidA)
			if ExtractStickySID(c2) != sidA {
				t.Fatalf("reuse lost sid: %s -> %s", sidA, c2)
			}
			t.Logf("%s", a)
		})
	}
}
