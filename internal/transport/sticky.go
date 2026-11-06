package transport

import (
	"crypto/rand"
	"math/big"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	reRegion = regexp.MustCompile(`region-[A-Za-z]+`)
	// arxlabs / 1024proxy: -sid-XXXX[-t-N]
	reDashSid = regexp.MustCompile(`-sid-[A-Za-z0-9]+(-t-\d+)?`)
	// bestgo / trustsource family: -session-ID
	reSession = regexp.MustCompile(`-session-[A-Za-z0-9]+`)
	// ipwo: _sid_ID[_time_N]
	reUnderSid = regexp.MustCompile(`_sid_[A-Za-z0-9]+(_time_\d+)?`)
	reTailT    = regexp.MustCompile(`-t-\d+`)
	// legacy ExtractStickySID helper (kept name used elsewhere)
	reSid = reDashSid
)

const sidChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomSid(n int) string {
	b := make([]byte, n)
	for i := range b {
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(sidChars))))
		b[i] = sidChars[idx.Int64()]
	}
	return string(b)
}

var (
	sidMu   sync.Mutex
	sidSeen = map[string]time.Time{}
)

// FreshUniqueSID is FreshStickySID but guarantees the sticky id was never
// handed out before by this process (so two tickets/accounts can never share
// an exit IP).
func FreshUniqueSID(raw string) string {
	for i := 0; i < 20; i++ {
		out := FreshStickySID(raw)
		key := ExtractStickySID(out)
		if key == "" {
			return out
		}
		sidMu.Lock()
		now := time.Now()
		if len(sidSeen) > 5000 {
			for k, t := range sidSeen {
				if now.Sub(t) > 2*time.Hour {
					delete(sidSeen, k)
				}
			}
		}
		_, dup := sidSeen[key]
		if !dup {
			sidSeen[key] = now
		}
		sidMu.Unlock()
		if !dup {
			return out
		}
	}
	return FreshStickySID(raw)
}

// FreshStickySID generates a fresh sticky session while preserving the
// template's vendor username grammar and region tag.
func FreshStickySID(raw string) string {
	return ApplyStickySID(raw, randomSid(8))
}

type stickyKind int

const (
	kindDashSid stickyKind = iota // -sid-X-t-N
	kindSession                   // -session-X (+ sessTime)
	kindUnderSid                  // _sid_X_time_N
	kindPlain                     // no marker — inject -session-
)

func detectKind(user string) stickyKind {
	switch {
	case reUnderSid.MatchString(user) || strings.Contains(user, "_custom_zone_") || strings.Contains(user, "_zone_"):
		return kindUnderSid
	case reSession.MatchString(user) || strings.Contains(user, "zone-custom") ||
		strings.Contains(user, "sessTime-") || strings.Contains(user, "sessAuto-"):
		return kindSession
	case reDashSid.MatchString(user) || reTailT.MatchString(user):
		return kindDashSid
	default:
		return kindPlain
	}
}

// ApplyStickySID builds a sticky proxy URL using the given sticky id
// (or a random one if empty), matching the vendor's username grammar.
func ApplyStickySID(raw, stickySID string) string {
	raw = CanonProxy(raw)
	if raw == "" {
		return ""
	}
	if stickySID == "" {
		stickySID = randomSid(8)
	}

	u, err := url.Parse(raw)
	if err == nil && u.User != nil && u.User.Username() != "" {
		user := u.User.Username()
		pw, hasPW := u.User.Password()
		user = rewriteUser(user, stickySID, detectKind(user))
		if hasPW {
			u.User = url.UserPassword(user, pw)
		} else {
			u.User = url.User(user)
		}
		return u.String()
	}

	// Fallback: string replace on legacy templates without parseable userinfo.
	region := "region-US"
	if m := reRegion.FindString(raw); m != "" {
		region = m
	}
	newSticky := "-sid-" + stickySID + "-t-10"
	if reDashSid.MatchString(raw) {
		raw = reDashSid.ReplaceAllString(raw, newSticky)
	} else if reTailT.MatchString(raw) {
		raw = reTailT.ReplaceAllString(raw, newSticky)
	} else if strings.Contains(raw, region) && strings.Contains(raw, "@") {
		raw = strings.Replace(raw, region, region+newSticky, 1)
	}
	return raw
}

func rewriteUser(user, sid string, kind stickyKind) string {
	switch kind {
	case kindUnderSid:
		repl := "_sid_" + sid + "_time_10"
		if reUnderSid.MatchString(user) {
			return reUnderSid.ReplaceAllString(user, repl)
		}
		return strings.TrimRight(user, "_") + repl
	case kindSession:
		repl := "-session-" + sid
		if reSession.MatchString(user) {
			user = reSession.ReplaceAllString(user, repl)
		} else {
			user = strings.TrimRight(user, "-") + repl
		}
		if !strings.Contains(user, "sessTime-") {
			user += "-sessTime-5"
		}
		if !strings.Contains(user, "sessAuto-") {
			user += "-sessAuto-1"
		}
		return user
	case kindDashSid:
		repl := "-sid-" + sid + "-t-10"
		if reDashSid.MatchString(user) {
			return reDashSid.ReplaceAllString(user, repl)
		}
		if reTailT.MatchString(user) {
			return reTailT.ReplaceAllString(user, repl)
		}
		return strings.TrimRight(user, "-") + repl
	default:
		repl := "-session-" + sid
		if reSession.MatchString(user) {
			return reSession.ReplaceAllString(user, repl)
		}
		return strings.TrimRight(user, "-") + repl
	}
}

// ExtractStickySID returns the sticky session id from a proxy URL, or "".
func ExtractStickySID(proxy string) string {
	proxy = CanonProxy(proxy)
	user := proxy
	if u, err := url.Parse(proxy); err == nil && u.User != nil {
		user = u.User.Username()
	}
	if m := reDashSid.FindString(user); m != "" {
		m = strings.TrimPrefix(m, "-sid-")
		if i := strings.IndexByte(m, '-'); i > 0 {
			m = m[:i]
		}
		return m
	}
	if m := reSession.FindString(user); m != "" {
		return strings.TrimPrefix(m, "-session-")
	}
	if m := reUnderSid.FindString(user); m != "" {
		m = strings.TrimPrefix(m, "_sid_")
		if i := strings.IndexByte(m, '_'); i > 0 {
			m = m[:i]
		}
		return m
	}
	return ""
}

// RenewStickyTTL keeps the same sticky id but refreshes TTL markers.
func RenewStickyTTL(proxy string) string {
	proxy = CanonProxy(proxy)
	sid := ExtractStickySID(proxy)
	if sid == "" {
		return FreshStickySID(proxy)
	}
	return ApplyStickySID(proxy, sid)
}

// asSocks5h makes the proxy resolve the target name itself.
// socks5:// (local DNS) and http:// on a known SOCKS port/host become socks5h://.
// A plain HTTP proxy on another port is left alone.
func asSocks5h(raw string) string {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "" || strings.HasPrefix(raw, "socks5h://"):
		return raw
	case strings.HasPrefix(raw, "socks5://"):
		return "socks5h://" + strings.TrimPrefix(raw, "socks5://")
	case strings.HasPrefix(raw, "http://"):
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || !socksEndpoint(u.Hostname(), u.Port()) {
			return raw
		}
		return "socks5h://" + strings.TrimPrefix(raw, "http://")
	default:
		return raw
	}
}

func socksEndpoint(host, port string) bool {
	switch port {
	case "3010", "3000", "1080", "9050", "7878", "9595", "6666", "10000":
		return true
	}
	h := strings.ToLower(host)
	for _, tip := range []string{"arxlabs", "1024proxy", "bestgo", "trustsource", "ipwo", "iprocket", "udealproxy"} {
		if strings.Contains(h, tip) {
			return true
		}
	}
	return false
}

// CanonProxy accepts the common one-line proxy spellings and returns a
// scheme://user:pass@host:port URL.
//
// A missing scheme becomes socks5h for known SOCKS ports / hosts, http otherwise.
// An existing socks5:// or SOCKS-port http:// URL is upgraded to socks5h://.
func CanonProxy(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		return asSocks5h(raw)
	}
	schemeFor := func(host, port string) string {
		switch port {
		case "3010", "3000", "1080", "9050", "7878", "9595", "6666", "10000":
			return "socks5h://"
		}
		h := strings.ToLower(host)
		for _, tip := range []string{"arxlabs", "1024proxy", "bestgo", "trustsource", "ipwo", "iprocket", "udealproxy"} {
			if strings.Contains(h, tip) {
				return "socks5h://"
			}
		}
		return "http://"
	}
	if at := strings.LastIndex(raw, "@"); at >= 0 {
		hp := raw[at+1:]
		port := hp
		host := hp
		if i := strings.LastIndex(hp, ":"); i >= 0 {
			host, port = hp[:i], hp[i+1:]
		}
		return schemeFor(host, port) + raw
	}
	p := strings.Split(raw, ":")
	isPort := func(s string) bool { n, err := strconv.Atoi(s); return err == nil && n > 0 && n < 65536 }
	switch {
	case len(p) == 2 && isPort(p[1]):
		return schemeFor(p[0], p[1]) + raw
	case len(p) >= 4 && isPort(p[1]):
		// host:port:user:pass  (pass may itself contain colons)
		return schemeFor(p[0], p[1]) + p[2] + ":" + strings.Join(p[3:], ":") + "@" + p[0] + ":" + p[1]
	case len(p) == 4 && isPort(p[3]):
		return schemeFor(p[2], p[3]) + p[0] + ":" + p[1] + "@" + p[2] + ":" + p[3]
	}
	return raw
}
