package activate

import (
	"context"
	"encoding/json"
	"firefly-go/internal/geo"
	"fmt"
	"net/url"
	"strings"

	"firefly-go/internal/transport"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/google/uuid"
)

// Session is one activation attempt bound to a proxy + cookie jar.
type Session struct {
	pool  *transport.Pool
	id    string
	proxy string
	ua    string
}

type Response struct {
	Status int
	Header map[string][]string
	Body   []byte
}

type tracker struct {
	verify string
	state  string
}

func (t *tracker) read(h map[string][]string) {
	for k, vs := range h {
		if len(vs) == 0 || vs[0] == "" {
			continue
		}
		switch strings.ToLower(k) {
		case "x-identity-verification-token":
			t.verify = vs[0]
		case "x-ims-authentication-state-encrypted":
			t.state = vs[0]
		}
	}
}

func (t tracker) extra() map[string]string {
	out := map[string]string{}
	if t.verify != "" {
		out["x-identity-verification-token"] = t.verify
	}
	if t.state != "" {
		out["x-ims-authentication-state-encrypted"] = t.state
	}
	return out
}

func openSession(pool *transport.Pool, proxy, ua string) *Session {
	if ua == "" {
		ua = defaultUA
	}
	return &Session{
		pool:  pool,
		id:    "act-" + uuid.NewString(),
		proxy: proxy,
		ua:    ua,
	}
}

func (s *Session) Cookie(name string) string {
	for _, host := range []string{
		authHost, imsBackend, imsHost, "https://www.adobe.com", "https://account.adobe.com",
		fireflyHome, "https://new.express.adobe.com/", "https://express.adobe.com",
	} {
		if v := s.pool.Cookie(s.id, s.proxy, host, name); v != "" {
			return v
		}
	}
	return ""
}

func headerOne(h map[string][]string, name string) string {
	if h == nil {
		return ""
	}
	for k, vs := range h {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

func toHeaderMap(h fhttp.Header) map[string][]string {
	out := map[string][]string{}
	for k, vs := range h {
		out[k] = append([]string{}, vs...)
	}
	return out
}

func send(ctx context.Context, sess *Session, tr *tracker, method, rawURL string, body any, clientID string, extra map[string]string) (*Response, error) {
	_ = ctx
	if clientID == "" {
		clientID = susiClient
	}
	var payload []byte
	ct := "application/json"
	if body != nil {
		switch b := body.(type) {
		case string:
			payload = []byte(b)
			if !strings.HasPrefix(strings.TrimSpace(b), "{") && !strings.HasPrefix(strings.TrimSpace(b), "[") {
				ct = "application/x-www-form-urlencoded"
			}
		case []byte:
			payload = b
		default:
			raw, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			payload = raw
		}
	}
	if v := extra["content-type"]; v != "" {
		ct = v
	}

	hdrs := [][2]string{
		{"accept", "application/json, text/plain, */*"},
		{"content-type", ct},
		{"origin", authHost},
		{"referer", authHost + "/en_US/index.html?client_id=" + clientID},
		{"x-ims-clientid", clientID},
		{"accept-language", geo.ForProxy(sess.proxy).AcceptLanguage()},
		{"user-agent", sess.ua},
	}
	set := func(k, v string) {
		if v == "" && !strings.EqualFold(k, "x-ims-arp-token") {
			return
		}
		lk := strings.ToLower(k)
		for i := range hdrs {
			if hdrs[i][0] == lk {
				hdrs[i][1] = v
				return
			}
		}
		hdrs = append(hdrs, [2]string{lk, v})
	}
	if tr != nil {
		for k, v := range tr.extra() {
			set(k, v)
		}
	}
	for k, v := range extra {
		set(k, v)
	}
	if strings.EqualFold(extra["sec-fetch-mode"], "navigate") {
		set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}

	status, hdr, data, err := sess.pool.Do(sess.id, sess.proxy, method, rawURL, hdrs, payload)
	resp := &Response{Status: status, Header: toHeaderMap(hdr), Body: data}
	if tr != nil {
		tr.read(resp.Header)
	}
	if err != nil {
		return resp, fmt.Errorf("出站失败 %s", scrubErr(err))
	}
	if status >= 500 {
		return resp, fmt.Errorf("上游暂时不可用")
	}
	return resp, nil
}

func scrubErr(err error) string {
	if err == nil {
		return ""
	}
	s := userinfoRE.ReplaceAllString(err.Error(), "://*@")
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

func postFormHost(ctx context.Context, sess *Session, rawURL string, form url.Values, clientID string) string {
	if clientID == "" {
		clientID = susiClient
	}
	resp, err := send(ctx, sess, &tracker{}, "POST", rawURL, form.Encode(), clientID, map[string]string{
		"content-type":   "application/x-www-form-urlencoded",
		"accept":         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"origin":         authHost,
		"referer":        authHost + "/en_US/index.html?client_id=" + clientID,
		"sec-fetch-mode": "navigate",
		"sec-fetch-dest": "document",
		"x-ims-clientid": clientID,
	})
	if err != nil && resp == nil {
		return ""
	}
	next := headerOne(resp.Header, "Location")
	if next == "" {
		if m := metaURL.FindStringSubmatch(string(resp.Body)); len(m) == 2 {
			next = strings.ReplaceAll(m[1], "&amp;", "&")
		}
	}
	access := tokenIn(next)
	if access == "" {
		access = tokenIn(string(resp.Body))
	}
	for i := 0; i < 8 && strings.HasPrefix(next, "http"); i++ {
		hop, err := send(ctx, sess, &tracker{}, "GET", next, nil, clientID, map[string]string{
			"accept":         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"sec-fetch-mode": "navigate",
			"sec-fetch-dest": "document",
		})
		if err != nil || hop == nil {
			break
		}
		if sess.Cookie("ims_sid") != "" {
			if access == "" {
				access = tokenIn(headerOne(hop.Header, "Location") + string(hop.Body))
			}
			return access
		}
		loc := headerOne(hop.Header, "Location")
		if loc == "" {
			if m := metaURL.FindStringSubmatch(string(hop.Body)); len(m) == 2 {
				loc = strings.ReplaceAll(m[1], "&amp;", "&")
			}
		}
		if tok := tokenIn(loc + string(hop.Body)); tok != "" {
			access = tok
		}
		if loc == "" {
			break
		}
		next = strings.ReplaceAll(loc, "&amp;", "&")
	}
	return access
}
