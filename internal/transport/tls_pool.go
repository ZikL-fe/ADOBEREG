// Package transport embeds the Chrome 150 TLS/HTTP2 client pool and local relay
// endpoint (migrated directly from tools/ark_relay/main.go) so Go callers and
// the Node Arkose sandbox share one in-process connection pool.
package transport

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"firefly-go/internal/config"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

type RelayReq struct {
	Session string      `json:"session"`
	Proxy   string      `json:"proxy"`
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Headers [][2]string `json:"headers"`
	Body    string      `json:"body"`
}

type RelayResp struct {
	Status   int               `json:"status"`
	Headers  map[string]string `json:"headers"`
	Cookies  []string          `json:"setCookie,omitempty"`
	Body     string            `json:"body"`
	Protocol string            `json:"protocol"`
	Error    string            `json:"error,omitempty"`
}

type jarClient struct {
	client   tlsclient.HttpClient
	lastUsed time.Time
}

type Pool struct {
	mu        sync.Mutex
	clients   map[string]*jarClient
	relayAddr string
	srv       *http.Server
}

func NewPool() *Pool {
	p := &Pool{
		clients: make(map[string]*jarClient),
	}
	go p.sweepLoop()
	return p
}

func (p *Pool) StartLocalRelay() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.relayAddr != "" {
		return p.relayAddr, nil
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	secret := make([]byte, 16)
	_, _ = rand.Read(secret)
	pathSecret := hex.EncodeToString(secret)

	mux := http.NewServeMux()
	mux.HandleFunc("/"+pathSecret+"/", func(w http.ResponseWriter, r *http.Request) {
		var in RelayReq
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(&in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p.DoRelay(in))
	})

	p.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	p.relayAddr = ln.Addr().String() + "/" + pathSecret
	go func() { _ = p.srv.Serve(ln) }()
	return p.relayAddr, nil
}

func (p *Pool) Close() {
	if p.srv != nil {
		_ = p.srv.Close()
	}
}

// NormalizeProxy is the URL the TLS client, IMS exchange and generate-async
// submit actually dial. Name resolution stays on the proxy (socks5h).
func NormalizeProxy(raw string) string {
	return asSocks5h(raw)
}

func (p *Pool) ClientFor(session, proxy string) (tlsclient.HttpClient, error) {
	proxy = NormalizeProxy(proxy)
	p.mu.Lock()
	defer p.mu.Unlock()
	key := session + "|" + proxy
	if c, ok := p.clients[key]; ok {
		c.lastUsed = time.Now()
		return c.client, nil
	}
	timeoutSec := 15
	if strings.HasPrefix(session, "probe-") {
		timeoutSec = 4
	} else if strings.HasPrefix(session, "ftr-") {
		timeoutSec = 6
	} else if strings.HasPrefix(session, "ims-") {
		timeoutSec = 8 // a healthy exit answers IMS in ~1s; a dead one should fail fast
	} else if strings.HasPrefix(session, "up-") || strings.HasPrefix(session, "act-") {
		timeoutSec = 90 // uploads / Adobe activation fromSusi can sit on slow proxies
	}
	opts := []tlsclient.HttpClientOption{
		tlsclient.WithTimeoutSeconds(timeoutSec),
		tlsclient.WithCookieJar(tlsclient.NewCookieJar()),
	}
	if isFireflyAPISession(session) {
		opts = append(opts, tlsclient.WithClientProfile(iosSafariProfile()))
	} else {
		opts = append(opts, tlsclient.WithClientProfile(chrome150Profile()), tlsclient.WithRandomTLSExtensionOrder())
	}
	if proxy != "" {
		opts = append(opts, tlsclient.WithProxyUrl(proxy))
	}
	c, err := tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
	if err != nil {
		return nil, err
	}
	p.clients[key] = &jarClient{client: c, lastUsed: time.Now()}
	return c, nil
}

func (p *Pool) Do(session, proxy, method, rawURL string, headers [][2]string, body []byte) (int, fhttp.Header, []byte, error) {
	var lastErr error
	tries := 3
	if strings.HasPrefix(session, "ims-") {
		tries = 2 // the caller switches account + exit on failure, so don't linger
	}
	for attempt := 0; attempt < tries; attempt++ {
		if attempt > 0 {
			p.evict(session, proxy)
			time.Sleep(time.Duration(attempt*250) * time.Millisecond)
		}
		status, hdr, data, err := p.doOnce(session, proxy, method, rawURL, headers, body)
		if err == nil {
			return status, hdr, data, nil
		}
		lastErr = err
		errMsg := strings.ToLower(err.Error())
		if !strings.Contains(errMsg, "eof") &&
			!strings.Contains(errMsg, "reset") &&
			!strings.Contains(errMsg, "broken pipe") &&
			!strings.Contains(errMsg, "timeout") &&
			!strings.Contains(errMsg, "connection") {
			break
		}
	}
	return 0, nil, nil, lastErr
}

func (p *Pool) DoFast(session, proxy, method, rawURL string, headers [][2]string, body []byte) (int, fhttp.Header, []byte, error) {
	return p.doOnce(session, proxy, method, rawURL, headers, body)
}

func (p *Pool) evict(session, proxy string) {
	proxy = NormalizeProxy(proxy)
	key := session + "|" + proxy
	p.mu.Lock()
	if c, ok := p.clients[key]; ok {
		c.client.CloseIdleConnections()
		delete(p.clients, key)
	}
	p.mu.Unlock()
}

// doOnce preserves the exact header ordering logic from tools/ark_relay/main.go.
func (p *Pool) doOnce(session, proxy, method, rawURL string, headers [][2]string, body []byte) (int, fhttp.Header, []byte, error) {
	c, err := p.ClientFor(session, proxy)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%s", scrub(err.Error(), proxy))
	}
	var rd io.Reader
	if len(body) > 0 {
		rd = bytes.NewReader(body)
	}
	req, err := fhttp.NewRequest(method, rawURL, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	order := make([]string, 0, len(headers)+1)
	hasCL := false
	for _, kv := range headers {
		name := strings.ToLower(kv[0])
		if name == "content-length" {
			hasCL = true
		}
		order = append(order, name)
		if name == "content-length" || name == "host" || kv[1] == "" {
			continue
		}
		req.Header.Add(name, kv[1])
	}
	if len(body) > 0 && !hasCL {
		order = append([]string{"content-length"}, order...)
	}
	req.Header[fhttp.HeaderOrderKey] = order
	req.Header[fhttp.PHeaderOrderKey] = []string{":method", ":authority", ":scheme", ":path"}

	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%s", scrub(err.Error(), proxy))
	}
	defer resp.Body.Close()

	bodyReader := resp.Body
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !resp.Uncompressed {
		bodyReader = fhttp.DecompressBodyByType(resp.Body, ce)
	}
	data, err := io.ReadAll(bodyReader)
	return resp.StatusCode, resp.Header, data, err
}

func (p *Pool) DoRelay(in RelayReq) RelayResp {
	var rawBody []byte
	if in.Body != "" {
		dec, err := base64.StdEncoding.DecodeString(in.Body)
		if err != nil {
			return RelayResp{Error: "body base64"}
		}
		rawBody = dec
	}
	status, hdr, data, err := p.doOnce(in.Session, in.Proxy, in.Method, in.URL, in.Headers, rawBody)
	if err != nil {
		return RelayResp{Error: err.Error()}
	}
	out := RelayResp{
		Status:   status,
		Headers:  map[string]string{},
		Body:     base64.StdEncoding.EncodeToString(data),
		Protocol: "HTTP/2.0",
	}
	for k, v := range hdr {
		lk := strings.ToLower(k)
		if lk == "set-cookie" {
			out.Cookies = append(out.Cookies, v...)
			continue
		}
		if lk == "content-encoding" || lk == "content-length" {
			continue
		}
		out.Headers[lk] = strings.Join(v, ", ")
	}
	return out
}

func (p *Pool) sweepLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-3 * time.Minute)
		p.mu.Lock()
		for key, c := range p.clients {
			if c.lastUsed.Before(cutoff) {
				c.client.CloseIdleConnections()
				delete(p.clients, key)
			}
		}
		p.mu.Unlock()
	}
}

// chrome150Profile matches the HTTP identity: Chrome 150.0.7871.115.
func chrome150Profile() profiles.ClientProfile {
	return profiles.Chrome_150
}

// iosSafariProfile is the TLS/HTTP2 identity for firefly-3p calls, matching
// config.IOSUserAgent. Safari keeps a fixed extension order, so no randomizing.
func iosSafariProfile() profiles.ClientProfile {
	return profiles.Safari_IOS_18_5
}

// isFireflyAPISession reports the firefly-3p sessions (generate-async submit,
// result poll, reference upload) that present the iOS identity.
// The desktop Express site keeps Chrome end to end.
func isFireflyAPISession(session string) bool {
	if config.ExpressSite() {
		return false
	}
	return strings.HasPrefix(session, "gen-") || strings.HasPrefix(session, "poll-") || strings.HasPrefix(session, "up-")
}

func proxyHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func scrub(msg, proxy string) string {
	if proxy == "" {
		return msg
	}
	msg = strings.ReplaceAll(msg, proxy, fmt.Sprintf("proxy(%s)", proxyHost(proxy)))
	if i := strings.Index(proxy, "://"); i >= 0 {
		rest := proxy[i+3:]
		if at := strings.LastIndex(rest, "@"); at > 0 {
			if colon := strings.Index(rest[:at], ":"); colon >= 0 {
				if pass := rest[colon+1 : at]; pass != "" {
					msg = strings.ReplaceAll(msg, pass, "***")
				}
			}
		}
	}
	return msg
}

// Cookie returns one named cookie from the jar bound to session+proxy for host.
func (p *Pool) Cookie(session, proxy, rawURL, name string) string {
	c, err := p.ClientFor(session, proxy)
	if err != nil {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	for _, ck := range c.GetCookies(u) {
		if strings.EqualFold(ck.Name, name) && ck.Value != "" {
			return ck.Value
		}
	}
	return ""
}
