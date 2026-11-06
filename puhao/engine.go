package main

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firefly-go/internal/activate"
	"firefly-go/internal/arp"
	"firefly-go/internal/config"
	"firefly-go/internal/mail"
	"firefly-go/internal/transport"
)

type Engine struct {
	store    *Store
	pool     *transport.Pool
	profiles *arp.ProfileBook
	log      func(level, msg string)

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
	proxyN  uint32
}

func newEngine(store *Store, sandbox string, log func(level, msg string)) *Engine {
	return &Engine{
		store:    store,
		pool:     transport.NewPool(),
		profiles: arp.NewProfileBook(sandbox),
		log:      log,
	}
}

func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

func (e *Engine) Start(ids []string) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return 0, errBusy
	}
	set := e.store.Settings()
	if strings.TrimSpace(set.CaptchaKey) == "" {
		return 0, errNoKey
	}
	if len(proxyLines(set.Proxies)) == 0 {
		return 0, errNoProxy
	}
	todo := make([]string, 0, len(ids))
	for _, id := range ids {
		acc, ok := e.store.Get(id)
		if !ok || acc.Status == "running" || acc.Status == "activated" {
			continue
		}
		if !mail.Parse(acc.Secret).Ready() {
			e.store.Update(id, func(a *Account) {
				a.Status, a.Message = "failed", "邮箱凭据不完整"
			})
			continue
		}
		e.store.Update(id, func(a *Account) {
			a.Status, a.Message = "running", "排队中"
		})
		todo = append(todo, id)
	}
	if len(todo) == 0 {
		return 0, errNone
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.running = true
	e.log("info", "开始注册 "+itoa(len(todo))+" 个")
	go e.loop(ctx, todo, set)
	return len(todo), nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	cancel := e.cancel
	e.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (e *Engine) loop(ctx context.Context, ids []string, set Settings) {
	defer func() {
		e.mu.Lock()
		e.running = false
		e.cancel = nil
		e.mu.Unlock()
		e.log("info", "本轮结束")
	}()
	n := set.Concurrency
	if n < 1 {
		n = 1
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for _, id := range ids {
		if ctx.Err() != nil {
			e.store.Update(id, func(a *Account) {
				if a.Status == "running" {
					a.Status, a.Message = "pending", "已停止"
				}
			})
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			e.one(ctx, id, set)
			if set.IntervalSec > 0 {
				select {
				case <-ctx.Done():
				case <-time.After(time.Duration(set.IntervalSec) * time.Second):
				}
			}
		}(id)
	}
	wg.Wait()
}

func (e *Engine) one(ctx context.Context, id string, set Settings) {
	acc, ok := e.store.Get(id)
	if !ok {
		return
	}
	if ctx.Err() != nil {
		e.store.Update(id, func(a *Account) {
			if a.Status == "running" {
				a.Status, a.Message = "pending", "已停止"
			}
		})
		return
	}
	country := acc.Country
	if country == "" {
		country = set.Country
	}
	proxy := e.nextProxy(set.Proxies)
	e.store.Update(id, func(a *Account) {
		a.Status, a.Message = "running", "正在注册"
		a.Tries++
		a.Country = country
	})
	e.log("info", acc.Email+" 出发，国家 "+country)
	prof := e.profiles.For(acc.Email)
	device := ""
	if prof != nil {
		device = prof.File
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	var res activate.Result
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		if ctx.Err() != nil {
			break
		}
		if attempt > 1 {
			proxy = e.nextProxy(set.Proxies)
			e.log("warn", acc.Email+" 换一条线路再试，第 "+itoa(attempt)+" 次")
		}
		res, err = activate.RunPlain(cctx, activate.Input{
			Email:      acc.Email,
			Secret:     acc.Secret,
			Country:    country,
			Proxy:      proxy,
			UA:         config.DefaultUserAgent,
			DevicePath: device,
			Captcha:    struct{ Provider, Key string }{Provider: "yescaptcha", Key: set.CaptchaKey},
			Pool:       e.pool,
			Profile:    prof,
			Log: func(step string) {
				e.log("info", acc.Email+" "+step)
			},
		})
		if err == nil || !retryableActivate(err.Error()) {
			break
		}
		e.log("warn", acc.Email+" "+err.Error())
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	if ctx.Err() != nil && cctx.Err() != nil {
		e.store.Update(id, func(a *Account) {
			a.Status, a.Message = "pending", "已停止"
		})
		e.log("warn", acc.Email+" 已停止")
		return
	}
	if err != nil {
		msg := err.Error()
		if cctx.Err() != nil && ctx.Err() == nil {
			msg = "这轮超时"
		}
		e.store.Update(id, func(a *Account) {
			a.Status, a.Message = "failed", msg
		})
		e.log("error", acc.Email+" "+msg)
		return
	}
	e.store.Update(id, func(a *Account) {
		a.Status, a.Message, a.Cookie = "activated", "注册成功", res.Line
	})
	e.log("ok", acc.Email+" 注册成功")
}

func retryableActivate(msg string) bool {
	for _, part := range []string{
		"没拿到打码参数", "建号敲门失败", "要打码但没拿到参数",
		"认图还没过关", "建号没成功", "出站失败", "上游暂时不可用", "invalid_field",
	} {
		if strings.Contains(msg, part) {
			return true
		}
	}
	return false
}

func (e *Engine) nextProxy(raw string) string {
	lines := proxyLines(raw)
	if len(lines) == 0 {
		return ""
	}
	i := atomic.AddUint32(&e.proxyN, 1)
	return transport.FreshUniqueSID(lines[int(i-1)%len(lines)])
}

func proxyLines(raw string) []string {
	var out []string
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" && !strings.HasPrefix(ln, "#") {
			out = append(out, ln)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
