package main

import (
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"firefly-go/internal/refill"
)

//go:embed web/*
var webFS embed.FS

type logLine struct {
	T     int64  `json:"t"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

type App struct {
	layout layout
	store  *Store
	engine *Engine

	mu          sync.Mutex
	logs        []logLine
	envChecking bool
	envReady    bool
}

func newApp(l layout) *App {
	a := &App{layout: l, store: openStore(l.StateFile), envChecking: true}
	a.engine = newEngine(a.store, l.Sandbox, a.addLog)
	return a
}

func (a *App) finishEnv(ok bool) {
	a.mu.Lock()
	a.envChecking = false
	a.envReady = ok
	a.mu.Unlock()
}

func (a *App) addLog(level, msg string) {
	a.mu.Lock()
	a.logs = append(a.logs, logLine{T: time.Now().UnixMilli(), Level: level, Msg: msg})
	if len(a.logs) > 400 {
		a.logs = a.logs[len(a.logs)-400:]
	}
	a.mu.Unlock()
}

func (a *App) handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/state", a.handleState)
	mux.HandleFunc("/api/env/init", a.handleEnvInit)
	mux.HandleFunc("/api/env", a.handleEnv)
	mux.HandleFunc("/api/settings", a.handleSettings)
	mux.HandleFunc("/api/import", a.handleImport)
	mux.HandleFunc("/api/start", a.handleStart)
	mux.HandleFunc("/api/stop", a.handleStop)
	mux.HandleFunc("/api/delete", a.handleDelete)
	mux.HandleFunc("/api/export", a.handleExport)
	mux.HandleFunc("/api/open", a.handleOpen)
	mux.HandleFunc("/api/window/", handleWindow)
	return mux
}

func (a *App) handleOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var body struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, 400, "链接读不懂")
		return
	}
	switch body.URL {
	case "https://cookieauto.com/register?invite=RUS99UJJ", "https://github.com/lichao199208/ADOBEREG":
		openBrowser(body.URL)
		writeJSON(w, map[string]bool{"ok": true})
	default:
		writeErr(w, 400, "这个链接不能打开")
	}
}

func handleWindow(w http.ResponseWriter, r *http.Request) {
	switch strings.TrimPrefix(r.URL.Path, "/api/window/") {
	case "drag":
		postWindow(wmAppDrag)
	case "minimize":
		postWindow(wmAppMin)
	case "close":
		postWindow(wmAppClose)
	default:
		http.NotFound(w, r)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	accounts := a.store.List()
	view := make([]map[string]any, 0, len(accounts))
	sum := map[string]int{}
	for _, acc := range accounts {
		sum[acc.Status]++
		sum["total"]++
		if acc.Cookie != "" {
			sum["cookie"]++
		}
		view = append(view, map[string]any{
			"id": acc.ID, "email": acc.Email, "country": acc.Country,
			"status": acc.Status, "message": acc.Message, "tries": acc.Tries,
			"hasCookie": acc.Cookie != "", "ready": secretReady(acc.Secret),
		})
	}
	a.mu.Lock()
	logs := append([]logLine(nil), a.logs...)
	a.mu.Unlock()
	writeJSON(w, map[string]any{
		"settings": a.store.Settings(),
		"accounts": view,
		"sum":      sum,
		"running":  a.engine.Running(),
		"logs":     logs,
	})
}

func (a *App) handleEnv(w http.ResponseWriter, r *http.Request) {
	rep := a.layout.report()
	a.mu.Lock()
	rep["checking"] = a.envChecking
	rep["ready"] = a.envReady
	a.mu.Unlock()
	writeJSON(w, rep)
}

func (a *App) handleEnvInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	msgs, ok := a.layout.prepareEnv(func(line string) { a.addLog("info", line) })
	writeJSON(w, map[string]any{"ok": ok, "lines": msgs})
}

func (a *App) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", 405)
		return
	}
	var in Settings
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, 400, "设置读不懂")
		return
	}
	writeJSON(w, a.store.SaveSettings(in))
}

type parsedLine struct{ email, secret string }

func (a *App) handleImport(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&body); err != nil {
		writeErr(w, 400, "导入内容读不懂")
		return
	}
	set := a.store.Settings()
	var lines []parsedLine
	for _, ln := range strings.Split(body.Text, "\n") {
		email, secret, ok := refill.ParseLine(ln)
		if ok {
			lines = append(lines, parsedLine{email, secret})
		}
	}
	if len(lines) == 0 {
		writeErr(w, 400, "没有认出邮箱行")
		return
	}
	added, updated := a.store.Import(lines, set.Country)
	a.addLog("info", "导入 "+itoa(added)+" 新增，"+itoa(updated)+" 更新")
	writeJSON(w, map[string]int{"added": added, "updated": updated})
}

func (a *App) handleStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
		All bool     `json:"all"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	ids := body.IDs
	if body.All {
		ids = nil
		for _, acc := range a.store.List() {
			if acc.Status == "pending" || acc.Status == "failed" {
				ids = append(ids, acc.ID)
			}
		}
		if n := a.store.Settings().Count; n > 0 && len(ids) > n {
			ids = ids[:n]
		}
	}
	n, err := a.engine.Start(ids)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]int{"count": n})
}

func (a *App) handleStop(w http.ResponseWriter, r *http.Request) {
	a.engine.Stop()
	a.addLog("warn", "已请求停止")
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
	writeJSON(w, map[string]int{"deleted": a.store.Delete(body.IDs)})
}

func (a *App) handleExport(w http.ResponseWriter, r *http.Request) {
	var ids []string
	if r.Method == http.MethodPost {
		var body struct {
			IDs []string `json:"ids"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeErr(w, 400, "导出内容读不懂")
			return
		}
		if len(body.IDs) == 0 {
			writeErr(w, 400, "先勾选要导出的邮箱")
			return
		}
		ids = body.IDs
	}
	lines := a.store.CookiesOf(ids)
	if len(lines) == 0 {
		writeErr(w, 400, "没有可导出的已注册账号")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=cookies.txt")
	_, _ = io.WriteString(w, strings.Join(lines, "\n"))
	_, _ = io.WriteString(w, "\n")
}

func secretReady(secret string) bool {
	return strings.Count(secret, "----") >= 2
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
