package main

import (
	"net"
	"net/http"
	"os"
)

const listenAddr = "127.0.0.1:17620"

func main() {
	l := resolveLayout()
	l.apply()
	app := newApp(l)
	setShutdown(func() {
		app.engine.Stop()
		app.store.ReleaseRunning("软件已关闭，已放开")
	})
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		focusExisting()
		return
	}
	go func() {
		_ = http.Serve(ln, app.handler())
	}()
	go func() {
		app.addLog("info", "正在检查环境")
		_, ok := app.layout.prepareEnv(func(line string) { app.addLog("info", line) })
		app.finishEnv(ok)
		if ok {
			app.addLog("ok", "环境检查通过")
		} else {
			app.addLog("error", "环境还没齐")
		}
	}()
	if hasFlag("--no-open") {
		select {}
	}
	runWindow("http://" + listenAddr + "/")
}

func hasFlag(name string) bool {
	for _, a := range os.Args[1:] {
		if a == name {
			return true
		}
	}
	return false
}
