package main

const (
	wmAppDrag  = 0x8000 + 1
	wmAppMin   = 0x8000 + 2
	wmAppClose = 0x8000 + 3
)

var shutdownFn func()

func setShutdown(fn func()) { shutdownFn = fn }

func runShutdown() {
	fn := shutdownFn
	shutdownFn = nil
	if fn != nil {
		fn()
	}
}
