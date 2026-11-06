//go:build windows

package main

import (
	"embed"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/wailsapp/go-webview2/pkg/edge"
	"golang.org/x/sys/windows"
)

//go:embed icon.ico
var iconICO embed.FS

const (
	windowW = 1360
	windowH = 840

	wsPopup        = 0x80000000
	wsVisible      = 0x10000000
	wsClipChildren = 0x02000000
	wsClipSiblings = 0x04000000

	wmDestroy       = 0x0002
	wmSize          = 0x0005
	wmClose         = 0x0010
	wmNCLButtonDown = 0x00A1
	wmSetIcon       = 0x0080
	htCaption       = 2
	swMinimize      = 6
	swRestore       = 9
	iconSmall       = 0
	iconBig         = 1
	idcArrow        = 32512
	colorWindow     = 5
)

var (
	user32             = windows.NewLazySystemDLL("user32.dll")
	gdi32              = windows.NewLazySystemDLL("gdi32.dll")
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procModuleHandle   = kernel32.NewProc("GetModuleHandleW")
	procRegisterClass  = user32.NewProc("RegisterClassExW")
	procCreateWindow   = user32.NewProc("CreateWindowExW")
	procDefWindowProc  = user32.NewProc("DefWindowProcW")
	procDestroyWindow  = user32.NewProc("DestroyWindow")
	procPostQuit       = user32.NewProc("PostQuitMessage")
	procGetMessage     = user32.NewProc("GetMessageW")
	procTranslate      = user32.NewProc("TranslateMessage")
	procDispatch       = user32.NewProc("DispatchMessageW")
	procShowWindow     = user32.NewProc("ShowWindow")
	procSetForeground  = user32.NewProc("SetForegroundWindow")
	procLoadCursor     = user32.NewProc("LoadCursorW")
	procLoadImage      = user32.NewProc("LoadImageW")
	procSendMessage    = user32.NewProc("SendMessageW")
	procPostMessage    = user32.NewProc("PostMessageW")
	procReleaseCapture = user32.NewProc("ReleaseCapture")
	procGetSystemMet   = user32.NewProc("GetSystemMetrics")
	procFindWindow     = user32.NewProc("FindWindowW")
	procMsgBox         = user32.NewProc("MessageBoxW")
	procCreateBrush    = gdi32.NewProc("CreateSolidBrush")

	winHWND   uintptr
	winChrome *edge.Chromium
	className = "PuhaoRegister"
)

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	menuName      *uint16
	className     *uint16
	hIconSm       windows.Handle
}

type winMsg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	ptX     int32
	ptY     int32
}

func runWindow(page string) {
	runtime.LockOSThread()
	enableDPI()
	hwnd := createFrame()
	if hwnd == 0 {
		return
	}
	winHWND = hwnd
	chrome := edge.NewChromium()
	winChrome = chrome
	chrome.DataPath = filepath.Join(os.TempDir(), "puhao-webview")
	chrome.SetErrorCallback(func(err error) {
		if err != nil {
			messageBox("普号注册", "窗口打不开："+err.Error())
		}
	})
	chrome.Embed(hwnd)
	chrome.SetBackgroundColour(18, 20, 24, 255)
	chrome.Resize()
	chrome.Navigate(page)
	chrome.Focus()

	var msg winMsg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslate.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatch.Call(uintptr(unsafe.Pointer(&msg)))
	}
}

func hideCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

func focusExisting() {
	name, _ := windows.UTF16PtrFromString(className)
	hwnd, _, _ := procFindWindow.Call(uintptr(unsafe.Pointer(name)), 0)
	if hwnd == 0 {
		return
	}
	procShowWindow.Call(hwnd, swRestore)
	procSetForeground.Call(hwnd)
}

func postWindow(msg uint32) {
	if winHWND == 0 {
		return
	}
	procPostMessage.Call(winHWND, uintptr(msg), 0, 0)
}

func createFrame() uintptr {
	inst, _, _ := procModuleHandle.Call(0)
	cursor, _, _ := procLoadCursor.Call(0, idcArrow)
	brush, _, _ := procCreateBrush.Call(uintptr(rgb(18, 20, 24)))
	icon := loadAppIcon()
	name, _ := windows.UTF16PtrFromString(className)
	title, _ := windows.UTF16PtrFromString("普号注册")
	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   syscall.NewCallback(wndProc),
		hInstance:     windows.Handle(inst),
		hIcon:         windows.Handle(icon),
		hCursor:       windows.Handle(cursor),
		hbrBackground: windows.Handle(brush),
		className:     name,
		hIconSm:       windows.Handle(icon),
	}
	procRegisterClass.Call(uintptr(unsafe.Pointer(&wc)))
	scale := dpiScale()
	width := int(float64(windowW) * scale)
	height := int(float64(windowH) * scale)
	sw, _, _ := procGetSystemMet.Call(0)
	sh, _, _ := procGetSystemMet.Call(1)
	x := (int(sw) - width) / 2
	y := (int(sh) - height) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	hwnd, _, _ := procCreateWindow.Call(
		0,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(title)),
		wsPopup|wsVisible|wsClipChildren|wsClipSiblings,
		uintptr(x), uintptr(y), uintptr(width), uintptr(height),
		0, 0, uintptr(inst), 0,
	)
	if hwnd != 0 && icon != 0 {
		procSendMessage.Call(hwnd, wmSetIcon, iconBig, icon)
		procSendMessage.Call(hwnd, wmSetIcon, iconSmall, icon)
	}
	roundWindow(hwnd, width, height)
	return hwnd
}

func roundWindow(hwnd uintptr, width, height int) {
	if hwnd == 0 {
		return
	}
	dwmapi := windows.NewLazySystemDLL("dwmapi.dll")
	if proc := dwmapi.NewProc("DwmSetWindowAttribute"); proc.Find() == nil {
		pref := uint32(2)
		proc.Call(hwnd, 33, uintptr(unsafe.Pointer(&pref)), 4)
	}
	rad := int(14 * dpiScale())
	rgn, _, _ := gdi32.NewProc("CreateRoundRectRgn").Call(0, 0, uintptr(width+1), uintptr(height+1), uintptr(rad), uintptr(rad))
	if rgn != 0 {
		user32.NewProc("SetWindowRgn").Call(hwnd, rgn, 1)
	}
}

func wndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch msg {
	case wmSize:
		if winChrome != nil {
			winChrome.Resize()
		}
		return 0
	case wmAppDrag:
		procReleaseCapture.Call()
		procSendMessage.Call(hwnd, wmNCLButtonDown, htCaption, 0)
		return 0
	case wmAppMin:
		procShowWindow.Call(hwnd, swMinimize)
		return 0
	case wmAppClose, wmClose:
		runShutdown()
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procPostQuit.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wparam, lparam)
	return r
}

func loadAppIcon() uintptr {
	b, err := iconICO.ReadFile("icon.ico")
	if err != nil {
		return 0
	}
	path := filepath.Join(os.TempDir(), "puhao-icon.ico")
	if os.WriteFile(path, b, 0o644) != nil {
		return 0
	}
	p, _ := windows.UTF16PtrFromString(path)
	const lrLoadFromFile = 0x0010
	h, _, _ := procLoadImage.Call(0, uintptr(unsafe.Pointer(p)), 1, 32, 32, lrLoadFromFile)
	return h
}

func dpiScale() float64 {
	getDC := user32.NewProc("GetDC")
	releaseDC := user32.NewProc("ReleaseDC")
	getCaps := gdi32.NewProc("GetDeviceCaps")
	hdc, _, _ := getDC.Call(0)
	dpi, _, _ := getCaps.Call(hdc, 88)
	releaseDC.Call(0, hdc)
	if dpi < 96 {
		return 1
	}
	return float64(dpi) / 96
}

func enableDPI() {
	shcore := windows.NewLazySystemDLL("shcore.dll")
	if proc := shcore.NewProc("SetProcessDpiAwareness"); proc.Find() == nil {
		if r, _, _ := proc.Call(2); r == 0 {
			return
		}
	}
	user32.NewProc("SetProcessDPIAware").Call()
}

func openBrowser(raw string) {
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	proc := shell32.NewProc("ShellExecuteW")
	verb, _ := windows.UTF16PtrFromString("open")
	target, _ := windows.UTF16PtrFromString(raw)
	proc.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(target)), 0, 0, 1)
}

func messageBox(title, text string) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	procMsgBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10)
}

func rgb(r, g, b byte) uintptr {
	return uintptr(uint32(r) | uint32(g)<<8 | uint32(b)<<16)
}
