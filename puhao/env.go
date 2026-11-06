package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type layout struct {
	AppDir    string
	DataDir   string
	Sandbox   string
	Protocol  string
	StateFile string
	NodeDir   string
	Python    string
}

func resolveLayout() layout {
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	cwd, _ := os.Getwd()

	appDir, dataDir := cwd, ""
	if hasProtocol(filepath.Join(exeDir, "data")) {
		appDir, dataDir = exeDir, filepath.Join(exeDir, "data")
	} else if hasProtocol(filepath.Join(cwd, "data")) {
		appDir, dataDir = cwd, filepath.Join(cwd, "data")
	} else if hasProtocol(filepath.Join(cwd, "..", "data")) {
		appDir, dataDir = cwd, filepath.Join(cwd, "..", "data")
	} else {
		dataDir = filepath.Join(appDir, "data")
	}
	appDir, _ = filepath.Abs(appDir)
	dataDir, _ = filepath.Abs(dataDir)

	l := layout{
		AppDir:    appDir,
		DataDir:   dataDir,
		Sandbox:   firstExistingDir(filepath.Join(dataDir, "arksandbox"), filepath.Join(filepath.Dir(dataDir), "dist", "data", "arksandbox")),
		Protocol:  filepath.Join(dataDir, "activate", "adobe_pure_protocol"),
		StateFile: filepath.Join(appDir, "puhao.db"),
	}
	if l.Sandbox == "" {
		l.Sandbox = filepath.Join(dataDir, "arksandbox")
	}
	l.NodeDir = firstExistingDir(
		filepath.Join(appDir, "runtime", "node"),
		filepath.Join(filepath.Dir(dataDir), "dist", "runtime", "node"),
		filepath.Join(dataDir, "..", "dist", "runtime", "node"),
	)
	l.Python = firstExistingFile(
		filepath.Join(appDir, "runtime", "python", "python.exe"),
		filepath.Join(filepath.Dir(dataDir), "dist", "runtime", "python", "python.exe"),
		filepath.Join(dataDir, "..", "dist", "runtime", "python", "python.exe"),
	)
	return l
}

func (l layout) apply() {
	_ = os.MkdirAll(filepath.Dir(l.StateFile), 0o755)
	_ = os.MkdirAll(l.DataDir, 0o755)
	_ = os.Setenv("DATA_DIR", l.DataDir)
	_ = os.Setenv("ADOBE_PURE_PROTOCOL", l.Protocol)
	_ = os.Setenv("ARK_SANDBOX_DIR", l.Sandbox)
	if l.Python != "" {
		_ = os.Setenv("PYTHON_BIN", l.Python)
		pyDir := filepath.Dir(l.Python)
		prependPath(pyDir)
		prependPath(filepath.Join(pyDir, "Scripts"))
	}
	if l.NodeDir != "" {
		prependPath(l.NodeDir)
	}
	if parent := filepath.Dir(l.DataDir); parent != "" {
		_ = os.Chdir(parent)
	}
}

func (l layout) prepareEnv(log func(string)) (msgs []string, ok bool) {
	note := func(s string) {
		msgs = append(msgs, s)
		if log != nil {
			log(s)
		}
	}
	ok = true
	node := ""
	if l.NodeDir != "" {
		node = filepath.Join(l.NodeDir, "node.exe")
	}
	if node == "" || !fileExists(node) {
		ok = false
		note("没有找到 Node")
	} else if err := runCmd(node, []string{"-e", "process.exit(0)"}, 20*time.Second); err != nil {
		ok = false
		note("Node 无法运行")
	} else {
		note("Node 已就绪")
	}

	if l.Python == "" || !fileExists(l.Python) {
		ok = false
		note("没有找到 Python")
	} else if missing := missingPyMods(l.Python); len(missing) == 0 {
		note("Python 依赖已就绪")
	} else {
		req := filepath.Join(l.DataDir, "activate", "requirements.txt")
		note("正在安装 " + strings.Join(missing, "、"))
		if !fileExists(req) {
			ok = false
			note("没有找到依赖清单")
		} else if err := installPy(l.Python, req); err != nil {
			ok = false
			note("安装失败")
		} else if missing = missingPyMods(l.Python); len(missing) > 0 {
			ok = false
			note("仍缺少 " + strings.Join(missing, "、"))
		} else {
			note("Python 依赖已安装")
		}
	}

	if _, err := os.Stat(filepath.Join(l.Protocol, "arp", "yescaptcha.py")); err != nil {
		ok = false
		note("没有找到协议")
	} else {
		note("协议已就绪")
	}
	n := 0
	ents, _ := os.ReadDir(filepath.Join(l.Sandbox, "profiles", "devices"))
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".json") {
			n++
		}
	}
	if n == 0 {
		ok = false
		note("没有设备指纹")
	} else {
		note("设备指纹 " + itoa(n))
	}
	return msgs, ok
}

func missingPyMods(python string) []string {
	const code = "import importlib.util,sys\nmods=['curl_cffi','Crypto','PIL','requests']\nprint(','.join(m for m in mods if importlib.util.find_spec(m) is None))"
	out, err := runOut(python, []string{"-c", code}, 30*time.Second)
	if err != nil {
		return []string{"curl_cffi", "Crypto", "PIL", "requests"}
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil
	}
	return strings.Split(out, ",")
}

func installPy(python, req string) error {
	_ = runCmd(python, []string{"-m", "ensurepip", "--upgrade"}, 2*time.Minute)
	return runCmd(python, []string{"-m", "pip", "install", "--disable-pip-version-check", "-r", req}, 8*time.Minute)
}

func runCmd(bin string, args []string, limit time.Duration) error {
	_, err := runOut(bin, args, limit)
	return err
}

func runOut(bin string, args []string, limit time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	hideCmd(cmd)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func (l layout) report() map[string]any {
	node := ""
	if p, err := exec.LookPath("node"); err == nil {
		node = p
	}
	devices := 0
	ents, _ := os.ReadDir(filepath.Join(l.Sandbox, "profiles", "devices"))
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".json") {
			devices++
		}
	}
	_, protocolOK := os.Stat(filepath.Join(l.Protocol, "arp"))
	return map[string]any{
		"appDir":    l.AppDir,
		"dataDir":   l.DataDir,
		"node":      node,
		"python":    l.Python,
		"protocol":  protocolOK == nil,
		"devices":   devices,
		"stateFile": l.StateFile,
	}
}

func hasProtocol(dataDir string) bool {
	st, err := os.Stat(filepath.Join(dataDir, "activate", "solve_arkose.py"))
	return err == nil && !st.IsDir()
}

func firstExistingDir(cands ...string) string {
	for _, c := range cands {
		c = filepath.Clean(c)
		st, err := os.Stat(c)
		if err == nil && st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

func firstExistingFile(cands ...string) string {
	for _, c := range cands {
		c = filepath.Clean(c)
		st, err := os.Stat(c)
		if err == nil && !st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

func prependPath(dir string) {
	if dir == "" {
		return
	}
	cur := os.Getenv("PATH")
	_ = os.Setenv("PATH", dir+string(os.PathListSeparator)+cur)
}
