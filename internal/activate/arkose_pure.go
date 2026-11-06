package activate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// solveCaptchaViaPure runs adobe_pure_protocol MatchGame (local PoW + Classification).
// Returns token candidates or an error; caller may fall back to the Go path.
func solveCaptchaViaPure(ctx context.Context, sess *Session, cap captchaKey, devicePath, sealed, blob string, log LogFunc) ([]string, error) {
	script := filepath.Join("data", "activate", "solve_arkose.py")
	if st, err := os.Stat(script); err != nil || st.IsDir() {
		return nil, fmt.Errorf("缺少纯协议打码脚本")
	}
	var fp any
	if raw, err := fingerprintPack(devicePath, sess.proxy); err == nil {
		_ = json.Unmarshal(raw, &fp)
	}
	payload := map[string]any{
		"proxy":          sess.proxy,
		"ua":             sess.ua,
		"blob":           blob,
		"yescaptcha_key": cap.Key,
		"c":              sealed,
		"fp":             fp,
		"public_key":     signupPK,
		"site":           authHost,
		"surl":           strings.TrimPrefix(arkHost, "https://"),
		"capi_mode":      "lightbox",
	}
	if pem := strings.TrimSpace(signupRSAPublicPEM); pem != "" {
		payload["pem"] = pem
	}
	raw, _ := json.Marshal(payload)
	if log != nil {
		log("走本地拆分打码（更稳一点）")
	}
	pureRoot := pureProtocolRoot()
	if pureRoot == "" {
		return nil, fmt.Errorf("未找到 adobe_pure_protocol（请放在 data/activate/adobe_pure_protocol 或设置 ADOBE_PURE_PROTOCOL）")
	}
	absScript, _ := filepath.Abs(script)
	py := pythonBin()
	cmd := exec.CommandContext(ctx, py, absScript)
	hideCmd(cmd)
	cmd.Dir = pureRoot
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Env = append(os.Environ(),
		"ADOBE_PURE_PROTOCOL="+pureRoot,
		"DATA_DIR="+strings.TrimSpace(os.Getenv("DATA_DIR")),
		"POW_CWD="+pureRoot,
		"POW_SOLVER="+shellQuote(py)+" tools/re/pow_solve.py",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	out := bytes.TrimSpace(stdout.Bytes())
	_ = os.WriteFile("data/activate/last_pure_out.json", out, 0o644)
	if len(stderr.Bytes()) > 0 {
		_ = os.WriteFile("data/activate/last_pure_err.txt", stderr.Bytes(), 0o644)
	}
	if len(out) == 0 {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" && err != nil {
			msg = err.Error()
		}
		return nil, fmt.Errorf("纯协议打码无输出: %s", clip(msg, 160))
	}
	var res struct {
		OK      bool   `json:"ok"`
		Token   string `json:"token"`
		Session string `json:"session"`
		Error   string `json:"error"`
	}
	if json.Unmarshal(out, &res) != nil {
		return nil, fmt.Errorf("纯协议打码结果无效: %s", clip(string(out), 120))
	}
	if !res.OK || res.Token == "" {
		return nil, fmt.Errorf("%s", orEmpty(res.Error, "纯协议打码失败"))
	}
	if log != nil {
		log("认图过关啦")
	}
	return tokenCandidates(res.Token, orEmpty(res.Session, strings.Split(res.Token, "|")[0]), res.Token), nil
}

func tryPureThenGo(ctx context.Context, sess *Session, cap captchaKey, devicePath, sealed, blob string, log LogFunc, goSolve func() ([]string, error)) ([]string, error) {
	ctxPure, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	toks, err := solveCaptchaViaPure(ctxPure, sess, cap, devicePath, sealed, blob, log)
	if err == nil && len(toks) > 0 {
		return toks, nil
	}
	if log != nil && err != nil {
		log("本地认图差点意思，换内置路径再试：" + clip(err.Error(), 100))
	}
	return goSolve()
}
