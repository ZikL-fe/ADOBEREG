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
	"sync"
	"time"
)

// yesCaptchaSoftID is our YesCaptcha developer softID (20% commission share).
const yesCaptchaSoftID = 136300

func classifyImage(ctx context.Context, provider, key, imageB64, question string) (int, error) {
	host := solverHost(provider)
	created, err := postSolver(ctx, host+"/createTask", map[string]any{
		"clientKey": key,
		"softID":    yesCaptchaSoftID,
		"task": map[string]any{
			"type":     "FunCaptchaClassification",
			"image":    imageB64,
			"question": question,
		},
	})
	if err != nil {
		return 0, err
	}
	if id, _ := created["errorId"].(float64); id != 0 {
		return 0, fmt.Errorf("%v", orEmpty(strAny(created["errorCode"]), strAny(created["errorDescription"])))
	}
	taskID := created["taskId"]
	if taskID == nil {
		return 0, fmt.Errorf("classify_no_task")
	}
	for i := 0; i < 30; i++ {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		result, err := postSolver(ctx, host+"/getTaskResult", map[string]any{"clientKey": key, "taskId": taskID})
		if err != nil {
			continue
		}
		if id, _ := result["errorId"].(float64); id != 0 {
			return 0, fmt.Errorf("%v", orEmpty(strAny(result["errorCode"]), strAny(result["errorDescription"])))
		}
		if status, _ := result["status"].(string); status != "ready" {
			continue
		}
		sol, _ := result["solution"].(map[string]any)
		objs, _ := sol["objects"].([]any)
		confs, _ := sol["confidences"].([]any)
		// Match adobe_pure_protocol/tools/adobe_register_pure.solve_image:
		// confidences argmax when present, else objects[0].
		if len(confs) > 0 {
			best, bestV := 0, -1.0
			for i, c := range confs {
				var v float64
				switch t := c.(type) {
				case float64:
					v = t
				case json.Number:
					v, _ = t.Float64()
				}
				if v > bestV {
					best, bestV = i, v
				}
			}
			return best, nil
		}
		if len(objs) > 0 {
			switch v := objs[0].(type) {
			case float64:
				return int(v), nil
			case json.Number:
				n, _ := v.Int64()
				return int(n), nil
			}
		}
		if idx, ok := sol["index"].(float64); ok {
			return int(idx), nil
		}
		return 0, fmt.Errorf("classify_empty")
	}
	return 0, fmt.Errorf("classify_timeout")
}

func runDapib(ctx context.Context, source string, answer json.RawMessage) (json.RawMessage, error) {
	// Prefer the proven adobe_pure_protocol runner (process-free vm sandbox).
	if raw, err := runDapibScript(ctx, source, answer); err == nil && len(raw) > 0 && string(raw) != "null" {
		return raw, nil
	}
	out, err := runNodeHelper(ctx, "dapib", map[string]any{
		"source": source,
		"answer": json.RawMessage(answer),
	})
	if err != nil {
		return nil, err
	}
	if !out.OK {
		return nil, fmt.Errorf("%s", orEmpty(out.Error, "dapib failed"))
	}
	if len(out.TAnswer) == 0 {
		return nil, fmt.Errorf("dapib_no_answer")
	}
	return out.TAnswer, nil
}

func runDapibScript(ctx context.Context, source string, answer json.RawMessage) (json.RawMessage, error) {
	dir := filepath.Join("data", "activate")
	runner := filepath.Join(dir, "run_dapib.js")
	if st, err := os.Stat(runner); err != nil || st.IsDir() {
		return nil, fmt.Errorf("run_dapib.js missing")
	}
	td, err := os.MkdirTemp("", "act-dapib-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(td)
	sp := filepath.Join(td, "dapib.js")
	ip := filepath.Join(td, "in.json")
	if err := os.WriteFile(sp, []byte(source), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(ip, answer, 0o644); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "node", runner, sp, ip)
	hideCmd(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run_dapib: %s", clip(orEmpty(strings.TrimSpace(stderr.String()), err.Error()), 160))
	}
	raw := bytes.TrimSpace(stdout.Bytes())
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fmt.Errorf("dapib_no_answer")
	}
	return json.RawMessage(raw), nil
}

func runPow(ctx context.Context, source string, setup json.RawMessage) (json.RawMessage, error) {
	out, err := runNodeHelper(ctx, "pow", map[string]any{
		"source": source,
		"setup":  json.RawMessage(setup),
	})
	if err != nil {
		return nil, err
	}
	if !out.OK {
		return nil, fmt.Errorf("%s", orEmpty(out.Error, "pow failed"))
	}
	if len(out.Result) == 0 {
		return nil, fmt.Errorf("pow_empty")
	}
	return out.Result, nil
}

type nodeOut struct {
	OK      bool            `json:"ok"`
	Error   string          `json:"error"`
	TAnswer json.RawMessage `json:"tanswer"`
	Result  json.RawMessage `json:"result"`
}

var (
	helperOnce sync.Once
	helperPath string
	helperErr  error
)

// helperScript lives under ./data/activate — never under ./data/arksandbox
// so ARP mint (bda_sandbox.js) is untouched.
func resolveHelper() (string, error) {
	helperOnce.Do(func() {
		candidates := []string{
			filepath.Join("data", "activate", "arkose_helper.js"),
			filepath.Join(".", "data", "activate", "arkose_helper.js"),
		}
		if exe, err := os.Executable(); err == nil {
			candidates = append([]string{
				filepath.Join(filepath.Dir(exe), "data", "activate", "arkose_helper.js"),
			}, candidates...)
		}
		for _, c := range candidates {
			if st, err := os.Stat(c); err == nil && !st.IsDir() {
				helperPath = c
				return
			}
		}
		// Last resort: write a minimal dapib-only stub to data/activate (not arksandbox).
		dir := filepath.Join("data", "activate")
		_ = os.MkdirAll(dir, 0o755)
		helperPath = filepath.Join(dir, "arkose_helper.js")
		helperErr = os.WriteFile(helperPath, []byte(fallbackHelperJS), 0o644)
	})
	if helperErr != nil {
		return "", helperErr
	}
	if helperPath == "" {
		return "", fmt.Errorf("activate helper missing")
	}
	return helperPath, nil
}

func runNodeHelper(ctx context.Context, mode string, payload map[string]any) (nodeOut, error) {
	script, err := resolveHelper()
	if err != nil {
		return nodeOut{}, err
	}
	raw, _ := json.Marshal(map[string]any{"mode": mode, "payload": payload})
	cmd := exec.CommandContext(ctx, "node", script)
	hideCmd(cmd)
	cmd.Stdin = bytes.NewReader(raw)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nodeOut{}, fmt.Errorf("node helper: %s", clip(msg, 160))
	}
	var out nodeOut
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nodeOut{}, fmt.Errorf("node helper bad json: %s", clip(stdout.String(), 120))
	}
	return out, nil
}

// Minimal fallback if the full helper file is absent (dapib only; pow needs the full script).
const fallbackHelperJS = `
const fs = require("fs");
const vm = require("vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
function fail(e){ process.stdout.write(JSON.stringify({ok:false,error:String(e&&e.message||e)})); }
function runDapib(source, answer) {
  let result = null;
  const sandbox = { console, Math, JSON, Object, String, Number, Boolean, Array, Date, RegExp, Error,
    parseInt, parseFloat, isNaN, encodeURIComponent, decodeURIComponent, setTimeout, clearTimeout };
  sandbox.window = sandbox; sandbox.self = sandbox; sandbox.globalThis = sandbox; sandbox.parent = sandbox;
  sandbox.navigator = { userAgent: "Mozilla/5.0", webdriver: false };
  sandbox.document = { hidden: false, visibilityState: "visible", activeElement: {} };
  sandbox.ae = { answer, dapibReceive(r) { result = r; } };
  vm.createContext(sandbox);
  vm.runInContext(String(source||""), sandbox, { timeout: 15000 });
  if (!result || result.tanswer == null) throw new Error("dapib_no_answer");
  return result.tanswer;
}
try {
  if (input.mode === "dapib") {
    let answer = input.payload.answer;
    if (typeof answer === "string") { try { answer = JSON.parse(answer); } catch {} }
    process.stdout.write(JSON.stringify({ ok:true, tanswer: runDapib(input.payload.source, answer) }));
  } else {
    fail("pow_helper_missing");
  }
} catch (e) { fail(e); }
`
