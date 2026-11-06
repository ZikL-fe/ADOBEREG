package activate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func solverHost(provider string) string {
	if strings.EqualFold(provider, "twocaptcha") || strings.EqualFold(provider, "2captcha") {
		return "https://api.2captcha.com"
	}
	return "https://api.yescaptcha.com"
}

// Whole-token FunCaptchaTask* is disabled. Activate uses local PoW/dapib
// plus FunCaptchaClassification only (see classifyImage / solveCaptcha).
func solveFunCaptcha(ctx context.Context, provider, key, pageURL, publicKey, blob, proxy, ua string, log func(string)) (string, error) {
	_ = ctx
	_ = provider
	_ = key
	_ = pageURL
	_ = publicKey
	_ = blob
	_ = proxy
	_ = ua
	if log != nil {
		log("整令牌打码关掉啦，只玩认图小游戏")
	}
	return "", fmt.Errorf("整令牌打码已禁用")
}

func postSolver(ctx context.Context, rawURL string, body any) (map[string]any, error) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("solver_bad_json")
	}
	return out, nil
}
