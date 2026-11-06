package activate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"firefly-go/internal/geo"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	arkHost = "https://arks-client.adobe.com"
	// signupRSAPublicPEM is the Arkose site key for Adobe Express signup (PK 436DD567-...).
	// Current api.js is JSVMP-obfuscated and no longer embeds this PEM in plaintext.
	signupRSAPublicPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzKujot2aB1DweLR4kBKu
kEbje+c8ii97V9b2nW3I6vK8pkyRtJ5WO+9/KEjCMILoMYQN1+tZFFvkPRBDdJL6
4/DQ0/X2WiKjv28V3rM3ziCcRECc8ZJk895E05jQUTfav39Mi1EjhwJdEvq6z6lR
7Dd7mS4AY5wB1/hGy0e4VhTRc+v10P0jiNpKTrzETOhScYra+zyhnhzxywpGXsXB
+bKiLuOFCDaxiab7lgifdIMj6MOBAL0IkzagyrVF3CWMK+zBK//1mHJlyzhGZrVn
0hfkVgBnDcPYxK30GR7GfV2sHfus3x/KJyEq1x8SfyC13dBkimNlsXcV/Cj9kJfu
fQIDAQAB
-----END PUBLIC KEY-----`
	arkBuildID   = "9fdbbdc3-859f-44ba-8334-229c279a79f1"
	capiVersion  = "4.6.0"
	arkDefaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
)

type arkSession struct {
	full    string
	session string
	sid     string
}

type captchaKey struct {
	Provider string
	Key      string
}

// solveCaptcha encrypts this device's fingerprint into the Arkose request,
// then recognises each challenge image. It returns token candidates for the
// account submit. The whole-token solver is not used here.
func solveCaptcha(ctx context.Context, sess *Session, cap captchaKey, devicePath, blob string, log LogFunc) ([]string, error) {
	step := func(msg string) {
		if log != nil && strings.TrimSpace(msg) != "" {
			log(msg)
		}
	}
	if strings.TrimSpace(cap.Key) == "" {
		return nil, fmt.Errorf("没有打码密钥")
	}
	pub, fromJS := loadSignupPublicKey(ctx, sess)
	if pub == nil {
		return nil, fmt.Errorf("验证码公钥没取到")
	}
	pack, err := fingerprintPack(devicePath, sess.proxy)
	if err != nil {
		return nil, err
	}
	sealed, err := encryptFingerprint(pack, pub)
	if err != nil {
		return nil, err
	}
	if toks, err := solveCaptchaViaPure(ctx, sess, cap, devicePath, sealed, blob, log); err == nil && len(toks) > 0 {
		return toks, nil
	} else if err != nil && log != nil {
		log("本地认图这局没过，换路径再试：" + clip(err.Error(), 120))
	}
	if fromJS {
		step("指纹加密塞进验证码啦")
	} else {
		step("用站点钥匙把指纹加密好啦")
	}
	gt, err := postGT2(ctx, sess, devicePath, sealed, blob)
	if err != nil {
		return nil, err
	}
	step("验证码会话建立好啦")
	if gt.pow {
		step("开始做工作量小证明")
		if err := solvePow(ctx, sess, gt.session); err != nil {
			return nil, err
		}
		step("工作量小证明过关啦")
	}
	game, err := postGFCT(ctx, sess, gt.session)
	if err != nil {
		return nil, err
	}
	var guesses []int
	var script string
	var last map[string]any
	for round := 0; round < 8; round++ {
		img := firstImage(game.raw)
		if img == "" {
			break
		}
		png, err := arkDo(ctx, sess, http.MethodGet, absArk(img), "", nil, nil)
		if err != nil {
			return nil, err
		}
		if png.Status != 200 || len(png.Body) < 32 {
			return nil, fmt.Errorf("验证码图片没取到")
		}
		question := instructionOf(game.raw)
		if question == "" {
			question = "请选出正确的图片呀"
		}
		step(fmt.Sprintf("认图第%d轮：%s", round+1, clip(question, 48)))
		idx, err := classifyImage(ctx, cap.Provider, cap.Key, base64.StdEncoding.EncodeToString(png.Body), question)
		if err != nil {
			return nil, err
		}
		if n := pngTileCount(png.Body); n > 0 && idx >= n {
			idx = idx % n
		}
		if idx < 0 {
			idx = 0
		}
		step(fmt.Sprintf("认图第%d轮点了第%d块", round+1, idx))
		guesses = append(guesses, idx)
		var tanswer json.RawMessage
		if game.dapib == "" {
			return nil, fmt.Errorf("缺少 dapib 地址")
		}
		if script == "" {
			src, err := arkDo(ctx, sess, http.MethodGet, absArk(game.dapib), "", nil, nil)
			if err != nil {
				return nil, err
			}
			if src.Status != 200 || len(src.Body) < 32 {
				return nil, fmt.Errorf("dapib 脚本为空")
			}
			script = string(src.Body)
			_ = os.WriteFile("data/activate/last_dapib.js", src.Body, 0o644)
		}
		tanswer, err = runDapib(ctx, script, dapibAnswer(guesses, gt.session.session))
		if err != nil {
			return nil, fmt.Errorf("dapib 失败: %v", err)
		}
		if len(tanswer) == 0 || string(tanswer) == "null" {
			return nil, fmt.Errorf("dapib 答案为空")
		}
		_ = os.WriteFile("data/activate/last_tanswer.json", tanswer, 0o644)

		answered, err := postCA(ctx, sess, gt.session, game.challengeID, guesses, tanswer)
		if err != nil {
			return nil, err
		}
		if raw, _ := json.Marshal(answered); len(raw) > 0 {
			_ = os.WriteFile("data/activate/last_ca.json", raw, 0o644)
		}
		last = answered
		if denied(answered) {
			return nil, fmt.Errorf("图片答案被拒绝")
		}
		if truthy(answered["solved"]) {
			step("图片验证过关啦")
			return tokenCandidates(gt.full, gt.session.session, strOf(answered["token"])), nil
		}
		// "not answered" with a next challenge_image means this wave was accepted.
		if answered["solved"] != nil && !truthy(answered["solved"]) {
			step(fmt.Sprintf("认图第%d轮没过，换一题再试", round+1))
			break
		}
		if next := nextGame(answered, game); next.challengeID != "" || firstImage(next.raw) != "" {
			game = next
			continue
		}
		break
	}
	if last != nil && truthy(last["solved"]) {
		step("图片验证过关啦")
		return tokenCandidates(gt.full, gt.session.session, strOf(last["token"])), nil
	}
	return nil, fmt.Errorf("图片验证没通过")
}

type gtResult struct {
	full    string
	session arkSession
	pow     bool
}

type gameState struct {
	raw         map[string]any
	challengeID string
	dapib       string
	waves       int
}

func postGT2(ctx context.Context, sess *Session, devicePath, sealed, blob string) (gtResult, error) {
	ua := deviceUA(devicePath)
	form := url.Values{}
	form.Set("public_key", signupPK)
	form.Set("capi_mode", "lightbox")
	form.Set("style_theme", "default")
	form.Set("rnd", rnd())
	if sealed != "" {
		form.Set("c", sealed)
	}
	form.Set("site", authHost)
	form.Set("userbrowser", ua)
	form.Set("language", "en")
	form.Set("data[blob]", blob)
	form.Set("capi_version", capiVersion)
	sec := time.Now().Unix()
	resp, err := arkDo(ctx, sess, http.MethodPost, arkHost+"/fc/gt2/public_key/"+signupPK, "application/x-www-form-urlencoded; charset=UTF-8", []byte(form.Encode()), map[string]string{
		"Origin":            authHost,
		"Referer":           authHost + "/en_US/index.html",
		"x-ark-esync-value": strconv.FormatInt(sec-sec%3600, 10),
		"ark-build-id":      arkBuildID,
	})
	if err != nil {
		return gtResult{}, err
	}
	if resp.Status >= 500 {
		return gtResult{}, fmt.Errorf("上游暂时不可用")
	}
	var body map[string]any
	if json.Unmarshal(resp.Body, &body) != nil {
		return gtResult{}, fmt.Errorf("验证码会话没建立")
	}
	token := strOf(body["token"])
	if token == "" {
		if msg := strOf(body["error"]); msg != "" {
			return gtResult{}, fmt.Errorf("验证码会话没建立 %s", clip(msg, 80))
		}
		return gtResult{}, fmt.Errorf("验证码会话没建立")
	}
	return gtResult{full: token, session: splitArk(token), pow: truthy(body["pow"])}, nil
}

func postGFCT(ctx context.Context, sess *Session, st arkSession) (gameState, error) {
	form := url.Values{}
	form.Set("token", st.session)
	form.Set("sid", st.sid)
	form.Set("render_type", "canvas")
	form.Set("lang", "en")
	form.Set("isAudioGame", "false")
	form.Set("is_compatibility_mode", "false")
	form.Set("apiBreakerVersion", "green")
	form.Set("analytics_tier", "40")
	resp, err := arkDo(ctx, sess, http.MethodPost, arkHost+"/fc/gfct/", "application/x-www-form-urlencoded; charset=UTF-8", []byte(form.Encode()), arkHeaders(st, ""))
	if err != nil {
		return gameState{}, err
	}
	var body map[string]any
	if json.Unmarshal(resp.Body, &body) != nil {
		return gameState{}, fmt.Errorf("验证码题目没取到")
	}
	_ = os.WriteFile("data/activate/last_gfct.json", resp.Body, 0o644)
	g := gameFrom(body)
	if g.challengeID == "" {
		return gameState{}, fmt.Errorf("缺少挑战编号")
	}
	if g.dapib == "" {
		return gameState{}, fmt.Errorf("缺少 dapib 地址")
	}
	return g, nil
}

func postCA(ctx context.Context, sess *Session, st arkSession, challengeID string, guesses []int, tanswer json.RawMessage) (map[string]any, error) {
	guess, err := encryptPayload(indexJSON(guesses), st.session)
	if err != nil {
		return nil, err
	}
	fields := [][2]string{
		{"session_token", st.session},
		{"game_token", challengeID},
		{"sid", st.sid},
		{"guess", guess},
		{"render_type", "canvas"},
		{"analytics_tier", "40"},
		{"bio", b64([]byte(`{"mbio":"","tbio":"","kbio":""}`))},
		{"is_compatibility_mode", "false"},
		{"ecdata", b64([]byte(`{"height":450,"width":400}`))},
	}
	if len(tanswer) > 0 && string(tanswer) != "null" {
		tg, err := encryptPayload(string(tanswer), st.session)
		if err != nil {
			return nil, err
		}
		fields = append(fields, [2]string{"tguess", tg})
	}
	body := encodeFields(fields)
	_ = os.WriteFile("data/activate/last_ca_body.txt", []byte(body), 0o644)
	reqID, err := encryptPayload(`{"sc":[200,233]}`, "REQUESTED"+st.session+"ID")
	if err != nil {
		return nil, err
	}
	resp, err := arkDo(ctx, sess, http.MethodPost, arkHost+"/fc/ca/", "application/x-www-form-urlencoded; charset=UTF-8", []byte(body), arkHeaders(st, reqID))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if json.Unmarshal(resp.Body, &out) != nil {
		return nil, fmt.Errorf("图片答案没提交上")
	}
	return out, nil
}

func solvePow(ctx context.Context, sess *Session, st arkSession) error {
	setupResp, err := arkDo(ctx, sess, http.MethodGet, arkHost+"/pows/setup?session_token="+url.QueryEscape(st.session), "", nil, powHeaders())
	if err != nil {
		return err
	}
	setup := map[string]any{}
	_ = json.Unmarshal(setupResp.Body, &setup)
	if strOf(setup["pow_token"]) == "" {
		return fmt.Errorf("工作量证明初始化为空")
	}
	for round := 0; round < 6; round++ {
		started, err := marshalPowJSON(map[string]any{
			"session_token": st.session,
			"pow_token":     strOf(setup["pow_token"]),
			"round":         round,
			"time":          time.Now().UnixMilli(),
		})
		if err != nil {
			return err
		}
		if _, err := arkDo(ctx, sess, http.MethodPost, arkHost+"/pows/started", "application/json", started, powHeaders()); err != nil {
			return err
		}
		seq := absArk(strOf(setup["sequence"]))
		worker, err := arkDo(ctx, sess, http.MethodGet, seq, "", nil, nil)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(setup)
		result, err := runPow(ctx, string(worker.Body), raw)
		if err != nil {
			return fmt.Errorf("工作量证明计算失败: %v", err)
		}
		_ = os.WriteFile("data/activate/last_pow_result.json", result, 0o644)
		_ = os.WriteFile("data/activate/last_pow_setup.json", raw, 0o644)
		check, err := powCheck(setup, result, st.session)
		if err != nil {
			return err
		}
		_ = os.WriteFile("data/activate/last_pow_check.json", check, 0o644)
		resp, err := arkDo(ctx, sess, http.MethodPost, arkHost+"/pows/check", "application/json", check, powHeaders())
		if err != nil {
			return err
		}
		var body map[string]any
		_ = json.Unmarshal(resp.Body, &body)
		_ = os.WriteFile("data/activate/last_pow_resp.json", resp.Body, 0o644)
		switch strOf(body["action"]) {
		case "challenge":
			return nil
		case "next":
			seqURL := strOf(setup["sequence"])
			for k, v := range body {
				setup[k] = v
			}
			if strOf(setup["sequence"]) == "" {
				setup["sequence"] = seqURL
			}
			continue
		case "block":
			return fmt.Errorf("工作量证明被拦截")
		default:
			snip := string(resp.Body)
			if len(snip) > 180 {
				snip = snip[:180]
			}
			return fmt.Errorf("工作量证明校验失败 动作=%s 状态=%d %s", orEmpty(strOf(body["action"]), "-"), resp.Status, snip)
		}
	}
	return fmt.Errorf("工作量证明校验失败")
}

// powHeaders matches adobe_pure_protocol MatchGame._post_json for /pows/*.
// Missing cookie:timestamp=... is a common cause of {"error":"Invalid Request"}.
func powHeaders() map[string]string {
	ms := strconv.FormatInt(time.Now().UnixMilli(), 10)
	return map[string]string{
		"Referer":              "https://auth.services.adobe.com/",
		"x-newrelic-timestamp": ms,
		"x-requested-with":     "XMLHttpRequest",
		"Cookie":               "timestamp=" + ms,
	}
}

func marshalPowJSON(v any) ([]byte, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(buf.String())), nil
}

func powCheck(setup map[string]any, result json.RawMessage, session string) ([]byte, error) {
	var computed map[string]any
	if json.Unmarshal(result, &computed) != nil {
		return nil, fmt.Errorf("工作量证明结果为空")
	}
	if data, ok := computed["data"].(map[string]any); ok && computed["finalTransform"] == nil {
		computed = data
	}
	transform := computed["finalTransform"]
	answer := computed["result"]
	if answer == nil {
		answer = powResultFromTargets(computed["targetHashData"])
	}
	if transform == nil || answer == nil {
		return nil, fmt.Errorf("工作量证明未完成")
	}
	// Same normalization as adobe_pure_protocol/arp/pow.py run_pow_node:
	// jump-patched worker reports absurd hashRate/time; only rewrite those two scalars.
	hr := floatOf(computed["hashRate"])
	tm := int(floatOf(computed["time"]))
	if hr > 2000 || tm < 200 {
		iters := maxIter(computed)
		start := startNonce(setup)
		dist := iters - start
		if dist < 0 {
			dist = iters
		}
		hr = 130 + float64(time.Now().UnixNano()%230)
		if hr > 0 && dist > 0 {
			tm = int(float64(dist) / hr)
		}
		if tm < 400 {
			tm = 400
		}
	}
	return marshalPowJSON(map[string]any{
		"pow_token":      strOf(setup["pow_token"]),
		"session_token":  session,
		"hash_rate":      hr,
		"execution_time": tm,
		"transform":      transform,
		"result":         answer,
	})
}

func powResultFromTargets(raw any) []map[string]any {
	rows, ok := raw.([]any)
	if !ok || len(rows) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		m, _ := row.(map[string]any)
		if m == nil {
			continue
		}
		hash := m["targetHash"]
		if hash == nil {
			hash = m["target_hash"]
		}
		iters := m["iterations"]
		if iters == nil {
			iters = m["attempt_count"]
		}
		if hash == nil || iters == nil {
			continue
		}
		out = append(out, map[string]any{"target_hash": hash, "attempt_count": iters})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// fingerprintPack builds the Arkose `c` plaintext. Language and time-zone
// offset follow the proxy's exit country (and today's DST), not the device file.
func fingerprintPack(devicePath, proxy string) ([]byte, error) {
	ua := deviceUA(devicePath)
	ver := chromeVer(ua)
	dev := loadDeviceMeta(devicePath)
	loc := geo.ForProxy(proxy)
	dev.Lang, dev.TZOffset = loc.Lang(), loc.Offset(time.Now())
	lang := dev.Lang
	fe := []string{
		ver, strconv.Itoa(dev.HC), "false", "false", "true", lang, "Win32",
		strconv.Itoa(dev.SW), strconv.Itoa(dev.SH), strconv.Itoa(dev.TZOffset),
		"480", "1", "0", lang, "false", "false", "", "0,0",
	}
	f := murmur3x64(strings.Join(fe, ";"))
	wh := murmur3x64("window__location_href|window__tree_index|window__tree_structure") + "|" + murmur3x64("location")
	ife := murmur3x64("arke|" + strings.Join(fe, "|"))
	type pair struct {
		Key   string `json:"key"`
		Value any    `json:"value"`
	}
	pack := map[string]any{
		"api_type": "js",
		"f":        f,
		"n":        base64.StdEncoding.EncodeToString([]byte(strconv.FormatInt(time.Now().Unix(), 10))),
		"wh":       wh,
		"enhanced_fp": []pair{
			{"navigator_device_memory", dev.DM},
			{"navigator_languages", lang},
			{"screen_pixel_depth", 24},
			{"window_inner_width", dev.IW},
			{"window_inner_height", dev.IH},
			{"window_outer_width", dev.OW},
			{"window_outer_height", dev.OH},
			{"user_agent_data_mobile", false},
			{"document__referrer", authHost + "/"},
			{"window__location_href", authHost + "/en_US/index.html"},
			{"client_config__language", lang},
			{"client_config__surl", arkHost},
			{"is_keyless", false},
			{"browser_detection_firefox", false},
			{"browser_detection_brave", false},
			{"headless_browser_phantom", false},
			{"headless_browser_selenium", false},
			{"headless_browser_nightmare_js", false},
			{"webgl_unmasked_vendor", dev.GPUVendor},
			{"webgl_unmasked_renderer", dev.GPURenderer},
			{"webgl_hash_webgl", murmur3x64(ver + ua + "|" + dev.GPURenderer)},
		},
		"fe":       fe,
		"ife_hash": ife,
		"jsbd":     `{"ac":1,"cd":2}`,
	}
	return json.Marshal(pack)
}

type deviceMeta struct {
	HC, DM                 int
	SW, SH, IW, IH, OW, OH int
	Lang                   string
	TZOffset               int
	GPUVendor, GPURenderer string
}

func loadDeviceMeta(path string) deviceMeta {
	out := deviceMeta{
		HC: 8, DM: 8, SW: 1920, SH: 1080, IW: 1920, IH: 969, OW: 1920, OH: 1040,
		Lang: geo.Default.Lang(), TZOffset: geo.Default.Offset(time.Now()),
		GPUVendor:   "Google Inc. (NVIDIA)",
		GPURenderer: "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var d struct {
		HC       int    `json:"hardwareConcurrency"`
		DM       int    `json:"deviceMemory"`
		Language string `json:"language"`
		TZOffset int    `json:"tzOffset"`
		Screen   struct {
			W, H, AW, AH int
		} `json:"screen"`
		Win struct {
			OW, OH, IW, IH int
		} `json:"win"`
		WebGL1 struct {
			Vendor   string `json:"unmaskedVendor"`
			Renderer string `json:"unmaskedRenderer"`
		} `json:"webgl1"`
	}
	if json.Unmarshal(raw, &d) != nil {
		return out
	}
	if d.HC > 0 {
		out.HC = d.HC
	}
	if d.DM > 0 {
		out.DM = d.DM
		if out.DM > 8 {
			out.DM = 8
		}
	}
	if d.Language != "" {
		out.Lang = d.Language
	}
	if d.TZOffset != 0 {
		out.TZOffset = d.TZOffset
	}
	if d.Screen.W > 0 && d.Screen.H > 0 {
		out.SW, out.SH = d.Screen.W, d.Screen.H
	}
	if d.Win.IW > 0 {
		out.IW, out.IH, out.OW, out.OH = d.Win.IW, d.Win.IH, d.Win.OW, d.Win.OH
	} else if d.Screen.AW > 0 {
		out.OW, out.OH = d.Screen.AW, d.Screen.AH
		out.IW, out.IH = d.Screen.AW, d.Screen.AH-40
	}
	if d.WebGL1.Renderer != "" {
		out.GPURenderer = d.WebGL1.Renderer
		if d.WebGL1.Vendor != "" {
			out.GPUVendor = d.WebGL1.Vendor
		}
	}
	return out
}

func deviceUA(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return arkDefaultUA
	}
	var doc struct {
		UA1 string `json:"user_agent"`
		UA2 string `json:"userAgent"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return arkDefaultUA
	}
	if doc.UA2 != "" {
		return doc.UA2
	}
	if doc.UA1 != "" {
		return doc.UA1
	}
	return arkDefaultUA
}

func chromeVer(ua string) string {
	i := strings.Index(ua, "Chrome/")
	if i < 0 {
		return "155.0.0.0"
	}
	rest := ua[i+len("Chrome/"):]
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		rest = rest[:j]
	}
	if rest == "" {
		return "155.0.0.0"
	}
	return rest
}

func splitArk(token string) arkSession {
	session := token
	if i := strings.IndexByte(token, '|'); i >= 0 {
		session = token[:i]
	}
	sid := "ap-southeast-1"
	if i := strings.Index(token, "r="); i >= 0 {
		rest := token[i+2:]
		if j := strings.IndexAny(rest, "|&"); j >= 0 {
			rest = rest[:j]
		}
		if rest != "" {
			sid = rest
		}
	}
	return arkSession{session: session, sid: sid}
}

func tokenCandidates(full, session, caToken string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range []string{caToken, full, session} {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func gameFrom(body map[string]any) gameState {
	return gameState{
		raw:         body,
		challengeID: firstString(body, "challengeID", "challenge_id", "game_token", "gameToken"),
		dapib:       strOf(body["dapib_url"]),
		waves:       int(floatOf(nested(body, "game_data", "waves"))),
	}
}

func nextGame(answered map[string]any, prev gameState) gameState {
	g := gameFrom(answered)
	if g.challengeID == "" {
		g.challengeID = prev.challengeID
	}
	if g.dapib == "" {
		g.dapib = prev.dapib
	}
	if g.waves == 0 {
		g.waves = prev.waves
	}
	return g
}

func pngTileCount(b []byte) int {
	// PNG IHDR width at bytes 16..19; Arkose tiles are 200px wide.
	if len(b) < 24 || string(b[1:4]) != "PNG" {
		return 0
	}
	w := int(b[16])<<24 | int(b[17])<<16 | int(b[18])<<8 | int(b[19])
	if w < 200 {
		return 0
	}
	return w / 200
}

func firstImage(v map[string]any) string {
	if gd, ok := v["game_data"].(map[string]any); ok {
		if s := firstStringList(gd["_challenge_imgs"]); s != "" {
			return s
		}
		if gui, ok := gd["customGUI"].(map[string]any); ok {
			if s := firstStringList(gui["_challenge_imgs"]); s != "" {
				return s
			}
		}
	}
	if s := firstStringList(v["_challenge_imgs"]); s != "" {
		return s
	}
	if rc, ok := v["round_config"].(map[string]any); ok {
		if s := strOf(rc["challenge_image"]); s != "" {
			return s
		}
	}
	return ""
}

func instructionOf(v map[string]any) string {
	if gd, ok := v["game_data"].(map[string]any); ok {
		if s := strOf(gd["instruction_string"]); s != "" {
			return s
		}
	}
	if rc, ok := v["round_config"].(map[string]any); ok {
		return strOf(rc["instruction_string"])
	}
	return ""
}

func dapibAnswer(guesses []int, session string) json.RawMessage {
	sid, rand, ok := strings.Cut(session, ".")
	if !ok || rand == "" {
		rand = "0"
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, n := range guesses {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"index":%d,"%s":"%s"}`, n, jsonEscape(sid), jsonEscape(rand))
	}
	b.WriteByte(']')
	return json.RawMessage(b.String())
}

func indexJSON(guesses []int) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, n := range guesses {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"index":%d}`, n)
	}
	b.WriteByte(']')
	return b.String()
}

func jsonEscape(s string) string {
	out, _ := json.Marshal(s)
	if len(out) < 2 {
		return ""
	}
	return string(out[1 : len(out)-1])
}

func arkHeaders(st arkSession, requestedID string) map[string]string {
	ms := strconv.FormatInt(time.Now().UnixMilli(), 10)
	h := map[string]string{
		"Origin":               arkHost,
		"Referer":              gameReferer(st),
		"x-newrelic-timestamp": ms,
		"x-requested-with":     "XMLHttpRequest",
		"Cookie":               "timestamp=" + ms,
	}
	if requestedID != "" {
		h["x-requested-id"] = requestedID
	}
	return h
}

func gameReferer(st arkSession) string {
	cdn := arkHost + "/cdn/fc"
	q := url.Values{}
	q.Set("session", st.session)
	q.Set("r", st.sid)
	q.Set("meta", "3")
	q.Set("meta_width", "400")
	q.Set("meta_height", "303")
	q.Set("metabgclr", "transparent")
	q.Set("metaiconclr", "#555555")
	q.Set("guitextcolor", "#000000")
	q.Set("pk", signupPK)
	q.Set("at", "40")
	q.Set("ag", "101")
	q.Set("cdn_url", cdn)
	q.Set("surl", strings.TrimPrefix(arkHost, "https://"))
	return arkHost + "/fc/assets/ec-game-core/game-core/1.39.1/standard/index.html?" + q.Encode()
}

func encodeFields(fields [][2]string) string {
	var b strings.Builder
	for i, f := range fields {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(f[0]))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(f[1]))
	}
	return b.String()
}

func loadSignupPublicKey(ctx context.Context, sess *Session) (*rsa.PublicKey, bool) {
	urls := []string{
		arkHost + "/v2/" + signupPK + "/api.js",
		"https://client-api.arkoselabs.com/v2/" + signupPK + "/api.js",
	}
	for _, rawURL := range urls {
		for attempt := 0; attempt < 2; attempt++ {
			js, err := arkDo(ctx, sess, http.MethodGet, rawURL, "", nil, nil)
			if err != nil || js == nil || js.Status >= 400 {
				continue
			}
			if pub, err := parseArkPEM(string(js.Body)); err == nil {
				return pub, true
			}
		}
	}
	if pub, err := parseArkPEM(signupRSAPublicPEM); err == nil {
		return pub, false
	}
	return nil, false
}

func arkDo(ctx context.Context, sess *Session, method, rawURL, contentType string, body []byte, hdr map[string]string) (*Response, error) {
	_ = ctx
	hdrs := [][2]string{
		{"accept", "*/*"},
		{"user-agent", sess.ua},
		{"accept-language", geo.ForProxy(sess.proxy).AcceptLanguage()},
	}
	if contentType != "" {
		hdrs = append(hdrs, [2]string{"content-type", contentType})
	}
	for k, v := range hdr {
		if strings.TrimSpace(v) == "" {
			continue
		}
		lk := strings.ToLower(k)
		found := false
		for i := range hdrs {
			if hdrs[i][0] == lk {
				hdrs[i][1] = v
				found = true
				break
			}
		}
		if !found {
			hdrs = append(hdrs, [2]string{lk, v})
		}
	}
	var last error
	for i := 0; i < 2; i++ {
		status, rh, data, err := sess.pool.Do(sess.id, sess.proxy, method, rawURL, hdrs, body)
		if err == nil {
			return &Response{Status: status, Header: toHeaderMap(rh), Body: data}, nil
		}
		last = err
		msg := strings.ToLower(err.Error())
		retry := strings.Contains(msg, "timeout") || strings.Contains(msg, "reset") || strings.Contains(msg, "refused") || strings.Contains(msg, "eof") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "temporarily")
		if !retry || i == 1 {
			break
		}
	}
	return nil, fmt.Errorf("出站失败 %s", scrubErr(last))
}

func absArk(raw string) string {
	if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
		return raw
	}
	if strings.HasPrefix(raw, "//") {
		return "https:" + raw
	}
	if strings.HasPrefix(raw, "/") {
		return arkHost + raw
	}
	return raw
}

func denied(m map[string]any) bool {
	return strings.HasPrefix(strings.ToUpper(strOf(m["error"])), "DENIED")
}

func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	default:
		return false
	}
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

func floatOf(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	default:
		return 0
	}
}

func nested(m map[string]any, a, b string) any {
	child, _ := m[a].(map[string]any)
	if child == nil {
		return nil
	}
	return child[b]
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := strOf(m[k]); s != "" {
			return s
		}
	}
	return ""
}

func firstStringList(v any) string {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return ""
	}
	return strOf(list[0])
}

func maxIter(computed map[string]any) int {
	list, _ := computed["targetHashData"].([]any)
	best := 0
	for _, item := range list {
		m, _ := item.(map[string]any)
		n := int(floatOf(m["iterations"]))
		if n > best {
			best = n
		}
	}
	return best
}

func startNonce(setup map[string]any) int {
	wc, _ := setup["work_config"].(map[string]any)
	if wc == nil {
		return 0
	}
	return int(floatOf(wc["starting_nonce"]))
}

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func rnd() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000_000_000_000))
	if err != nil {
		return "0.5"
	}
	return "0." + fmt.Sprintf("%015d", n.Int64())
}
