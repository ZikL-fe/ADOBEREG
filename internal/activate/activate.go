package activate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"firefly-go/internal/arp"
	"firefly-go/internal/mail"
	"firefly-go/internal/transport"

	"github.com/google/uuid"
)

// LogFunc writes one step into the run log. It must not receive secrets.
type LogFunc func(step string)

// Input is one incomplete Adobe sub-account plus proxy and captcha.
type Input struct {
	Email      string
	Secret     string
	Country    string
	Proxy      string
	UA         string
	DevicePath string // Arkose device JSON for this sub (Profile.File)
	Captcha    struct{ Provider, Key string }
	Pool       *transport.Pool
	Profile    *arp.Profile
	CaptureBFP func(sessionID, proxy, ua string, prof *arp.Profile) (arp.BFPResult, error)
	Log        LogFunc
}

// Result is one activation attempt.
type Result struct {
	OK       bool
	Message  string
	Password string
	Line     string
	Touched  bool
}

func note(in Input, step string) {
	if in.Log != nil && strings.TrimSpace(step) != "" {
		in.Log(step)
	}
}

// Run finishes an incomplete Adobe account and returns a pool cookie line.
func Run(ctx context.Context, in Input) (Result, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	country := strings.ToUpper(strings.TrimSpace(in.Country))
	if country == "" {
		country = "US"
	}
	cred := mail.Parse(in.Secret)
	if email == "" || !cred.Ready() {
		return Result{}, fmt.Errorf("缺邮箱或收码凭据")
	}
	if strings.TrimSpace(in.Captcha.Key) == "" {
		return Result{}, fmt.Errorf("没有打码密钥")
	}
	if strings.TrimSpace(in.Proxy) == "" {
		return Result{}, fmt.Errorf("没有代理")
	}
	if in.Pool == nil {
		return Result{}, fmt.Errorf("没有出站连接池")
	}

	ua := strings.TrimSpace(in.UA)
	devicePath := strings.TrimSpace(in.DevicePath)
	if devicePath == "" && in.Profile != nil {
		devicePath = in.Profile.File
	}
	if dUA := deviceUA(devicePath); dUA != "" {
		ua = dUA
	}
	in.DevicePath = devicePath
	sess := openSession(in.Pool, in.Proxy, ua)
	note(in, "开始给宝宝办证啦，国家 "+country)
	tr := tracker{}
	debugID := uuid.NewString()
	locale := "en_US"
	password := genActivatePassword()
	used := peekCodes(ctx, in.Secret, email)
	referer := authHost + "/en_US/index.html?client_id=" + susiClient

	activateAuthorize(ctx, sess, &tr, email, debugID)
	touched := true
	if st := activateProbeStatus(ctx, sess, &tr, email, debugID); st != "" && st != "incomplete" {
		note(in, "瞅了一眼账号状态："+st)
	}
	if resp, ok := activateAuthStateResp(ctx, sess, &tr, email, debugID, "multiFactorAuthentication"); !ok {
		why := "认证状态没准备好"
		if resp != nil {
			why = fmt.Sprintf("认证状态没准备好（%d）%s", resp.Status, orEmpty(adobeErr(resp.Body), adobeFieldDetail(resp.Body)))
		}
		return Result{Touched: touched, Message: why}, fmt.Errorf("%s", why)
	}
	sent := activateSendIncomplete(ctx, sess, &tr, debugID)
	since := time.Now().Add(-5 * time.Second)
	if !sent {
		since = time.Now().Add(-2 * time.Minute)
	}
	note(in, "盯着邮箱等验证码中…")
	code, waitErr := waitCode(ctx, in.Secret, email, since, used, in.Log)
	if waitErr != nil {
		note(in, waitErr.Error())
		code = ""
	} else if code != "" {
		used[code] = struct{}{}
		note(in, "验证码到手啦")
	}
	susi := ""
	if code != "" {
		susi = activateTokenFromCode(ctx, sess, &tr, debugID, code)
		if susi != "" {
			note(in, "验证码兑换成功～")
		}
	}
	if susi == "" {
		return Result{Touched: touched, Message: "验证码没拿到，这轮先停一下"}, fmt.Errorf("验证码没拿到，这轮先停一下")
	}

	ok, password, reason := activateSubmitProfile(ctx, sess, &tr, in, email, password, country, locale, debugID, susi)
	if !ok {
		return Result{Touched: touched, Message: reason, Password: password}, fmt.Errorf("%s", reason)
	}
	tr.verify, tr.state = "", ""
	note(in, "资料交好了，接着去拿登录凭证")
	line, landErr := loginLine(ctx, sess, &tr, email, in.Secret, debugID, password, in.Log)
	if landErr != nil {
		fallback := cookiePoolLine(ctx, email, sess)
		if strings.Contains(fallback, "ims_sid=") {
			note(in, "登录凭证其实已经有啦，落地时嘀咕了句："+landErr.Error())
			return Result{OK: true, Touched: touched, Message: "激活成功啦", Password: password, Line: fallback}, nil
		}
		return Result{OK: true, Touched: touched, Message: "资料交好了，可登录凭证还没拿到: " + landErr.Error(), Password: password}, fmt.Errorf("资料交好了，可登录凭证还没拿到: %s", landErr.Error())
	}
	if !strings.Contains(line, "ims_sid=") {
		note(in, "登录凭证还没落地哦")
		return Result{OK: true, Touched: touched, Message: "资料交好了，可登录凭证还没拿到", Password: password}, fmt.Errorf("资料交好了，可登录凭证还没拿到")
	}
	_ = referer
	note(in, "登录凭证到手，可以进号池啦")
	return Result{OK: true, Touched: touched, Message: "激活成功啦", Password: password, Line: line}, nil
}

func activateAuthorize(ctx context.Context, sess *Session, tr *tracker, email, debugID string) {
	_, _ = send(ctx, sess, tr, "GET", "https://www.adobe.com/home", nil, susiClient, map[string]string{
		"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	})
	params := url.Values{
		"client_id": {susiClient}, "scope": {homeScope}, "response_type": {"token"},
		"redirect_uri": {"https://www.adobe.com/home#old_hash=&from_ims=true&client_id=" + susiClient + "&api=authorize&scope=" + homeScope},
		"puser":        {email}, "locale": {"en_US"}, "flow_type": {"token"}, "idp_flow_type": {"login"},
		"use_ms_for_expiry": {"true"},
	}
	_, _ = send(ctx, sess, tr, "GET", imsHost+"/ims/authorize/v1?"+params.Encode(), nil, susiClient, map[string]string{
		"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	})
	_, _ = send(ctx, sess, tr, "GET", authHost+"/signin/v2/configurations/"+susiClient, nil, susiClient, map[string]string{
		"x-debug-id": debugID,
	})
}

func activateProbeStatus(ctx context.Context, sess *Session, tr *tracker, email, debugID string) string {
	resp, err := send(ctx, sess, tr, "POST", authHost+"/signin/v2/users/accounts", map[string]string{
		"username": email, "usernameType": "EMAIL",
	}, susiClient, map[string]string{"x-debug-id": debugID})
	if err != nil || resp == nil {
		return ""
	}
	var rows []map[string]any
	if json.Unmarshal(resp.Body, &rows) != nil || len(rows) == 0 {
		return ""
	}
	st, _ := rows[0]["status"].(map[string]any)
	code, _ := st["code"].(string)
	return strings.ToLower(strings.TrimSpace(code))
}

func activateAuthStateResp(ctx context.Context, sess *Session, tr *tracker, email, debugID, purpose string) (*Response, bool) {
	body := map[string]any{
		"extraPbaChecks": false, "pbaPolicy": nil,
		"username": email, "usernameType": "EMAIL", "accountType": "individual",
	}
	if purpose == "multiFactorAuthentication" {
		body["deviceInfo"] = map[string]any{"lsId": uuid.NewString(), "hdId": nil}
	}
	if purpose == "incompleteAccount" && tr != nil {
		tr.verify, tr.state = "", ""
	}
	resp, err := send(ctx, sess, tr, "POST", authHost+"/signin/v2/authenticationstate?purpose="+url.QueryEscape(purpose), body, susiClient, map[string]string{"x-debug-id": debugID})
	if err != nil || resp == nil {
		return resp, false
	}
	return resp, resp.Status == 200 || resp.Status == 201
}

func activateSendIncomplete(ctx context.Context, sess *Session, tr *tracker, debugID string) bool {
	_, _ = send(ctx, sess, tr, "GET", authHost+"/signin/v3/challenges?purpose=multiFactorAuthentication", nil, susiClient, map[string]string{"x-debug-id": debugID})
	_, _ = send(ctx, sess, tr, "GET", authHost+"/signin/v3/challenges?purpose=incompleteAccount", nil, susiClient, map[string]string{"x-debug-id": debugID})
	resp, err := send(ctx, sess, tr, "POST", authHost+"/signin/v3/challenges?purpose=incompleteAccount&factor=email&extendedAuthState=false", map[string]any{}, susiClient, map[string]string{"x-debug-id": debugID})
	return err == nil && resp != nil && resp.Status == 200
}

func activateTokenFromCode(ctx context.Context, sess *Session, tr *tracker, debugID, code string) string {
	resp, err := send(ctx, sess, tr, "POST", authHost+"/signin/v3/tokens?credential=code", map[string]any{
		"purpose": "incompleteAccount", "code": code,
	}, susiClient, map[string]string{"x-debug-id": debugID})
	if err != nil || resp == nil || resp.Status != 200 {
		return ""
	}
	return jsonToken(resp.Body)
}

func checkActivatePassword(ctx context.Context, sess *Session, tr *tracker, email, password, debugID string) (bool, string) {
	try := func(existing string) (*Response, error) {
		return send(ctx, sess, tr, "POST", authHost+"/signin/v1/passwords/validity?existingUser="+existing, map[string]string{
			"password": password,
		}, susiClient, map[string]string{"x-debug-id": debugID})
	}
	valid, err := try("true")
	if err != nil || valid == nil {
		return false, scrubErr(err)
	}
	if valid.Status == 401 {
		valid, err = try("false")
		if err != nil || valid == nil {
			return false, scrubErr(err)
		}
	}
	_, _ = send(ctx, sess, tr, "POST", authHost+"/signin/v1/passwords/leak_verification", map[string]string{
		"username": email, "usernameType": "EMAIL", "password": password,
	}, susiClient, map[string]string{"x-debug-id": debugID})
	if valid.Status != 200 {
		return false, fmt.Sprintf("状态=%d %s", valid.Status, orEmpty(adobeErr(valid.Body), adobeFieldDetail(valid.Body)))
	}
	var parsed map[string]any
	_ = json.Unmarshal(valid.Body, &parsed)
	if v, ok := parsed["valid"].(bool); ok && !v {
		return false, orEmpty(adobeErr(valid.Body), "valid=false")
	}
	if code := adobeErr(valid.Body); code != "" && (strings.Contains(strings.ToLower(code), "invalid") || strings.Contains(strings.ToLower(code), "password")) {
		return false, code
	}
	return true, ""
}

func solveActivateCaptcha(ctx context.Context, sess *Session, in Input, blob string) (string, error) {
	cap := captchaKey{Provider: in.Captcha.Provider, Key: in.Captcha.Key}
	devicePath := strings.TrimSpace(in.DevicePath)
	if devicePath == "" && in.Profile != nil {
		devicePath = in.Profile.File
	}
	if ua := deviceUA(devicePath); ua != "" {
		sess.ua = ua
	}
	note(in, "开始认图小游戏啦")
	tokens, err := solveCaptcha(ctx, sess, cap, devicePath, blob, in.Log)
	if err != nil {
		return "", err
	}
	if len(tokens) == 0 || tokens[0] == "" {
		return "", fmt.Errorf("没有打码令牌")
	}
	return tokens[0], nil
}

func clipPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "（无）"
	}
	base := p
	if i := strings.LastIndexAny(p, `\/`); i >= 0 && i+1 < len(p) {
		base = p[i+1:]
	}
	return base
}

func captureGenuine(ctx context.Context, in Input, sess *Session) string {
	_ = ctx
	if in.CaptureBFP != nil {
		res, err := in.CaptureBFP("bfp-"+sess.id, in.Proxy, sess.ua, in.Profile)
		if err == nil && res.OK && res.BFP != "" {
			return res.BFP
		}
	}
	return uuid.NewString()
}

func activateSubmitProfile(ctx context.Context, sess *Session, tr *tracker, in Input, email, password, country, locale, debugID, susi string) (bool, string, string) {
	meExtra := map[string]string{"x-debug-id": debugID}
	me, err := send(ctx, sess, tr, "GET", authHost+"/signin/v1/accounts/me?client_id="+url.QueryEscape(susiClient), nil, susiClient, meExtra)
	if (err != nil || me == nil || me.Status != 200) && strings.TrimSpace(susi) != "" {
		meExtra["authorization"] = "Bearer " + susi
		me, err = send(ctx, sess, tr, "GET", authHost+"/signin/v1/accounts/me?client_id="+url.QueryEscape(susiClient), nil, susiClient, meExtra)
	}
	if err != nil || me == nil || me.Status != 200 {
		why := scrubErr(err)
		if me != nil {
			why = fmt.Sprintf("状态=%d %s", me.Status, orEmpty(adobeErr(me.Body), adobeFieldDetail(me.Body)))
		}
		return false, password, "资料读取失败: " + why
	}
	var raw map[string]any
	_ = json.Unmarshal(me.Body, &raw)
	userID := strAny(raw["userId"])
	if userID == "" {
		return false, password, "资料读取失败"
	}
	first, last := "User", "Name"
	// Prefer the configured activate country. Incomplete-account /me often
	// already carries a low-credit region (e.g. SG → 10 pts/day).
	cc := strings.ToUpper(strings.TrimSpace(country))
	if len(cc) != 2 {
		cc = strings.ToUpper(strAny(raw["countryCode"]))
	}
	if len(cc) != 2 {
		cc = "US"
	}
	dob := activateDOB(raw["dateOfBirth"])

	_, _ = send(ctx, sess, tr, "POST", authHost+"/signin/v2/users/accounts", map[string]string{
		"username": email, "usernameType": "EMAIL",
	}, susiClient, map[string]string{"x-debug-id": debugID})
	stateResp, stateOK := activateAuthStateResp(ctx, sess, tr, email, debugID, "incompleteAccount")
	if !stateOK {
		note(in, "未完成状态还没挂上，先继续交资料试试")
	}
	if tr.verify == "" || tr.state == "" {
		note(in, fmt.Sprintf("资料小会话还不完整（校验令牌=%v 会话态=%v）", tr.verify != "", tr.state != ""))
	}

	effective := password
	if strings.TrimSpace(effective) == "" {
		effective = genActivatePassword()
	}
	okPW, whyPW := checkActivatePassword(ctx, sess, tr, email, effective, debugID)
	if !okPW {
		note(in, "密码检查没过："+whyPW)
		return false, effective, "密码检查没过：" + whyPW
	}
	note(in, "密码检查通过，乖乖的")

	genuine := captureGenuine(ctx, in, sess)
	arpTok := imsARPToken(debugID)

	blob := ""
	if stateResp != nil {
		blob = headerOne(stateResp.Header, "x-ims-captcha-encrypted")
	}
	if blob == "" {
		blob = headerOne(me.Header, "x-ims-captcha-encrypted")
	}
	if blob == "" {
		cap, _ := send(ctx, sess, tr, "GET", authHost+"/signin/v1/captcha/encryptedData", nil, susiClient, map[string]string{"x-debug-id": debugID})
		if cap != nil {
			blob = headerOne(cap.Header, "x-ims-captcha-encrypted")
			if blob == "" {
				var c map[string]any
				_ = json.Unmarshal(cap.Body, &c)
				blob, _ = c["captchaEncryptedData"].(string)
			}
		}
	}
	if strings.TrimSpace(blob) == "" {
		return false, effective, "没有拿到打码参数"
	}

	note(in, "先过认图小游戏，再交资料")
	arkose, errCap := solveActivateCaptcha(ctx, sess, in, blob)
	if errCap != nil || arkose == "" {
		msg := "认图还没过关"
		if errCap != nil {
			msg = "认图还没过关：" + scrubErr(errCap)
		}
		return false, effective, msg
	}
	note(in, "打码搞定")

	account := map[string]any{
		"email": email, "phoneNumber": nil, "firstName": first, "lastName": last,
		"password": effective, "countryCode": cc,
		"phoneticFirstName": nil, "phoneticLastName": nil,
		"termsOfUseAcceptances": []any{map[string]any{"accepted": true, "name": "ADOBE_MASTER", "language": locale}},
		"marketingConsent":      map[string]any{"text": activateMarketingHTML(), "accepted": true},
		"isPasswordless":        false, "type": "individual",
		"dateOfBirth": dob, "userId": userID,
	}
	if phone := strAny(raw["phoneNumber"]); phone != "" {
		account["phoneNumber"] = phone
	}
	body := map[string]any{"account": account, "regionalOptInKorea": nil, "regionalOptInChina": nil, "locale": locale}

	lastStatus, lastCode, lastDetail := 0, "", ""
	for attempt := 1; attempt <= 3; attempt++ {
		note(in, fmt.Sprintf("正在提交资料（第%d次）", attempt))
		savedState := tr.state
		tr.state = ""
		hdr := map[string]string{
			"x-debug-id":                 debugID,
			"x-ims-arp-token":            arpTok,
			"x-ims-genuine-token":        genuine,
			"x-ims-arkose-captcha-token": arkose,
			"Sec-Fetch-Site":             "same-origin",
			"Sec-Fetch-Mode":             "cors",
			"Sec-Fetch-Dest":             "empty",
		}
		if strings.TrimSpace(susi) != "" {
			hdr["authorization"] = "Bearer " + susi
		}
		resp, err := send(ctx, sess, tr, "PUT", authHost+"/signin/v4/accounts", body, susiClient, hdr)
		tr.state = savedState
		if err != nil || resp == nil {
			note(in, fmt.Sprintf("资料提交网络开小差了（第%d次）%s", attempt, scrubErr(err)))
			continue
		}
		lastStatus = resp.Status
		lastCode = adobeErr(resp.Body)
		lastDetail = adobeFieldDetail(resp.Body)
		bodyLow := strings.ToLower(string(resp.Body))
		htmlForbidden := resp.Status == 403 && (strings.Contains(bodyLow, "<!doctype") || strings.Contains(bodyLow, "<html"))
		if resp.Status == 200 || strings.Contains(bodyLow, "not an incomplete") {
			if strings.Contains(bodyLow, "not an incomplete") && resp.Status != 200 {
				note(in, "这个账号其实已经完整啦")
			}
			return true, effective, ""
		}
		note(in, fmt.Sprintf("资料提交还差一点点（第%d次，状态%d，%s）%s", attempt, resp.Status, orEmpty(lastCode, "无码"), lastDetail))
		if lastCode == "invalid_password" && attempt < 3 {
			// Keep the fixed password; retry submit only.
			account["password"] = effective
			body["account"] = account
			continue
		}
		if htmlForbidden {
			break
		}
		needsCap := lastCode == "captcha_required" || lastCode == "forbidden" || lastCode == "invalid_field" ||
			resp.Status == 403 || resp.Status == 429
		if !needsCap || attempt == 3 {
			break
		}
		note(in, "再玩一轮认图小游戏")
		if stateResp, ok := activateAuthStateResp(ctx, sess, tr, email, debugID, "incompleteAccount"); ok && stateResp != nil {
			if b := headerOne(stateResp.Header, "x-ims-captcha-encrypted"); b != "" {
				blob = b
			}
		}
		if b := headerOne(resp.Header, "x-ims-captcha-encrypted"); b != "" {
			blob = b
		}
		if strings.TrimSpace(blob) == "" {
			return false, effective, "打码参数没拿到"
		}
		genuine = captureGenuine(ctx, in, sess)
		arpTok = imsARPToken(debugID)
		arkose, errCap = solveActivateCaptcha(ctx, sess, in, blob)
		if errCap != nil || arkose == "" {
			return false, effective, "认图还没过关"
		}
	}
	reason := "资料提交没成功"
	if lastStatus != 0 {
		reason = fmt.Sprintf("资料提交没成功（状态%d，%s）%s", lastStatus, orEmpty(lastCode, "无码"), lastDetail)
	}
	return false, effective, strings.TrimSpace(reason)
}
