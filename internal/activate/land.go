package activate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

func jumpToken(ctx context.Context, sess *Session, tr *tracker, debugID, referer, clientID, susi string) string {
	if clientID == "" {
		clientID = susiClient
	}
	extra := map[string]string{"x-debug-id": debugID, "referer": referer}
	if susi != "" {
		extra["authorization"] = "Bearer " + susi
	}
	resp, err := send(ctx, sess, tr, "POST", authHost+"/signin/v1/ims/tokens", map[string]any{
		"rememberMe": true, "reauthenticate": nil,
	}, clientID, extra)
	if err != nil || resp == nil || resp.Status != 200 || jsonToken(resp.Body) == "" {
		resp, err = send(ctx, sess, tr, "POST", authHost+"/signin/v1/ims/tokens?clientId="+url.QueryEscape(clientID), map[string]any{}, clientID, extra)
	}
	if err != nil || resp == nil {
		return ""
	}
	return jsonToken(resp.Body)
}

func exchangeSignupSession(ctx context.Context, sess *Session, tr *tracker, debugID, referer, jump, susi string) error {
	if jump == "" {
		return fmt.Errorf("没有登录令牌")
	}
	state := `{"jslibver":"v2-v0.60.0-10-g3e7a9f3","nonce":"` + debugID + `"}`
	redir := "https://www.adobe.com/home#old_hash=&from_ims=true&client_id=" + susiClient + "&api=authorize&scope=" + homeScope
	callback := imsHost + "/ims/adobeid/" + susiClient + "/AdobeID/token?" + url.Values{
		"redirect_uri": {redir}, "state": {state},
		"code_challenge_method": {"plain"}, "use_ms_for_expiry": {"true"},
	}.Encode()
	form := url.Values{
		"remember_me": {"true"}, "dctx_id": {""}, "callback": {callback},
		"client_id": {susiClient}, "scope": {homeScope}, "state": {state},
		"relay": {debugID}, "locale": {"en_US"}, "flow_type": {"token"},
		"idp_flow_type": {"login"}, "ab_test": {"welcome-back"},
		"s_p":           {"google,facebook,apple,microsoft,line,kakao"},
		"response_type": {"token"}, "code_challenge_method": {"plain"},
		"redirect_uri": {redir}, "use_ms_for_expiry": {"true"},
		"flow": {"signUp"}, "puser": {""}, "token": {jump}, "probing_results": {"[0]"},
	}
	_ = postFormHost(ctx, sess, imsBackend+"/ims/fromSusi", form, susiClient)
	if sess.Cookie("ims_sid") != "" {
		return nil
	}
	_ = postFormHost(ctx, sess, imsHost+"/ims/fromSusi", form, susiClient)
	if sess.Cookie("ims_sid") != "" {
		return nil
	}
	fresh := jumpToken(ctx, sess, tr, debugID, referer, susiClient, susi)
	if fresh == "" {
		fresh = jumpToken(ctx, sess, tr, debugID, referer, susiClient, "")
	}
	if fresh == "" {
		fresh = jump
	}
	loginForm := url.Values{}
	for k, vs := range form {
		loginForm[k] = append([]string{}, vs...)
	}
	loginForm.Set("token", fresh)
	loginForm.Set("idp_flow_type", "login")
	loginForm.Set("flow", "signIn")
	loginForm.Set("deeplink", "ssofirst")
	loginForm.Del("dl")
	_ = postFormHost(ctx, sess, imsBackend+"/ims/fromSusi", loginForm, susiClient)
	if sess.Cookie("ims_sid") != "" {
		return nil
	}
	_ = postFormHost(ctx, sess, imsHost+"/ims/fromSusi", loginForm, susiClient)
	if sess.Cookie("ims_sid") != "" {
		return nil
	}
	for _, page := range []string{"https://www.adobe.com/home", fireflyHome, "https://new.express.adobe.com/"} {
		_, _ = send(ctx, sess, tr, "GET", page, nil, susiClient, map[string]string{
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "referer": referer,
		})
		if sess.Cookie("ims_sid") != "" {
			return nil
		}
	}
	return fmt.Errorf("没有拿到登录会话")
}

func landSession(ctx context.Context, sess *Session, tr *tracker, debugID, referer, susi string, log func(string)) error {
	extra := map[string]string{"x-debug-id": debugID, "referer": referer}
	hdr := withBearer(extra, susi)
	me, _ := send(ctx, sess, tr, "GET", authHost+"/signin/v1/accounts/me?client_id="+url.QueryEscape(susiClient), nil, susiClient, hdr)
	// Guest/promo credit accounts expose a linked entitlement identity on /me.
	// Pinning only isSessionForwardProfile(personal guid) leaves the free 10-pt
	// AdobeID selected — switch to the entitlement link when Adobe offers one.
	if switched, tok := selectEntitlementProfile(ctx, sess, tr, me, susi, extra, log); switched && tok != "" {
		susi = tok
		hdr = withBearer(extra, susi)
		me, _ = send(ctx, sess, tr, "GET", authHost+"/signin/v1/accounts/me?client_id="+url.QueryEscape(susiClient), nil, susiClient, hdr)
	} else if guid := accountGUID(me); guid != "" {
		_ = activateProfileFilter(ctx, sess, tr, guid, hdr, log)
	}
	jump := jumpToken(ctx, sess, tr, debugID, referer, susiClient, susi)
	if jump == "" {
		jump = jumpToken(ctx, sess, tr, debugID, referer, susiClient, "")
	}
	if jump == "" {
		jump = susi
	}
	return exchangeSignupSession(ctx, sess, tr, debugID, referer, jump, susi)
}

// passwordLogin posts credential=password and returns a susi token (may be empty
// when Adobe demands an email challenge instead).
func passwordLogin(ctx context.Context, sess *Session, tr *tracker, email, password, debugID, referer string) (*Response, string, error) {
	extra := map[string]string{"x-debug-id": debugID, "referer": referer}
	pwResp, err := send(ctx, sess, tr, "POST", authHost+"/signin/v2/tokens?credential=password", map[string]any{
		"username": email, "usernameType": "EMAIL", "password": password,
		"accountType": "individual", "rememberMe": true,
	}, susiClient, extra)
	if err != nil {
		return nil, "", err
	}
	return pwResp, jsonToken(pwResp.Body), nil
}

func withBearer(extra map[string]string, susi string) map[string]string {
	out := map[string]string{}
	for k, v := range extra {
		out[k] = v
	}
	if strings.TrimSpace(susi) != "" {
		out["authorization"] = "Bearer " + susi
	}
	return out
}

type profileLink struct {
	Ident                    string
	ID                       string
	Status                   string
	EntitlementAccountUserID string
}

func parseProfileLinks(me *Response) []profileLink {
	if me == nil || len(me.Body) == 0 {
		return nil
	}
	var raw map[string]any
	if json.Unmarshal(me.Body, &raw) != nil {
		return nil
	}
	pd, _ := raw["profileData"].(map[string]any)
	if pd == nil {
		return nil
	}
	rows, _ := pd["links"].([]any)
	out := make([]profileLink, 0, len(rows))
	for _, row := range rows {
		m, _ := row.(map[string]any)
		if m == nil {
			continue
		}
		ident := strAny(m["ident"])
		id := strAny(m["id"])
		if ident == "" && id == "" {
			continue
		}
		out = append(out, profileLink{
			Ident:                    ident,
			ID:                       id,
			Status:                   strings.ToLower(strAny(m["status"])),
			EntitlementAccountUserID: strAny(m["entitlementAccountUserId"]),
		})
	}
	return out
}

func chooseEntitlementLink(links []profileLink) (profileLink, bool) {
	if len(links) == 0 {
		return profileLink{}, false
	}
	var entitled []profileLink
	for _, l := range links {
		if l.EntitlementAccountUserID != "" {
			entitled = append(entitled, l)
		}
	}
	pool := entitled
	if len(pool) == 0 {
		if len(links) < 2 {
			return profileLink{}, false
		}
		pool = links
	}
	for _, l := range pool {
		if l.Status == "active" {
			return l, true
		}
	}
	return pool[0], true
}

func activateProfileFilter(ctx context.Context, sess *Session, tr *tracker, guid string, extra map[string]string, log func(string)) bool {
	if strings.TrimSpace(guid) == "" {
		return false
	}
	bodies := []map[string]any{
		{"guid": guid, "filter": map[string]any{"preferForwardProfile": true}},
		{"guid": guid, "filter": "isSessionForwardProfile()"},
		{"guid": guid},
	}
	labels := []string{"preferForward", "sessionForward", "guid"}
	for i, body := range bodies {
		resp, err := send(ctx, sess, tr, "PUT", authHost+"/signin/v1/filterprofilemapping", body, susiClient, extra)
		if err != nil || resp == nil {
			continue
		}
		if log != nil {
			nice := map[string]string{"preferForward": "偏好转发", "sessionForward": "会话转发", "guid": "按编号"}[labels[i]]
			if nice == "" {
				nice = labels[i]
			}
			if resp.Status >= 200 && resp.Status < 300 {
				log(fmt.Sprintf("身份过滤「%s」成功啦", nice))
			} else {
				log(fmt.Sprintf("身份过滤「%s」没成，换下一种试试", nice))
			}
		}
		if resp.Status >= 200 && resp.Status < 300 {
			return true
		}
	}
	return false
}

// claimInviteLink mirrors HAR POST /signin/v2/links/{linkId} {"status":"active"}
// which turns an invited entitlement identity into active before filter/tokens.
func claimInviteLink(ctx context.Context, sess *Session, tr *tracker, linkID, susi string, extra map[string]string, log func(string)) (string, bool) {
	linkID = strings.TrimSpace(linkID)
	if linkID == "" {
		return susi, false
	}
	resp, err := send(ctx, sess, tr, "POST", authHost+"/signin/v2/links/"+url.PathEscape(linkID), map[string]any{
		"status": "active",
	}, susiClient, withBearer(extra, susi))
	if err != nil || resp == nil || resp.Status >= 300 {
		status := 0
		detail := ""
		if resp != nil {
			status = resp.Status
			detail = adobeErr(resp.Body)
		}
		if log != nil {
			log(fmt.Sprintf("领取权益身份没成（%d）%s", status, detail))
		}
		return susi, false
	}
	tok := jsonToken(resp.Body)
	if tok != "" {
		susi = tok
	}
	_, _ = send(ctx, sess, tr, "GET", authHost+"/signin/v1/policies/check?linkId="+url.QueryEscape(linkID), nil, susiClient, withBearer(extra, susi))
	if log != nil {
		log("权益身份领取成功，变成可用啦")
	}
	return susi, true
}

func selectEntitlementProfile(ctx context.Context, sess *Session, tr *tracker, me *Response, susi string, extra map[string]string, log func(string)) (bool, string) {
	links := parseProfileLinks(me)
	chosen, ok := chooseEntitlementLink(links)
	if !ok {
		if log != nil {
			log(fmt.Sprintf("看了看，有 %d 个身份，但没有可领的权益身份", len(links)))
		}
		return false, susi
	}
	if log != nil {
		st := orEmpty(chosen.Status, "未知")
		stNice := map[string]string{"invited": "邀请中", "active": "已可用"}[st]
		if stNice == "" {
			stNice = st
		}
		if chosen.EntitlementAccountUserID != "" {
			log(fmt.Sprintf("发现 %d 个身份，里面有权益身份（%s）", len(links), stNice))
		} else {
			log(fmt.Sprintf("发现 %d 个身份（%s）", len(links), stNice))
		}
	}
	linkID := chosen.Ident
	if linkID == "" {
		linkID = chosen.ID
	}
	if linkID == "" {
		return false, susi
	}
	guid := chosen.EntitlementAccountUserID
	if guid == "" {
		guid = accountGUID(me)
	}

	// HAR: invited links must be claimed via POST /v2/links/{id} before filtermapping.
	if chosen.Status != "active" {
		var claimed bool
		susi, claimed = claimInviteLink(ctx, sess, tr, linkID, susi, extra, log)
		if !claimed {
			return false, susi
		}
		me2, _ := send(ctx, sess, tr, "GET", authHost+"/signin/v1/accounts/me?client_id="+url.QueryEscape(susiClient), nil, susiClient, withBearer(extra, susi))
		links = parseProfileLinks(me2)
		if next, ok2 := chooseEntitlementLink(links); ok2 {
			chosen = next
			if chosen.Ident != "" {
				linkID = chosen.Ident
			} else if chosen.ID != "" {
				linkID = chosen.ID
			}
			if chosen.EntitlementAccountUserID != "" {
				guid = chosen.EntitlementAccountUserID
			}
		}
		if chosen.Status != "" && chosen.Status != "active" {
			if log != nil {
				log("权益身份还没亮起来，状态是 " + chosen.Status)
			}
			return false, susi
		}
	}

	if guid != "" {
		_ = activateProfileFilter(ctx, sess, tr, guid, withBearer(extra, susi), log)
	}
	// HAR also hits filtered_profiles before tokens; best-effort, ignore failures.
	_, _ = send(ctx, sess, tr, "GET", authHost+"/signin/v2/accounts/filtered_profiles?filter="+url.QueryEscape("isSessionForwardProfile()"), nil, susiClient, withBearer(extra, susi))

	tokResp, err := send(ctx, sess, tr, "POST", authHost+"/signin/v1/accounts/tokens", map[string]string{
		"linkId": linkID,
	}, susiClient, withBearer(extra, susi))
	if err != nil || tokResp == nil || tokResp.Status >= 300 {
		status := 0
		if tokResp != nil {
			status = tokResp.Status
		}
		detail := ""
		if tokResp != nil {
			detail = adobeErr(tokResp.Body)
		}
		if log != nil {
			log(fmt.Sprintf("切换身份没成（%d）%s", status, detail))
		}
		return false, susi
	}
	tok := jsonToken(tokResp.Body)
	if tok == "" {
		if log != nil {
			log("切换身份时没拿到小令牌")
		}
		return false, susi
	}
	if log != nil {
		log("已经切到权益身份啦")
	}
	return true, tok
}

func probeEVS(ctx context.Context, sess *Session) (blocked bool, detail string) {
	form := url.Values{"client_id": {fireflyID}, "scope": {fireflyScope}}
	resp, err := send(ctx, sess, &tracker{}, "POST", imsBackend+"/ims/check/v6/token?jslVersion=v2-v0.60.0-10-g3e7a9f3", form.Encode(), fireflyID, map[string]string{
		"content-type": "application/x-www-form-urlencoded",
		"accept":       "application/json",
		"origin":       fireflyHome,
		"referer":      fireflyHome,
	})
	if err != nil || resp == nil {
		return false, ""
	}
	low := strings.ToLower(string(resp.Body) + " " + adobeErr(resp.Body))
	if strings.Contains(low, "ride_adobeid_acct_evs") || strings.Contains(low, "acct_evs") {
		msg := adobeErr(resp.Body)
		if msg == "" {
			msg = fmt.Sprintf("状态码 %d", resp.Status)
		}
		return true, msg
	}
	if resp.Status >= 400 && strings.Contains(low, "evs") {
		return true, adobeErr(resp.Body)
	}
	return false, ""
}

func triggerCode(ctx context.Context, sess *Session, tr *tracker, secret, email, debugID, referer, purpose, clientID string, used map[string]struct{}, log func(string)) (string, error) {
	if used == nil {
		used = map[string]struct{}{}
	}
	if clientID == "" {
		clientID = fireflyID
	}
	for code := range peekCodes(ctx, secret, email) {
		used[code] = struct{}{}
	}
	extra := map[string]string{"x-debug-id": debugID, "referer": referer}
	_, _ = send(ctx, sess, tr, "GET", authHost+"/signin/v3/challenges?purpose="+purpose, nil, clientID, extra)
	since := time.Now().Add(-5 * time.Second)
	resp, err := send(ctx, sess, tr, "POST", authHost+"/signin/v3/challenges?purpose="+purpose+"&factor=email&extendedAuthState=false", map[string]any{}, clientID, extra)
	if err != nil {
		return "", err
	}
	if resp.Status != 200 && resp.Status != 201 && resp.Status != 204 {
		return "", fmt.Errorf("没有发出邮箱验证码 %s 状态=%d %s", purposeLabel(purpose), resp.Status, adobeErr(resp.Body))
	}
	if log != nil {
		log("验证码已呼叫，等信箱响一声")
	}
	return waitCode(ctx, secret, email, since, used, log)
}

func verifyCode(ctx context.Context, sess *Session, tr *tracker, debugID, referer, clientID, code string) (string, error) {
	if clientID == "" {
		clientID = fireflyID
	}
	extra := map[string]string{"x-debug-id": debugID, "referer": referer}
	put, err := send(ctx, sess, tr, "PUT", authHost+"/signin/v3/challenges?purpose=multiFactorAuthentication", map[string]string{"code": code}, clientID, extra)
	if err != nil {
		return "", err
	}
	if put.Status == 200 {
		return jsonToken(put.Body), nil
	}
	posted, err := send(ctx, sess, tr, "POST", authHost+"/signin/v3/tokens?credential=code", map[string]string{
		"purpose": "multiFactorAuthentication", "code": code,
	}, clientID, extra)
	if err != nil {
		return "", err
	}
	if posted.Status != 200 {
		return "", fmt.Errorf("邮箱验证码没有通过二次验证 状态=%d %s", posted.Status, adobeErr(posted.Body))
	}
	return jsonToken(posted.Body), nil
}

func exchangeCode(ctx context.Context, sess *Session, tr *tracker, debugID, referer, purpose, clientID, code string) (string, error) {
	if clientID == "" {
		clientID = fireflyID
	}
	extra := map[string]string{"x-debug-id": debugID, "referer": referer}
	if purpose == "incompleteAccount" {
		posted, err := send(ctx, sess, tr, "POST", authHost+"/signin/v3/tokens?credential=code", map[string]string{
			"purpose": purpose, "code": code,
		}, clientID, extra)
		if err != nil {
			return "", err
		}
		if posted.Status != 200 {
			return "", fmt.Errorf("邮箱验证码没有通过%s 状态=%d %s", purposeLabel(purpose), posted.Status, adobeErr(posted.Body))
		}
		tok := jsonToken(posted.Body)
		if tok == "" {
			return "", fmt.Errorf("邮箱验证码没有通过%s 无令牌", purposeLabel(purpose))
		}
		return tok, nil
	}
	put, err := send(ctx, sess, tr, "PUT", authHost+"/signin/v3/challenges?purpose="+purpose, map[string]string{"code": code}, clientID, extra)
	if err != nil {
		return "", err
	}
	if tok := jsonToken(put.Body); put.Status == 200 && tok != "" {
		return tok, nil
	}
	if put.Status == 200 {
		return "", nil
	}
	posted, err := send(ctx, sess, tr, "POST", authHost+"/signin/v3/tokens?credential=code", map[string]string{
		"purpose": purpose, "code": code,
	}, clientID, extra)
	if err != nil {
		return "", err
	}
	if posted.Status != 200 {
		return "", fmt.Errorf("邮箱验证码没有通过%s 状态=%d %s", purposeLabel(purpose), posted.Status, adobeErr(posted.Body))
	}
	return jsonToken(posted.Body), nil
}

func clearEVS(ctx context.Context, sess *Session, tr *tracker, secret, email, debugID, referer, purpose, clientID string, warmFirefly bool, used map[string]struct{}, log func(string)) (string, bool, error) {
	if used == nil {
		used = map[string]struct{}{}
	}
	if purpose == "" {
		purpose = "multiFactorAuthentication"
	}
	if clientID == "" {
		clientID = fireflyID
	}
	codeRef := referer
	if warmFirefly || clientID == fireflyID {
		codeRef = loginReferer(email, debugID)
		_, _ = send(ctx, sess, tr, "GET", fireflyHome, nil, fireflyID, map[string]string{
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		})
		authURL := imsHost + "/ims/authorize/v1?" + url.Values{
			"client_id": {fireflyID}, "scope": {fireflyScope}, "response_type": {"token"},
			"redirect_uri": {fireflyHome}, "puser": {email}, "locale": {"en_US"},
			"flow_type": {"token"}, "idp_flow_type": {"login"},
		}.Encode()
		_, _ = send(ctx, sess, tr, "GET", authURL, nil, fireflyID, map[string]string{"referer": fireflyHome})
		_, _ = send(ctx, sess, tr, "GET", authHost+"/signin/v2/configurations/"+fireflyID, nil, fireflyID, map[string]string{
			"x-debug-id": debugID, "referer": codeRef,
		})
		clientID = fireflyID
	}
	extra := map[string]string{"x-debug-id": debugID, "referer": codeRef}
	_, _ = send(ctx, sess, tr, "POST", authHost+"/signin/v2/authenticationstate?purpose="+purpose, map[string]any{
		"extraPbaChecks": false, "pbaPolicy": nil,
		"username": email, "usernameType": "EMAIL", "accountType": "individual",
		"deviceInfo": map[string]any{"lsId": uuid.NewString(), "hdId": nil},
	}, clientID, extra)
	code, err := triggerCode(ctx, sess, tr, secret, email, debugID, codeRef, purpose, clientID, used, log)
	if err != nil {
		return "", false, err
	}
	for try := 0; try < 2; try++ {
		used[code] = struct{}{}
		if log != nil {
			log("验证码到了，正在开门禁")
		}
		var tok string
		var verr error
		if purpose == "multiFactorAuthentication" {
			tok, verr = verifyCode(ctx, sess, tr, debugID, codeRef, clientID, code)
		} else {
			tok, verr = exchangeCode(ctx, sess, tr, debugID, codeRef, purpose, clientID, code)
		}
		if verr == nil {
			return tok, true, nil
		}
		if log != nil {
			log("开门禁没过：" + verr.Error())
		}
		if try == 0 && strings.Contains(verr.Error(), "invalid_code") {
			if next, err2 := waitCode(ctx, secret, email, time.Now().Add(-5*time.Second), used, log); err2 == nil {
				code = next
				continue
			}
		}
		return "", false, verr
	}
	return "", false, fmt.Errorf("邮箱验证门禁未解除")
}

func resolvePasswordChallenge(ctx context.Context, sess *Session, tr *tracker, email, secret, debugID, referer, password string, pwResp *Response, used map[string]struct{}, log func(string)) (string, error) {
	susi := ""
	if pwResp != nil {
		susi = jsonToken(pwResp.Body)
	}
	if susi != "" {
		if log != nil {
			log("密码敲门成功")
		}
		return susi, nil
	}
	if log != nil {
		log("密码登录要再收一封验证码")
	}
	purpose := ""
	if pwResp != nil {
		purpose = challengePurpose(pwResp.Body)
	}
	if purpose == "" {
		purpose = "multiFactorAuthentication"
	}
	client := susiClient
	warm := false
	if purpose == "multiFactorAuthentication" {
		client = fireflyID
		warm = true
	}
	tok, cleared, cerr := clearEVS(ctx, sess, tr, secret, email, debugID, referer, purpose, client, warm, used, log)
	if cerr != nil {
		return "", cerr
	}
	if tok != "" {
		return tok, nil
	}
	if !cleared {
		status := 0
		detail := ""
		if pwResp != nil {
			status = pwResp.Status
			detail = adobeErr(pwResp.Body)
		}
		return "", fmt.Errorf("密码登录没拿到令牌 状态=%d %s", status, detail)
	}
	return "", nil
}

func loginLine(ctx context.Context, sess *Session, tr *tracker, email, secret, debugID, password string, log func(string)) (string, error) {
	if tr == nil {
		tr = &tracker{}
	}
	referer := authHost + "/en_US/index.html?client_id=" + susiClient
	if debugID == "" {
		debugID = uuid.NewString()
	}
	if strings.TrimSpace(password) == "" {
		password = genActivatePassword()
	}
	used := map[string]struct{}{}

	if log != nil {
		log("用密码重新敲门…")
	}
	pwResp, susi, err := passwordLogin(ctx, sess, tr, email, password, debugID, referer)
	if err != nil {
		return "", err
	}
	if susi == "" {
		susi, err = resolvePasswordChallenge(ctx, sess, tr, email, secret, debugID, referer, password, pwResp, used, log)
		if err != nil {
			return "", err
		}
	} else if log != nil {
		log("密码敲门成功")
	}

	if log != nil {
		log("把「未完成」小尾巴清掉")
	}
	if tok, cleared, cerr := clearEVS(ctx, sess, tr, secret, email, debugID, referer, "incompleteAccount", susiClient, false, used, log); cerr != nil {
		if log != nil {
			log("未完成状态没清干净：" + cerr.Error())
		}
		if susi == "" {
			return "", fmt.Errorf("没有登录令牌: %s", cerr.Error())
		}
	} else if cleared {
		if log != nil {
			log("未完成状态清干净啦")
		}
		if tok != "" {
			susi = tok
		}
	}
	if susi == "" {
		return "", fmt.Errorf("没有登录令牌")
	}

	// User/HAR: entitlement invite is claimed on a fresh re-login after the
	// account is complete — not only on the first post-submit session.
	if log != nil {
		log("再登一次，去激活权益身份")
	}
	pw2, susi2, err := passwordLogin(ctx, sess, tr, email, password, debugID, referer)
	if err != nil {
		return "", err
	}
	if susi2 == "" {
		susi2, err = resolvePasswordChallenge(ctx, sess, tr, email, secret, debugID, referer, password, pw2, used, log)
		if err != nil {
			if log != nil {
				log("二次登录差点意思，先沿用上次会话：" + err.Error())
			}
		} else if susi2 != "" {
			susi = susi2
		}
	} else {
		susi = susi2
		if log != nil {
			log("二次登录顺利")
		}
	}

	if log != nil {
		log("挑选身份并落地中")
	}
	if err := landSession(ctx, sess, tr, debugID, referer, susi, log); err != nil {
		return "", err
	}
	if blocked, detail := probeEVS(ctx, sess); blocked {
		if log != nil {
			log("还卡着邮箱门禁，Firefly 再解一道：" + detail)
		}
		tok, cleared, cerr := clearEVS(ctx, sess, tr, secret, email, debugID, referer, "multiFactorAuthentication", fireflyID, true, used, log)
		if cerr != nil {
			return "", fmt.Errorf("邮箱门禁还没开：%s", cerr.Error())
		}
		if !cleared && tok == "" {
			return "", fmt.Errorf("邮箱门禁还没开：%s", detail)
		}
		if log != nil {
			log("邮箱门禁打开啦")
		}
		if tok != "" {
			susi = tok
			if log != nil {
				log("再落一次地")
			}
			if err := landSession(ctx, sess, tr, debugID, referer, susi, log); err != nil {
				return "", err
			}
		}
		if blocked, detail = probeEVS(ctx, sess); blocked {
			return "", fmt.Errorf("邮箱门禁还没开：%s", detail)
		}
		if log != nil {
			log("邮箱门禁复查也通过啦")
		}
	} else if log != nil {
		log("邮箱门禁检查通过")
	}

	relay := sess.Cookie("relay")
	ims := sess.Cookie("ims_sid")
	aux := sess.Cookie("aux_sid")
	if ims == "" {
		return "", fmt.Errorf("没有拿到登录会话")
	}
	if relay == "" {
		relay = ims
		if len(relay) > 48 {
			relay = relay[:48]
		}
	}
	return email + "----relay=" + relay + "; ftrset=560; locale=en_US; ims_sid=" + ims + "; aux_sid=" + aux, nil
}
