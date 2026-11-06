package activate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"firefly-go/internal/mail"

	"github.com/google/uuid"
)

// RunPlain registers a brand-new Adobe account (普号) via POST /signin/v2/accounts,
// then re-logins to claim entitlement identity and returns a pool cookie line.
// Differs from Run (incomplete-account): no OTP before create; captcha gates the
// first create attempt.
func RunPlain(ctx context.Context, in Input) (Result, error) {
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
	password := genActivatePassword()
	locale := "en_US"
	debugID := uuid.NewString()
	tr := tracker{}
	referer := authHost + "/en_US/index.html?client_id=" + susiClient
	note(in, "普号建号开工啦，国家 "+country)

	_, _ = send(ctx, sess, &tr, "GET", "https://www.adobe.com/home", nil, susiClient, map[string]string{
		"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	})
	_, _ = send(ctx, sess, &tr, "GET", authHost+"/signin/v2/configurations/"+susiClient, nil, susiClient, map[string]string{
		"x-debug-id": debugID, "referer": referer,
	})
	lookup, _ := send(ctx, sess, &tr, "POST", authHost+"/signin/v2/users/accounts", map[string]string{
		"username": email, "usernameType": "EMAIL",
	}, susiClient, map[string]string{"x-debug-id": debugID, "referer": referer})
	if lookup != nil {
		if exists, st := plainAccountExists(lookup.Body); exists {
			note(in, "这个邮箱已经有号了（"+orEmpty(st, "已存在")+"），直接去登录")
			tr.verify, tr.state = "", ""
			line, landErr := loginLine(ctx, sess, &tr, email, in.Secret, debugID, password, in.Log)
			return finishPlain(in, true, password, line, cookiePoolLine(ctx, email, sess), landErr)
		}
	}
	if at := strings.LastIndex(email, "@"); at > 0 {
		dom := email[at+1:]
		_, _ = send(ctx, sess, &tr, "GET", authHost+"/signin/v3/domains/"+dom+"/info", nil, susiClient, map[string]string{
			"x-debug-id": debugID, "referer": referer,
		})
	}
	okPW, whyPW := checkActivatePassword(ctx, sess, &tr, email, password, debugID)
	if !okPW {
		note(in, "密码检查没过："+whyPW)
		return Result{Touched: true, Message: "密码检查没过：" + whyPW, Password: password}, fmt.Errorf("密码检查没过：%s", whyPW)
	}
	note(in, "密码检查通过，乖乖的")

	dob := activateDOB(nil)
	// Match working XiaoAd adobe_register.py payload (普号 create ≠ 子号 PUT v4).
	body := map[string]any{
		"account": map[string]any{
			"email": email, "firstName": "Alex", "lastName": "Tan",
			"password": password, "countryCode": country,
			"termsOfUseAcceptances": []any{map[string]any{"accepted": true, "name": "ADOBE_MASTER", "language": locale}},
			"marketingConsent":      map[string]any{"text": activateMarketingHTML(), "accepted": false},
			"dateOfBirth":           dob,
		},
		"clientRedirect": nil, "redirectUri": "https://www.adobe.com/home",
		"regionalOptInKorea": nil, "regionalOptInChina": nil,
		"locale": locale, "idpFlow": "login", "inviteCode": nil,
	}

	touched := true
	var first *Response
	var err error
	var blob, code0 string
	for knock := 1; knock <= 3; knock++ {
		if knock == 1 {
			note(in, "先敲一下建号门，等打码参数")
		} else {
			note(in, fmt.Sprintf("打码参数没拿到，再敲一次（第%d次）", knock))
			select {
			case <-ctx.Done():
				return Result{Touched: touched, Message: "已停止", Password: password}, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
		first, err = send(ctx, sess, &tr, "POST", authHost+"/signin/v2/accounts", body, susiClient, map[string]string{
			"x-debug-id": debugID, "referer": referer,
		})
		if err != nil || first == nil {
			if knock == 3 {
				return Result{Touched: touched, Message: "建号敲门失败：" + scrubErr(err), Password: password}, fmt.Errorf("建号敲门失败：%s", scrubErr(err))
			}
			continue
		}
		blob = headerOne(first.Header, "x-ims-captcha-encrypted")
		code0 = adobeErr(first.Body)
		if blob != "" || first.Status == 200 || first.Status == 201 {
			break
		}
		detail := plainFailDetail(first)
		note(in, fmt.Sprintf("没拿到打码参数（%d）%s", first.Status, detail))
		if knock == 3 {
			return Result{Touched: touched, Message: fmt.Sprintf("没拿到打码参数（%d）%s", first.Status, detail), Password: password},
				fmt.Errorf("没拿到打码参数（%d）%s", first.Status, detail)
		}
	}
	if blob == "" && first != nil && (first.Status == 200 || first.Status == 201) {
		note(in, "居然免码建好了，接着拿登录凭证")
	}

	if blob != "" || strings.EqualFold(code0, "captcha_required") {
		if blob == "" {
			return Result{Touched: touched, Message: "要打码但没拿到参数", Password: password}, fmt.Errorf("要打码但没拿到参数")
		}
		note(in, "先过认图小游戏，再真正建号")
		arkose, errCap := solveActivateCaptcha(ctx, sess, in, blob)
		if errCap != nil || arkose == "" {
			msg := "认图还没过关"
			if errCap != nil {
				msg = "认图还没过关：" + scrubErr(errCap)
			}
			return Result{Touched: touched, Message: msg, Password: password}, fmt.Errorf("%s", msg)
		}
		note(in, "打码搞定，提交建号")
		// 普号 create 用 entcaptcha；子号 incomplete PUT 才用 arkose-captcha-token。
		hdr := map[string]string{
			"x-debug-id":                debugID,
			"referer":                   referer,
			"x-ims-entcaptcha-response": arkose,
		}
		if t := headerOne(first.Header, "x-ims-authentication-state-encrypted"); t != "" {
			hdr["x-ims-authentication-state-encrypted"] = t
		}
		var lastStatus int
		var lastDetail string
		ok := false
		for attempt := 1; attempt <= 3; attempt++ {
			note(in, fmt.Sprintf("正在建号（第%d次）", attempt))
			resp, err2 := send(ctx, sess, &tr, "POST", authHost+"/signin/v2/accounts", body, susiClient, hdr)
			if err2 != nil || resp == nil {
				lastDetail = scrubErr(err2)
				note(in, fmt.Sprintf("建号网络开小差了（第%d次）%s", attempt, lastDetail))
				continue
			}
			lastStatus = resp.Status
			lastDetail = orEmpty(adobeErr(resp.Body), adobeFieldDetail(resp.Body))
			low := strings.ToLower(string(resp.Body))
			if resp.Status == 200 || resp.Status == 201 || strings.Contains(low, "userid") || strings.Contains(low, `"email"`) {
				ok = true
				note(in, "普号建好啦")
				break
			}
			note(in, fmt.Sprintf("建号还差一点点（第%d次，状态%d）%s", attempt, resp.Status, lastDetail))
			if b := headerOne(resp.Header, "x-ims-captcha-encrypted"); b != "" {
				blob = b
				arkose, errCap = solveActivateCaptcha(ctx, sess, in, blob)
				if errCap != nil || arkose == "" {
					break
				}
				hdr["x-ims-entcaptcha-response"] = arkose
			}
		}
		if !ok {
			msg := "建号没成功"
			if lastStatus != 0 {
				msg = fmt.Sprintf("建号没成功（状态%d）%s", lastStatus, lastDetail)
			}
			return Result{Touched: touched, Message: msg, Password: password}, fmt.Errorf("%s", msg)
		}
	}

	tr.verify, tr.state = "", ""
	note(in, "资料交好了，接着去拿登录凭证")
	line, landErr := loginLine(ctx, sess, &tr, email, in.Secret, debugID, password, in.Log)
	return finishPlain(in, touched, password, line, cookiePoolLine(ctx, email, sess), landErr)
}

func finishPlain(in Input, touched bool, password, line, fallback string, landErr error) (Result, error) {
	if landErr != nil {
		if strings.Contains(fallback, "ims_sid=") {
			note(in, "登录凭证其实已经有啦，落地时嘀咕了句："+landErr.Error())
			return Result{OK: true, Touched: touched, Message: "补号成功啦", Password: password, Line: fallback}, nil
		}
		return Result{OK: true, Touched: touched, Message: "建号好了，可登录凭证还没拿到: " + landErr.Error(), Password: password},
			fmt.Errorf("建号好了，可登录凭证还没拿到: %s", landErr.Error())
	}
	if !strings.Contains(line, "ims_sid=") {
		note(in, "登录凭证还没落地哦")
		return Result{OK: true, Touched: touched, Message: "建号好了，可登录凭证还没拿到", Password: password},
			fmt.Errorf("建号好了，可登录凭证还没拿到")
	}
	note(in, "登录凭证到手，可以进号池啦")
	return Result{OK: true, Touched: touched, Message: "补号成功啦", Password: password, Line: line}, nil
}

func plainFailDetail(resp *Response) string {
	if resp == nil {
		return ""
	}
	detail := orEmpty(adobeErr(resp.Body), adobeFieldDetail(resp.Body))
	extra := strings.TrimSpace(adobeFieldDetail(resp.Body))
	if extra != "" && !strings.Contains(detail, extra) {
		detail = strings.TrimSpace(detail + " " + extra)
	}
	raw := strings.TrimSpace(string(resp.Body))
	if raw != "" && !strings.Contains(detail, raw) && len(raw) < 180 && !strings.Contains(raw, "token") {
		if detail == "" {
			detail = raw
		}
	}
	if len(detail) > 180 {
		detail = detail[:180]
	}
	return detail
}

func plainAccountExists(body []byte) (bool, string) {
	var arr []map[string]any
	if json.Unmarshal(body, &arr) == nil {
		if len(arr) == 0 {
			return false, ""
		}
		return true, plainStatus(arr[0])
	}
	var one map[string]any
	if json.Unmarshal(body, &one) == nil {
		if _, ok := one["status"]; ok {
			return true, plainStatus(one)
		}
	}
	return false, ""
}

func plainStatus(m map[string]any) string {
	status, _ := m["status"].(map[string]any)
	if status == nil {
		return ""
	}
	code, _ := status["code"].(string)
	return code
}
