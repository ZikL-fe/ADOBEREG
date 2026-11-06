package activate

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func jsonToken(body []byte) string {
	var parsed map[string]any
	if json.Unmarshal(body, &parsed) != nil {
		return ""
	}
	tok, _ := parsed["token"].(string)
	return tok
}

func tokenIn(text string) string {
	m := accessRE.FindStringSubmatch(text)
	if len(m) != 2 {
		return ""
	}
	val, err := url.QueryUnescape(m[1])
	if err != nil {
		return m[1]
	}
	return val
}

func adobeErr(body []byte) string {
	var parsed map[string]any
	if json.Unmarshal(body, &parsed) != nil {
		return ""
	}
	for _, key := range []string{"errorCode", "error", "message", "title"} {
		if s, _ := parsed[key].(string); strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func adobeFieldDetail(body []byte) string {
	var parsed map[string]any
	if json.Unmarshal(body, &parsed) != nil {
		return ""
	}
	var parts []string
	if msg, _ := parsed["message"].(string); strings.TrimSpace(msg) != "" && !strings.EqualFold(msg, adobeErr(body)) {
		parts = append(parts, msg)
	}
	for _, key := range []string{"invalidFields", "invalid_fields", "fields", "details"} {
		raw, ok := parsed[key]
		if !ok || raw == nil {
			continue
		}
		switch v := raw.(type) {
		case []any:
			for _, item := range v {
				switch it := item.(type) {
				case string:
					parts = append(parts, it)
				case map[string]any:
					name := strAny(it["name"])
					if name == "" {
						name = strAny(it["field"])
					}
					reason := strAny(it["message"])
					if reason == "" {
						reason = strAny(it["errorCode"])
					}
					if name != "" && reason != "" {
						parts = append(parts, name+"="+reason)
					} else if name != "" {
						parts = append(parts, name)
					}
				}
			}
		case string:
			if strings.TrimSpace(v) != "" {
				parts = append(parts, v)
			}
		}
	}
	out := strings.Join(parts, "; ")
	if len(out) > 180 {
		out = out[:180]
	}
	return out
}

func strAny(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return ""
	}
}

func orEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func accountGUID(resp *Response) string {
	if resp == nil || len(resp.Body) == 0 {
		return ""
	}
	var raw map[string]any
	if json.Unmarshal(resp.Body, &raw) != nil {
		return ""
	}
	for _, key := range []string{"guid", "userId", "id"} {
		if s, ok := raw[key].(string); ok && strings.Contains(s, "@AdobeID") {
			return s
		}
	}
	if pd, ok := raw["profileData"].(map[string]any); ok {
		if s, ok := pd["guid"].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func activateDOB(v any) map[string]int {
	if m, ok := v.(map[string]any); ok {
		day := intFromAny(m["day"])
		month := intFromAny(m["month"])
		year := intFromAny(m["year"])
		if day >= 1 && day <= 28 && month >= 1 && month <= 12 && year >= 1950 && year <= 2005 {
			return map[string]int{"day": day, "month": month, "year": year}
		}
	}
	return map[string]int{
		"day": 1 + mrand.Intn(28), "month": 1 + mrand.Intn(12), "year": 1980 + mrand.Intn(22),
	}
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}

// Fixed activate password for all incomplete subs. Re-login with this
// password is also when Adobe surfaces the invited entitlement identity.
const activatePasswordFixed = "Aa1230123.."

func genActivatePassword() string {
	return activatePasswordFixed
}

func randIntN(n int64) (int64, error) {
	if n <= 0 {
		return 0, fmt.Errorf("bad n")
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return 0, err
	}
	v := int64(0)
	for _, b := range buf {
		v = (v<<8 | int64(b)) & 0x7fffffffffffffff
	}
	return v % n, nil
}

func imsARPToken(sid string) string {
	ident := make([]byte, 16)
	_, _ = rand.Read(ident)
	mid := fmt.Sprintf("%dck", 10+mrand.Intn(90))
	raw, _ := json.Marshal(map[string]string{
		"sid": sid,
		"ftr": fmt.Sprintf("%x_%d__UDF43-m4_%s__tt", ident, time.Now().UnixMilli(), mid),
	})
	return base64.StdEncoding.EncodeToString(raw)
}

func activateMarketingHTML() string {
	return `<section data-id="MarketingConsent-Explicit">The <a class="dA8iBG_spectrum-Link dA8iBG_spectrum-Link--secondary" href="https://www.adobe.com/privacy/policy-linkfree.html" target="_blank" rel="noreferrer">Adobe family of companies</a> may keep me informed with <a class="dA8iBG_spectrum-Link dA8iBG_spectrum-Link--secondary" href="https://www.adobe.com/privacy/marketing-linkfree.html#mktg-email" target="_blank" rel="noreferrer">personalized</a> emails about products and services. See our <a class="dA8iBG_spectrum-Link dA8iBG_spectrum-Link--secondary" href="https://www.adobe.com/privacy/policy-linkfree.html#info-share" target="_blank" rel="noreferrer">Privacy Policy</a> for more details or to opt-out at any time. By clicking Complete account, I agree that I have read and accepted the Terms of Use and Privacy Policy.</section>`
}

func challengePurpose(body []byte) string {
	blob := strings.ToLower(string(body) + " " + adobeErr(body))
	switch {
	case strings.Contains(blob, "incompleteaccount"):
		return "incompleteAccount"
	case strings.Contains(blob, "multifactorauthentication"), strings.Contains(blob, `"mfa"`):
		return "multiFactorAuthentication"
	default:
		return ""
	}
}

func purposeLabel(purpose string) string {
	switch purpose {
	case "incompleteAccount":
		return "未完成账号"
	case "multiFactorAuthentication":
		return "二次验证"
	case "":
		return ""
	default:
		return purpose
	}
}

func ExtractCode(text string) string {
	clean := emailRE.ReplaceAllString(text, " ")
	if strings.Contains(clean, "<") {
		clean = regexp.MustCompile(`(?is)<script[^>]*>[\s\S]*?</script>`).ReplaceAllString(clean, " ")
		clean = regexp.MustCompile(`(?is)<style[^>]*>[\s\S]*?</style>`).ReplaceAllString(clean, " ")
		clean = regexp.MustCompile(`(?is)<[^>]+>`).ReplaceAllString(clean, " ")
	}
	for _, re := range []*regexp.Regexp{labeledCode, htmlCode} {
		if m := re.FindStringSubmatch(clean); len(m) == 2 && m[1] != "000000" {
			return m[1]
		}
	}
	trim := strings.TrimSpace(clean)
	if regexp.MustCompile(`^\d{6}$`).MatchString(trim) && trim != "000000" {
		return trim
	}
	if m := bareCode.FindStringSubmatch(clean); len(m) == 2 && m[1] != "000000" {
		return m[1]
	}
	return ""
}

func mailLooksAdobe(from, subject string) bool {
	blob := strings.ToLower(from + " " + subject)
	return strings.Contains(blob, "adobe") || strings.Contains(blob, "验证码") ||
		strings.Contains(blob, "verification") || strings.Contains(blob, "security code") ||
		strings.Contains(blob, "one-time")
}
