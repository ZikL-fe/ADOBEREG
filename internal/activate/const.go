package activate

import "regexp"

const (
	authHost   = "https://auth.services.adobe.com"
	imsHost    = "https://ims-na1.adobelogin.com"
	imsBackend = "https://adobeid-na1.services.adobe.com"
	signupPK   = "436DD567-5435-4B14-89A6-2F1188E11334"
	susiClient = "homepage_milo"
	fireflyID  = "clio-playground-web"
	fireflyScope = "openid,AdobeID,firefly_api,additional_info.roles"
	fireflyHome  = "https://firefly.adobe.com/"
	homeScope    = "AdobeID,openid,gnav,pps.read,read_organizations,firefly_api,additional_info.roles,account_cluster.read"
	redirectURI  = "https://auth-light.identity.adobe.com/wrapper-popup-helper/index.html"
	defaultUA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
)

var (
	labeledCode = regexp.MustCompile(`(?i)(?:one[\s-]?time[\s-]?(?:password|code)|verification\s+code|authentication\s+code|security\s+code|your\s+code|code\s+is|code:|otp[:\s]+|验证码|驗證碼|安全代码)[^\d]{0,50}(\d{6})`)
	htmlCode    = regexp.MustCompile(`(?i)code\s*[:is]+\s*<[^>]*>\s*(\d{6})`)
	bareCode    = regexp.MustCompile(`(?:^|[^\w.\-+/=])(\d{6})(?:[^\w.\-+/=]|$)`)
	emailRE     = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	accessRE    = regexp.MustCompile(`[#&?]access_token=([^&#]+)`)
	metaURL     = regexp.MustCompile(`(?i)url=([^"'>\s]+)`)
	userinfoRE  = regexp.MustCompile(`://[^/\s]*@`)
)
