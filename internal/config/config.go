package config

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type BucketSpec struct {
	ClientID     string
	APIKey       string
	Origin       string
	Referer      string
	Scope        string
	RequireNonce bool
	AllowFlare25 bool
}

var Buckets = map[string]BucketSpec{
	"clio-playground-web": {
		ClientID: "clio-playground-web",
		APIKey:   "clio-playground-web",
		Origin:   "https://firefly.adobe.com",
		Referer:  "https://firefly.adobe.com/",
		Scope: "AdobeID,ab.manage,account_cluster.read,additional_info.ownerOrg," +
			"additional_info.projectedProductContext,additional_info.roles," +
			"creative_production,dii_lr_ml_unlimited,firefly_api,openid,pps.read," +
			"pps.write,profile,read_organizations,tk_platform,tk_platform_sync," +
			"uds_read,uds_write",
		RequireNonce: true,
		AllowFlare25: true,
	},
	"projectx_webapp": {
		ClientID:     "projectx_webapp",
		APIKey:       "projectx_webapp",
		Origin:       "https://express.adobe.com",
		Referer:      "https://express.adobe.com/",
		Scope:        "AdobeID,openid,firefly_api",
		RequireNonce: false,
		AllowFlare25: true,
	},
	"PSWebApp1": {
		ClientID: "PSWebApp1",
		APIKey:   "PSWebApp1",
		Origin:   "https://photoshop.adobe.com",
		Referer:  "https://photoshop.adobe.com/",
		Scope: "ab.manage,AdobeID,openid,creative_sdk,tk_platform,tk_platform_sync," +
			"af_byof,uds_read,uds_write,firefly_api,additional_info.ownerOrg," +
			"additional_info.roles,read_organizations,pps.read,account_cluster.read," +
			"dii_lr_ml_unlimited",
		RequireNonce: false,
		AllowFlare25: false,
	},
}

const (
	// Chrome 150.0.7871.115 is the browser the working 著票 worker reports.
	// The UA string stays major.0.0.0; the full build is only in client hints.
	DefaultUserAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
	ChromeFullVersion      = "150.0.7871.115"
	DefaultAcceptLanguage  = "en-GB,en-US;q=0.9,en;q=0.8"
	DefaultTimezone        = "America/New_York"
	SecCHUA                = `"Not;A=Brand";v="8", "Chromium";v="150", "Google Chrome";v="150"`
	SecCHUAFullVersion     = `"150.0.7871.115"`
	SecCHUAFullVersionList = `"Not;A=Brand";v="8.0.0.0", "Chromium";v="150.0.7871.115", "Google Chrome";v="150.0.7871.115"`
	SecCHUAMobile          = "?0"
	SecCHUAPlatform        = `"Windows"`
	SecCHUAPlatformVersion = `"19.0.0"`
	SecCHUAArch            = `"x86"`
	SecCHUABitness         = `"64"`
	SecCHUAModel           = `""`

	// iOS Express (iPhone, iOS 18.7) identity for firefly-3p calls: generate-async,
	// result polling and reference upload. Safari sends no client hints.
	IOSUserAgent      = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Safari -nativeHz"
	IOSAcceptLanguage = "zh-CN,zh-Hans;q=0.9"
)

// ExpressSite (FIREFLY_SITE=express) makes the whole chain present the desktop
// Express page: tickets are minted for express.adobe.com / projectx_webapp and
// image jobs are submitted through projectx_webapp.
func ExpressSite() bool {
	return os.Getenv("FIREFLY_SITE") == "express"
}

// SiteOrigin is the page origin the ticket mint (Forter, BFP, Arkose) presents.
func SiteOrigin() string {
	if ExpressSite() {
		return "https://express.adobe.com"
	}
	return "https://firefly.adobe.com"
}

// SiteClientID is the Adobe client the ticket is minted for (BFP clientId).
func SiteClientID() string {
	if ExpressSite() {
		return "projectx_webapp"
	}
	return "clio-playground-web"
}

type Config struct {
	ListenAddr      string
	DataDir         string
	ArkSandboxDir   string
	SherlockDir     string
	BFPTemplatePath string
	CookiePoolPath  string
	ProxyFilePath   string
	NodeBin         string
	MaxWorkers      int
	SandboxPoolSize int
	ArpWarmPoolSize int
	PollInterval    time.Duration
	PollTimeout     time.Duration
}

func Load() Config {
	dataDir := envOr("DATA_DIR", "./data")
	_ = os.MkdirAll(dataDir, 0755)
	return Config{
		ListenAddr:      envOr("LISTEN_ADDR", ":8080"),
		DataDir:         dataDir,
		ArkSandboxDir:   envOr("ARK_SANDBOX_DIR", filepath.Join(dataDir, "arksandbox")),
		SherlockDir:     envOr("SHERLOCK_DIR", filepath.Join(dataDir, "sherlock")),
		BFPTemplatePath: envOr("BFP_TEMPLATE_PATH", filepath.Join(dataDir, "bfp_capture_template.json")),
		CookiePoolPath:  envOr("COOKIE_POOL_PATH", filepath.Join(dataDir, "ck.txt")),
		ProxyFilePath:   envOr("PROXY_FILE_PATH", filepath.Join(dataDir, "proxy.txt")),
		NodeBin:         envOr("ARK_SANDBOX_NODE", "node"),
		MaxWorkers:      envInt("MAX_WORKERS", 16),
		SandboxPoolSize: envInt("SANDBOX_POOL_SIZE", 24),
		ArpWarmPoolSize: envInt("ARP_WARM_POOL_SIZE", 8),
		PollInterval:    2 * time.Second,
		PollTimeout:     180 * time.Second,
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}
