package arp

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"firefly-go/internal/config"
	"firefly-go/internal/geo"
	"firefly-go/internal/transport"
	"github.com/google/uuid"
)

const IDGURL = "https://idg.adobe.com/v1/api/bfp_capture"

type BFPCollector struct {
	once         sync.Once
	templatePost []byte
	loadErr      error
	templatePath string
}

func NewBFPCollector(templatePath string) *BFPCollector {
	return &BFPCollector{templatePath: templatePath}
}

func (b *BFPCollector) ensureTemplate() error {
	b.once.Do(func() {
		raw, err := os.ReadFile(b.templatePath)
		if err != nil {
			b.loadErr = err
			return
		}
		var wrapper struct {
			BfpReq struct {
				Post json.RawMessage `json:"post"`
			} `json:"bfp_req"`
		}
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			b.loadErr = err
			return
		}
		var postStr string
		if err := json.Unmarshal(wrapper.BfpReq.Post, &postStr); err == nil {
			b.templatePost = []byte(postStr)
		} else {
			b.templatePost = wrapper.BfpReq.Post
		}
	})
	return b.loadErr
}

type BFPResult struct {
	OK        bool   `json:"ok"`
	Status    int    `json:"status"`
	BFP       string `json:"bfp"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

func (b *BFPCollector) Capture(pool *transport.Pool, sessionID, proxy, userAgent string, prof *Profile) (BFPResult, error) {
	if prof == nil {
		prof = DefaultProfile()
	}
	if err := b.ensureTemplate(); err != nil {
		return BFPResult{}, fmt.Errorf("bfp template: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(b.templatePost, &payload); err != nil {
		return BFPResult{}, err
	}

	// pure_protocol/bfp_capture.py:_us_aligned_payload, with the locale of the
	// proxy's exit country instead of a fixed US one.
	loc := geo.ForProxy(proxy)
	payload["timezone"] = loc.TZ
	payload["languages"] = map[string]any{"default": loc.Langs}
	payload["screenResolution"] = []int{prof.H, prof.W}
	payload["colorDepth"] = 24
	payload["deviceMemory"] = prof.DM
	payload["hardwareConcurrency"] = prof.HC
	payload["platform"] = "Win32"

	if basics, ok := payload["webGlBasics"].(map[string]any); ok {
		basics["vendorUnmasked"] = prof.GPUVendor
		basics["rendererUnmasked"] = prof.GPURenderer
	}
	// Per-account identity: the harvested template carries one fixed canvas /
	// font set; sharing it across accounts would link them, so derive them
	// from the account's own device profile.
	if prof.File != "" {
		payload["canvas"] = map[string]any{
			"winding":  true,
			"geometry": prof.CanvasHash("geometry"),
			"text":     prof.CanvasHash("text"),
		}
		if len(prof.Fonts) > 0 {
			payload["fonts"] = prof.Fonts
		}
	}

	// Scrub all headless / automation flags from the harvested Express template
	if headless, ok := payload["headless"].(map[string]any); ok {
		headless["chromium"] = false
		if like, ok := headless["likeHeadless"].(map[string]any); ok {
			like["noTaskbar"] = false
			like["hasVvpScreenRes"] = false
		}
		if hl, ok := headless["headless"].(map[string]any); ok {
			hl["webDriverIsOn"] = false
			hl["hasHeadlessUA"] = false
		}
	}

	if uad, ok := payload["userAgentData"].(map[string]any); ok {
		uad["brands"] = []string{"Not;A=Brand", "Chromium", "Google Chrome"}
		uad["brandsVersion"] = []string{"Not;A=Brand 8", "Chromium 150", "Google Chrome 150"}
		uad["uaFullVersion"] = config.ChromeFullVersion
		uad["platform"] = "Windows"
		uad["platformVersion"] = "19.0.0"
		uad["architecture"] = "x86"
		uad["bitness"] = "64"
		uad["mobile"] = false
	}

	meta, _ := payload["metaData"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
		payload["metaData"] = meta
	}
	priv, _ := meta["privateMeta"].(map[string]any)
	if priv == nil {
		priv = map[string]any{}
		meta["privateMeta"] = priv
	}
	priv["idgTokenLs"] = uuid.NewString()
	meta["meta"] = map[string]any{"clientId": config.SiteClientID()}
	if payload["mode"] == nil || payload["mode"] == "" {
		payload["mode"] = "kBlocking"
	}
	if payload["version"] == nil || payload["version"] == "" {
		payload["version"] = "1.0.19"
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return BFPResult{}, err
	}
	if userAgent == "" {
		userAgent = config.DefaultUserAgent
	}

	headers := [][2]string{
		{"accept", "*/*"},
		{"content-type", "application/json"},
		{"origin", config.SiteOrigin()},
		{"referer", config.SiteOrigin() + "/"},
		{"user-agent", userAgent},
		{"accept-language", loc.AcceptLanguage()},
		{"x-api-key", "genuine-bfp-arp"},
		{"x-client-id", config.SiteClientID()},
		{"sec-ch-ua-mobile", "?0"},
		{"sec-ch-ua-platform", `"Windows"`},
	}

	started := time.Now()
	status, _, respBody, err := pool.Do(sessionID, proxy, "POST", IDGURL, headers, bodyBytes)
	if err != nil {
		return BFPResult{}, err
	}
	var resp struct {
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(respBody, &resp)
	ok := status == 200 && len(resp.RequestID) == 36
	return BFPResult{
		OK:        ok,
		Status:    status,
		BFP:       resp.RequestID,
		ElapsedMS: time.Since(started).Milliseconds(),
	}, nil
}
