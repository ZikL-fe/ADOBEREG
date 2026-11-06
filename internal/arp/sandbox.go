package arp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"firefly-go/internal/config"
	"firefly-go/internal/geo"
	"firefly-go/internal/transport"
)

var reTokenRegion = regexp.MustCompile(`\|r=([^|]+)`)

// SandboxPool bounds concurrent Node VM invocations and hooks them directly
// into the in-process Go Chrome-146 TLS relay (no external relay.exe needed).
type SandboxPool struct {
	sem         chan struct{}
	nodeBin     string
	sandboxDir  string
	sherlockDir string
	tlsPool     *transport.Pool
}

func NewSandboxPool(size int, nodeBin, sandboxDir, sherlockDir string, tlsPool *transport.Pool) *SandboxPool {
	if size <= 0 {
		size = 4
	}
	return &SandboxPool{
		sem:         make(chan struct{}, size),
		nodeBin:     nodeBin,
		sandboxDir:  sandboxDir,
		sherlockDir: sherlockDir,
		tlsPool:     tlsPool,
	}
}

type ArkResult struct {
	OK        bool   `json:"ok"`
	Token     string `json:"token"`
	Region    string `json:"region"`
	Sup       bool   `json:"sup"`
	Device    string `json:"device,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Error     string `json:"error,omitempty"`
}

// MintArk runs the Arkose VM with the time zone / languages of the proxy's exit
// country so the ark token agrees with the IP it is minted from.
func (s *SandboxPool) MintArk(ctx context.Context, proxyURL string, prof *Profile) (ArkResult, error) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return ArkResult{}, ctx.Err()
	}

	started := time.Now()
	relayAddr, err := s.tlsPool.StartLocalRelay()
	if err != nil {
		return ArkResult{}, fmt.Errorf("start local relay: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "arksb-*")
	if err != nil {
		return ArkResult{}, err
	}
	defer os.RemoveAll(tmpDir)

	loc := geo.ForProxy(proxyURL)

	runCtx, cancel := context.WithTimeout(ctx, 55*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, s.nodeBin, "bda_sandbox.js")
	cmd.Dir = s.sandboxDir
	env := append(os.Environ(),
		"TZ="+loc.TZ,
		"BDA_TZ="+loc.TZ,
		"BDA_LANGUAGES="+strings.Join(loc.Langs, ","),
		"BDA_LOCALE="+loc.SandboxLocale(),
		"BDA_TRANSPORT=chrome",
		"BDA_TAG=ark",
		"BDA_OUT="+tmpDir,
		"BDA_RELAY_ADDR="+relayAddr,
		"COLLECT_PROXY="+transport.NormalizeProxy(proxyURL),
		"BDA_TARGET="+arkTarget(),
		// Cached api.js is reused until it is half an hour old, then one mint
		// pulls the live script and keeps it only when the gt2 hook still matches.
		"BDA_API_REFRESH_MS=1800000",
	)
	if prof != nil && prof.File != "" {
		env = append(env, "BDA_DEVICE="+prof.File) // this account's own device, never a random one
	}
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()

	var report struct {
		Device     string `json:"device"`
		Kind       string `json:"kind"`
		Region     string `json:"region"`
		Sup        bool   `json:"sup"`
		Error      string `json:"error"`
		LoadError  string `json:"loadError"`
		APIRefresh string `json:"apiRefresh"`
		APIStatus  int    `json:"apiStatus"`
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") {
			_ = json.Unmarshal([]byte(line), &report)
			break
		}
	}
	switch report.APIRefresh {
	case "updated":
		log.Printf("[ARP] arkose api.js updated (status %d)", report.APIStatus)
	case "kept":
		log.Printf("[ARP] arkose api.js live copy has no hook, kept cache (status %d)", report.APIStatus)
	}

	tokBytes, _ := os.ReadFile(filepath.Join(tmpDir, "ark.token"))
	token := strings.TrimSpace(string(tokBytes))
	region := report.Region
	if region == "" {
		if m := reTokenRegion.FindStringSubmatch(token); len(m) > 1 {
			region = m[1]
		}
	}

	res := ArkResult{
		OK:        token != "" && report.Sup,
		Token:     token,
		Region:    region,
		Sup:       report.Sup,
		Device:    report.Device,
		ElapsedMS: time.Since(started).Milliseconds(),
	}
	if !res.OK {
		res.Error = report.Error
		if res.Error == "" {
			res.Error = report.LoadError
		}
		if res.Error == "" {
			res.Error = fmt.Sprintf("token_empty=%v sup=%v kind=%s", token == "", report.Sup, report.Kind)
		}
	}
	return res, nil
}

// arkTarget picks the bda_sandbox.js page (same Adobe pk, different site).
func arkTarget() string {
	if config.ExpressSite() {
		return "express"
	}
	return "firefly"
}

func sherlockPageURL() string {
	if config.ExpressSite() {
		return config.SiteOrigin() + "/"
	}
	return "https://firefly.adobe.com/hub"
}

type SherlockResult struct {
	OK        bool   `json:"ok"`
	Token     string `json:"token"`
	SID       string `json:"sid"`
	FTR       string `json:"ftr"`
	ARK       string `json:"ark"`
	BFP       string `json:"bfp"`
	Error     string `json:"error,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

// MintSherlock runs 著票's JSDOM Sherlock collector (real Forter /g/index +
// BFP + Arkose gt2) through the same sticky proxy. Protocol-reconstructed
// FTR is not used: Adobe rejects those with 408.
func (s *SandboxPool) MintSherlock(ctx context.Context, proxyURL, userAgent string, prof *Profile) (SherlockResult, error) {
	started := time.Now()
	if strings.TrimSpace(s.sherlockDir) == "" {
		return SherlockResult{ElapsedMS: time.Since(started).Milliseconds(), Error: "sherlock_dir_empty"}, fmt.Errorf("sherlock dir not configured")
	}
	script := filepath.Join(s.sherlockDir, "mint.js")
	if _, err := os.Stat(script); err != nil {
		return SherlockResult{ElapsedMS: time.Since(started).Milliseconds(), Error: "sherlock_missing"}, fmt.Errorf("sherlock mint.js: %w", err)
	}

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return SherlockResult{}, ctx.Err()
	}

	loc := geo.ForProxy(proxyURL)
	body, _ := json.Marshal(map[string]string{
		"proxy_url":   transport.CanonProxy(proxyURL),
		"page_url":    sherlockPageURL(),
		"client_id":   config.SiteClientID(),
		"locale":      loc.Lang(),
		"timezone":    loc.TZ,
		"user_agent":  userAgent,
		"device_path": profFile(prof),
	})

	// sherlock.js settles as soon as ftr+bfp+ark+gt2 are ready, and gives up at
	// 22s plus an 8s Forter grace. Leave room for node startup and the Forter
	// script parse so a slow mint fails cleanly instead of "signal: killed".
	runCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, s.nodeBin, "mint.js")
	cmd.Dir = s.sherlockDir
	cmd.Stdin = bytes.NewReader(body)
	cmd.Env = append(os.Environ(), "TZ="+loc.TZ)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	var out SherlockResult
	// stdout may contain page logs around the result. Use the last JSON object line.
	for _, line := range bytes.Split(stdout.Bytes(), []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) > 0 && line[0] == '{' {
			var one SherlockResult
			if json.Unmarshal(line, &one) == nil {
				out = one
			}
		}
	}
	out.ElapsedMS = time.Since(started).Milliseconds()
	if !out.OK {
		if out.Error == "" {
			out.Error = strings.TrimSpace(stderr.String())
		}
		if out.Error == "" && runErr != nil {
			out.Error = runErr.Error()
		}
		if out.Error == "" {
			out.Error = "sherlock_empty"
		}
		return out, fmt.Errorf("sherlock: %s", out.Error)
	}
	if !matureFTR(out.FTR) || strings.TrimSpace(out.BFP) == "" {
		out.OK = false
		if out.Error == "" {
			out.Error = "sherlock_immature"
		}
		return out, fmt.Errorf("sherlock: %s", out.Error)
	}
	return out, nil
}

func profFile(p *Profile) string {
	if p == nil {
		return ""
	}
	return p.File
}
