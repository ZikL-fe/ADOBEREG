package arp

import (
	"bytes"
	"compress/flate"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"time"

	"firefly-go/internal/config"
	"firefly-go/internal/geo"
	"firefly-go/internal/transport"
	"github.com/google/uuid"
)

const (
	ForterSiteID = "8a81eebba889"
	// Production SRI path Sherlock / goad harvest against. The previous
	// JNx73YmQ… hash is a stale collector build; events posted under it
	// never reach the live Forter script Firefly actually loads.
	ForterScriptHash = "sha256-Gh7TKmjdnCMfMU8%2B%2FQGSjb6IThXs4czxYsOpmy0H03w%3D"
	ForterPageURL    = "https://commerce.adobe.com/store/checkout?items%5B0%5D%5Bid%5D=65BA7CA7573834AC4D043B0E7CBD2349&items%5B0%5D%5Bq%5D=1&cli=adobe_com&ctx=fp&co=US&lang=en"
)

type ForterResult struct {
	OK              bool   `json:"ok"`
	FTR             string `json:"ftr"`
	TokenID         string `json:"token_id"`
	PowSolved       bool   `json:"pow_solved"`
	EventsSent      int    `json:"events_sent"`
	FallbackPowOnly bool   `json:"fallback_pow_only"`
}

func BuildFtrBase(tokenID string, nowMS int64, ex string) string {
	if tokenID == "" {
		tokenID = strings.ReplaceAll(uuid.NewString(), "-", "")
	}
	if nowMS <= 0 {
		nowMS = time.Now().UnixMilli()
	}
	if ex == "" {
		ex = "UDF43"
	}
	return fmt.Sprintf("%s_%d__%s_31ck", tokenID, nowMS, ex)
}

func SolveForterMD5PoW(challenge string, difficulty int) (int, string, error) {
	if difficulty < 1 || difficulty > 8 {
		return 0, "", fmt.Errorf("invalid difficulty %d", difficulty)
	}
	suffix := strings.Repeat("0", difficulty)
	for nonce := 2; nonce < 50_000_000; nonce++ {
		input := fmt.Sprintf("%s%d", challenge, nonce)
		sum := md5.Sum([]byte(input))
		h := hex.EncodeToString(sum[:])
		if strings.HasSuffix(h, suffix) {
			return nonce, fmt.Sprintf("%s-%d-v2", challenge, nonce), nil
		}
	}
	return 0, "", fmt.Errorf("pow exhausted")
}

func browserGzip(data []byte) ([]byte, error) {
	var rawDeflate bytes.Buffer
	zw, err := flate.NewWriter(&rawDeflate, 6)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	var out bytes.Buffer
	out.Write([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03})
	out.Write(rawDeflate.Bytes())
	var trailer [8]byte
	binary.LittleEndian.PutUint32(trailer[0:4], crc32.ChecksumIEEE(data))
	binary.LittleEndian.PutUint32(trailer[4:8], uint32(len(data)))
	out.Write(trailer[:])
	return out.Bytes(), nil
}

// MintForterFTR is a 1:1 port of pure_protocol/_forter_solver_upstream.py
// including full rdc_test mmt/mmd sampleArray statistics and 2-round PoW + events.
func MintForterFTR(pool *transport.Pool, sessionID, proxy, userAgent string, prof *Profile) (ForterResult, error) {
	if userAgent == "" {
		userAgent = config.DefaultUserAgent
	}
	if prof == nil {
		prof = DefaultProfile()
	}
	ts := time.Now().UnixMilli()
	tokenID := strings.ReplaceAll(uuid.NewString(), "-", "")
	ex := "UDF43-mnf"
	if config.ExpressSite() {
		ex = "UDF43-m4"
	}
	base := BuildFtrBase(tokenID, ts, ex)

	ftrSess := "ftr-" + tokenID

	// Round 1 Step 1 (Fail-Fast Proxy Probe): GET cdn123 PoW challenge first
	challenge, difficulty, nonce, powt, err := fetchAndSolvePoW(pool, ftrSess, proxy, userAgent, tokenID)
	if err != nil {
		return ForterResult{}, err
	}

	// Round 1 Steps 0/2/3/4: independent GETs/POSTs after PoW — run in parallel
	// to cut ~3 proxy RTTs (biggest win on JP/distant exits).
	scriptURL := fmt.Sprintf("https://%s.cdn4.forter.com/sn/%s/%s/script.js", ForterSiteID, ForterSiteID, ForterScriptHash)
	propBeaconURL := fmt.Sprintf("https://%s-%s.cdn.forter.com/prop.json", tokenID, ForterSiteID)
	pollURL := fmt.Sprintf("https://cdn0.forter.com/%s/%s/prop.json?_=%d", ForterSiteID, tokenID, time.Now().UnixMilli())
	wptURL := fmt.Sprintf("https://cdn0.forter.com/%s/%s/wpt.json", ForterSiteID, tokenID)
	wptBody, _ := json.Marshal(map[string]any{
		"wpt": round2(200.0 + rand.Float64()*100.0),
		"sct": 0,
		"dlt": 0,
	})
	var r1 sync.WaitGroup
	r1.Add(4)
	go func() {
		defer r1.Done()
		_, _, _, _ = pool.DoFast(ftrSess, proxy, "GET", scriptURL, [][2]string{
			{"origin", config.SiteOrigin()},
			{"referer", config.SiteOrigin() + "/"},
			{"user-agent", userAgent},
		}, nil)
	}()
	go func() {
		defer r1.Done()
		_, _, _, _ = pool.DoFast(ftrSess, proxy, "POST", propBeaconURL, [][2]string{
			{"referer", config.SiteOrigin() + "/"},
			{"content-type", "text/plain;charset=UTF-8"},
			{"user-agent", userAgent},
		}, nil)
	}()
	go func() {
		defer r1.Done()
		_, _, _, _ = pool.DoFast(ftrSess, proxy, "GET", pollURL, [][2]string{
			{"referer", config.SiteOrigin() + "/"},
			{"user-agent", userAgent},
		}, nil)
	}()
	go func() {
		defer r1.Done()
		_, _, _, _ = pool.DoFast(ftrSess, proxy, "POST", wptURL, [][2]string{
			{"referer", config.SiteOrigin() + "/"},
			{"content-type", "application/json; charset=UTF-8"},
			{"user-agent", userAgent},
		}, wptBody)
	}()
	r1.Wait()

	// Round 1 Step 5: Send initial events (id 0-39 with imm) + 1 rdc2 batch
	eventID := 0
	cursorTS := ts
	initBatch := genInitialEvents(ts, userAgent, prof, geo.ForProxy(proxy))
	eventID = 40
	cursorTS = ts + 40*50
	r1Batches := genRdc2Batches(ts, &eventID, &cursorTS, 1, false, false, false, "", 0)
	allR1 := append([][]map[string]any{initBatch}, r1Batches...)
	sent1 := sendForterEventBatches(pool, ftrSess, proxy, userAgent, tokenID, powt, allR1)

	// Round 2: Re-fetch PoW + prop beacon in parallel, then main batches
	time.Sleep(150 * time.Millisecond)
	var (
		ch2, powt2 string
		diff2, n2  int
		err2       error
		r2         sync.WaitGroup
	)
	r2.Add(2)
	go func() {
		defer r2.Done()
		ch2, diff2, n2, powt2, err2 = fetchAndSolvePoW(pool, ftrSess, proxy, userAgent, tokenID)
	}()
	go func() {
		defer r2.Done()
		_, _, _, _ = pool.DoFast(ftrSess, proxy, "POST", propBeaconURL, [][2]string{
			{"referer", config.SiteOrigin() + "/"},
			{"content-type", "text/plain;charset=UTF-8"},
			{"user-agent", userAgent},
		}, nil)
	}()
	r2.Wait()
	if err2 == nil && powt2 != "" {
		challenge, difficulty, nonce, powt = ch2, diff2, n2, powt2
	}
	_ = difficulty

	mainBatches := genRdc2Batches(ts, &eventID, &cursorTS, 3, true, true, true, challenge, nonce)
	sent2 := sendForterEventBatches(pool, ftrSess, proxy, userAgent, tokenID, powt, mainBatches)
	if sent1 == 0 || sent2 == 0 {
		return ForterResult{EventsSent: sent1 + sent2}, fmt.Errorf("forter events rejected (r1=%d r2=%d)", sent1, sent2)
	}

	ftr := fmt.Sprintf("%s_%s_tt", base, powt)
	return ForterResult{
		OK:         strings.HasSuffix(ftr, "_tt"),
		FTR:        ftr,
		TokenID:    tokenID,
		PowSolved:  true,
		EventsSent: sent1 + sent2,
	}, nil
}

func forterPageURL() string {
	if config.ExpressSite() {
		return config.SiteOrigin() + "/"
	}
	return ForterPageURL
}

func fetchAndSolvePoW(pool *transport.Pool, sess, proxy, ua, tokenID string) (string, int, int, string, error) {
	u := fmt.Sprintf("https://cdn123.forter.com/?u=%s&v=2", tokenID)
	status, _, body, err := pool.DoFast(sess, proxy, "GET", u, [][2]string{
		{"referer", config.SiteOrigin() + "/"},
		{"content-type", "text/plain"},
		{"user-agent", ua},
	}, nil)
	if err != nil {
		return "", 0, 0, "", fmt.Errorf("proxy unreachable on cdn123: %w", err)
	}

	if status != 200 || len(bytes.TrimSpace(body)) == 0 {
		return "", 0, 0, "", fmt.Errorf("cdn123 status=%d empty=%t", status, len(bytes.TrimSpace(body)) == 0)
	}
	var parsed struct {
		C string `json:"c"`
		D int    `json:"d"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &parsed); err != nil || parsed.C == "" {
		return "", 0, 0, "", fmt.Errorf("cdn123 challenge missing c: %.80s", bytes.TrimSpace(body))
	}
	difficulty := 3
	if parsed.D >= 1 && parsed.D <= 6 {
		difficulty = parsed.D
	}
	nonce, powt, err := SolveForterMD5PoW(parsed.C, difficulty)
	return parsed.C, difficulty, nonce, powt, err
}

func sendForterEventBatches(pool *transport.Pool, sess, proxy, ua, tokenID, powt string, batches [][]map[string]any) int {
	sent := 0
	useGzip := true
	for i, batch := range batches {
		if batch == nil {
			batch = []map[string]any{}
		}
		payload := map[string]any{
			"user":      batch,
			"bcn":       uuid.NewString(),
			"si":        ForterSiteID,
			"powt":      powt,
			"userId":    tokenID,
			"userAgent": ua,
			"url":       forterPageURL(),
			"refer":     "",
		}
		rawJSON, _ := json.Marshal(payload)

		var body []byte
		contentType := "text/plain; charset=gzip"
		if useGzip {
			if gz, err := browserGzip(rawJSON); err == nil {
				body = gz
			} else {
				body = rawJSON
				contentType = "text/plain;charset=UTF-8"
			}
		} else {
			body = rawJSON
			contentType = "text/plain;charset=UTF-8"
		}

		hdrs := [][2]string{
			{"referer", config.SiteOrigin() + "/"},
			{"content-type", contentType},
			{"user-agent", ua},
		}
		status, _, _, err := pool.DoFast(sess, proxy, "POST", "https://cdn3.forter.com/events", hdrs, body)
		if err == nil && status == 200 {
			sent++
		} else if err == nil && status == 415 && useGzip {
			useGzip = false
			hdrs[1][1] = "text/plain;charset=UTF-8"
			st2, _, _, err2 := pool.DoFast(sess, proxy, "POST", "https://cdn3.forter.com/events", hdrs, rawJSON)
			if err2 == nil && st2 == 200 {
				sent++
			}
		}
		if i+1 < len(batches) {
			time.Sleep(time.Duration(80+rand.IntN(120)) * time.Millisecond)
		}
	}
	return sent
}

func genInitialEvents(startTS int64, ua string, prof *Profile, loc geo.Locale) []map[string]any {
	now := time.Now()
	nowMS := now.UnixMilli()
	immFP := map[string]any{
		"T1": map[string]any{"agent": ua, "len": len(ua), "productSub": "20030107"},
		"T2": map[string]any{"platform": "Win32"},
		"T3": map[string]any{"appVersion": strings.TrimPrefix(ua, "Mozilla/")},
		"T4": map[string]any{
			"timeZone":       loc.TZ,
			"timeZoneOffset": loc.Offset(now),
			"newDate":        nowMS,
			"now":            nowMS,
			"getTime":        nowMS,
			"valueOf":        nowMS,
			"utcMethods":     "ok",
			"toJSON":         "ok",
			"toISOString":    "ok",
			"stringify":      "ok",
		},
		"T5":  map[string]any{"length": 5, "names": "PDF Viewer|Chrome PDF Viewer|Chromium PDF Viewer|Microsoft Edge PDF Viewer|WebKit built-in PDF|"},
		"T6":  true,
		"T7":  map[string]any{"length": 2},
		"T8":  true,
		"T9":  map[string]any{"language": loc.Lang(), "languages": loc.Langs, "languagesLength": len(loc.Langs)},
		"T10": map[string]any{"webdriver": false, "domAutomation": false, "domAutomationController": false, "selenium": false, "phantomJS": false, "nightmare": false, "callPhantom": false, "buffer": false, "emit": false, "spawn": false},
		"T12": map[string]any{"chrome": true},
		"T13": map[string]any{"notificationPermission": "default"},
		"T14": map[string]any{"usingDevTools": false},
		"T16": map[string]any{"outerHeight": prof.OH, "outerWidth": prof.OW, "innerHeight": prof.IH, "innerWidth": prof.IW},
		"T17": map[string]any{"connectionRtt": 50},
		"T21": map[string]any{
			"vendor":   prof.GPUVendor,
			"renderer": prof.GPURenderer,
		},
		"T42": map[string]any{"hardwareConcurrency": prof.HC},
		"T44": map[string]any{"doNotTrack": nil},
		"T45": map[string]any{"strScreen": map[string]any{
			"width": prof.W, "height": prof.H, "availWidth": prof.AW, "availHeight": prof.AH,
			"orientation":      map[string]any{"type": "landscape-primary", "angle": 0},
			"devicePixelRatio": prof.DPR, "screenTop": 0, "availLeft": 0, "screenLeft": 0, "availTop": 48,
			"colorDepth": 24, "pixelDepth": 24,
		}},
		"T49": map[string]any{"str": "function HTMLAudioElement() { [native code] }"},
		"T65": true,
		"T72": map[string]any{},
		"T80": nil,
		"T81": true,
		"T82": false,
		"T85": prof.DM,
		"T89": map[string]any{
			"brands": []map[string]string{
				{"brand": "Google Chrome", "version": "146"},
				{"brand": "Chromium", "version": "146"},
				{"brand": "Not_A Brand", "version": "24"},
			},
			"mobile":          false,
			"platform":        "Windows",
			"architecture":    "x86",
			"bitness":         "64",
			"model":           "",
			"platformVersion": "10.0.0",
			"uaFullVersion":   "146.0.0.0",
			"fullVersionList": []map[string]string{
				{"brand": "Google Chrome", "version": "146.0.0.0"},
				{"brand": "Chromium", "version": "146.0.0.0"},
				{"brand": "Not_A Brand", "version": "24.0.0.0"},
			},
		},
		"T100": map[string]any{"cookies": true, "localStorage": true, "sessionStorage": true, "indexedDB": true},
	}
	immBytes, _ := json.Marshal(immFP)

	events := make([]map[string]any, 0, 40)
	events = append(events, map[string]any{
		"start":      startTS,
		"end":        nowMS,
		"action":     "imm",
		"event_desc": "19",
		"url":        "https://commerce.adobe.com/store/email",
		"userAgent":  ua,
		"text":       string(immBytes),
		"id":         0,
	})

	for eid := 1; eid < 40; eid++ {
		evEnd := startTS + int64(eid*50+rand.IntN(21)-10)
		if rand.Float64() < 0.15 {
			events = append(events, map[string]any{
				"start":  evEnd,
				"end":    evEnd,
				"action": "blur",
				"id":     eid,
			})
		} else {
			events = append(events, genRdc2Event(eid, startTS, evEnd, false))
		}
	}
	return events
}

func genRdc2Event(eid int, startTS, endTS int64, isLast bool) map[string]any {
	margin := -1.04 + (rand.Float64()-0.5)*1.4
	prob := 1.0 / (1.0 + math.Exp(-margin))
	packets := []int{50, 50, 50, 50, 50, 48, 49, 45, 40, 38}
	textBytes, _ := json.Marshal(map[string]any{
		"modelVersion": "1.4",
		"scores": []map[string]any{{
			"marginScore":     margin,
			"probScore":       prob,
			"missingFeatures": []any{},
			"packetSize":      packets[rand.IntN(len(packets))],
		}},
	})
	ev := map[string]any{
		"start":  startTS,
		"end":    endTS,
		"action": "rdc2",
		"text":   string(textBytes),
		"extra":  `{"version":"12"}`,
		"id":     eid,
	}
	if isLast {
		ev["to_location"] = "flush"
	}
	return ev
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func genSample(stype string, eventsSeen int) map[string]any {
	mmdChoices := []float64{1, 1, 1, 1, 1, 1, 1, 1.41, 1.41, 1, 1}
	mmtChoices := []float64{3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 7, 9, 10, 3, 3, 4, 5}
	buf := make([]float64, 50)
	sum := 0.0
	for i := range buf {
		if stype == "mmd" {
			buf[i] = mmdChoices[rand.IntN(len(mmdChoices))]
		} else {
			buf[i] = mmtChoices[rand.IntN(len(mmtChoices))]
		}
		sum += buf[i]
	}
	meanV := round2(sum / 50.0)
	varSum := 0.0
	for _, x := range buf {
		d := x - meanV
		varSum += d * d
	}
	variance := round2(varSum / 50.0)
	stdev := round2(math.Sqrt(variance))
	sorted := slices.Clone(buf)
	slices.Sort(sorted)

	return map[string]any{
		"type": stype,
		"buf":  buf,
		"stats": map[string]any{
			"mean":     meanV,
			"median":   round2(sorted[25]),
			"variance": variance,
			"stdev":    stdev,
			"pcts": map[string]any{
				"0.25": sorted[12],
				"0.5":  sorted[25],
				"0.75": sorted[37],
				"0.95": sorted[47],
				"0.99": sorted[49],
			},
			"pEntropy": round2(1.5 + rand.Float64()*3.0),
			"streak0":  4 + rand.IntN(7),
			"streak1":  10 + rand.IntN(30),
			"signal": map[string]any{
				"range":         map[string]any{"min": sorted[0], "max": int(sorted[49]), "size": 6 + rand.IntN(9)},
				"crossLines":    map[string]any{"low": 3, "mid": 9, "high": 13, "cutoff": 16},
				"crossCount":    22,
				"filteredPeaks": []any{},
				"flatScore":     15 + rand.IntN(25),
			},
			"fps":              180,
			"eventsSeen":       eventsSeen,
			"idleTime":         1200 + rand.IntN(15000),
			"timeToFullWindow": 2500 + rand.IntN(20000),
		},
		"test": []any{},
	}
}

func genFullRdcTestEvent(eid int, startTS, endTS int64) map[string]any {
	nSamples := 4
	totalEvents := 3200 + rand.IntN(1200)
	totalDist := 7500 + rand.IntN(4000)
	dropCount := int(float64(totalEvents) * 0.9)
	dropRatio := round2(float64(dropCount) / float64(totalEvents))
	scoreLog := []float64{-0.3, -0.2, 0.1, 0.05, -0.1, 0.15, -0.25, -0.2, 0.05, -0.1}

	sampleStats := map[string]any{
		"variance": map[string]any{"mean": 220.5, "median": 215.2},
		"stdev":    map[string]any{"mean": 14.8, "median": 14.6},
		"pEntropy": map[string]any{"mean": 4.25, "median": 4.3},
		"streak0":  map[string]any{"mean": 6.2, "median": 6.0},
		"streak1":  map[string]any{"mean": 11.4, "median": 11.0},
	}
	signalStats := map[string]any{
		"range":   map[string]any{"mean": 12.1, "median": 12.0},
		"cross":   map[string]any{"mean": 18.0, "median": 18.0},
		"flat":    map[string]any{"mean": 19.0, "median": 19.0},
		"peaks":   map[string]any{"mean": 52.4, "median": 52.0},
		"peakLen": map[string]any{"mean": 4.0, "median": 4.0},
	}

	textObj := map[string]any{
		"anyMouseMove":                 true,
		"notTrackingCount":             5,
		"pseudoMoves":                  2,
		"totalEventsSeen":              totalEvents,
		"sampleCount":                  nSamples,
		"totalDistanceCovered":         totalDist,
		"globalDistanceRatio":          2.45,
		"avgActiveSampleTime":          185.4,
		"totalDropCount":               dropCount,
		"totalDropRatio":               dropRatio,
		"totalScore":                   -0.9,
		"batchScoreLog":                []any{},
		"totalScoreLog":                scoreLog,
		"goodInARow":                   3,
		"globalUnderMinMSDroppedCount": dropCount - 18,
		"longestStreak0":               8,
		"longestStreak1":               14,
		"currentFPS":                   180,
		"sampleStats":                  sampleStats,
		"signalStats":                  signalStats,
		"batchScore":                   -0.9,
	}

	mmtSamples := make([]map[string]any, nSamples)
	mmdSamples := make([]map[string]any, nSamples)
	for i := 0; i < nSamples; i++ {
		mmtSamples[i] = genSample("mmt", 400+rand.IntN(500))
		mmdSamples[i] = genSample("mmd", 400+rand.IntN(500))
	}

	extraObj := map[string]any{
		"anyMouseMove":                 true,
		"notTrackingCount":             5,
		"pseudoMoves":                  2,
		"totalEventsSeen":              totalEvents,
		"sampleCount":                  nSamples,
		"totalDistanceCovered":         totalDist,
		"globalDistanceRatio":          2.45,
		"avgActiveSampleTime":          185.4,
		"totalDropCount":               dropCount,
		"totalDropRatio":               dropRatio,
		"totalScore":                   -0.9,
		"test":                         []any{"[v/sig/rng]", "[x/sig/crs]", []string{"[v/pctMin]"}, "[x/strk1]"},
		"batchScoreLog":                []any{},
		"totalScoreLog":                scoreLog,
		"goodInARow":                   3,
		"sampleArray":                  map[string]any{"mmt": mmtSamples, "mmd": mmdSamples, "st": []any{}},
		"globalUnderMinMSDroppedCount": dropCount - 18,
		"longestStreak0":               8,
		"longestStreak1":               14,
		"currentFPS":                   180,
		"sampleStats":                  sampleStats,
		"signalStats":                  signalStats,
		"batchScore":                   -0.9,
	}

	textBytes, _ := json.Marshal(textObj)
	extraBytes, _ := json.Marshal(extraObj)
	return map[string]any{
		"start":      startTS,
		"end":        endTS,
		"action":     "rdc_test",
		"event_desc": "(v12)",
		"refer":      "n",
		"text":       string(textBytes),
		"extra":      string(extraBytes),
		"id":         eid,
	}
}

func genRdc2Batches(startTS int64, eventID *int, cursorTS *int64, numBatches int, includeAut, includeRdcTest, includePow bool, challenge string, nonce int) [][]map[string]any {
	batches := make([][]map[string]any, 0, numBatches)
	for b := 0; b < numBatches; b++ {
		batchSize := 10 + rand.IntN(8)
		events := make([]map[string]any, 0, batchSize+4)
		isLastBatch := b == numBatches-1
		for j := 0; j < batchSize; j++ {
			*cursorTS += int64(35 + rand.IntN(30))
			isLast := isLastBatch && j == batchSize-1 && !includePow
			events = append(events, genRdc2Event(*eventID, startTS, *cursorTS, isLast))
			*eventID++
		}
		if b == 1 && includeAut {
			autText, _ := json.Marshal(map[string]any{
				"count":     2 + rand.IntN(5),
				"category":  "behavior",
				"eventType": "events",
				"source":    "n/a",
				"name":      "mousemove_c",
			})
			events = append(events, map[string]any{
				"start":      startTS,
				"end":        *cursorTS,
				"action":     "aut",
				"event_desc": "16",
				"text":       string(autText),
				"id":         *eventID,
			})
			*eventID++
		}
		if b == numBatches-2 && includeRdcTest {
			events = append(events, genFullRdcTestEvent(*eventID, startTS, *cursorTS))
			*eventID++
		}
		if isLastBatch && includePow && challenge != "" {
			powText, _ := json.Marshal(map[string]any{
				"challenge": challenge,
				"num":       nonce,
				"v":         "v2",
				"isWorker":  true,
			})
			events = append(events, map[string]any{
				"start":       startTS,
				"end":         time.Now().UnixMilli(),
				"action":      "pow",
				"event_desc":  "8",
				"text":        string(powText),
				"to_location": "flush",
				"id":          *eventID,
			})
			*eventID++
			*cursorTS += 45
			events = append(events, genRdc2Event(*eventID, startTS, *cursorTS, true))
			*eventID++
		}
		batches = append(batches, events)
		*cursorTS += int64(2000 + rand.IntN(2000))
	}
	return batches
}
