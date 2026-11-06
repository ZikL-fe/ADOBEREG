package arp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	reArkRegion = regexp.MustCompile(`(?:^|\|)r=([^|]+)`)
	reFtrFlags  = regexp.MustCompile(`(?i)UDF43(?:-[a-z0-9]+)*_31ck`)
)

type TicketPayload struct {
	SID string
	FTR string
	ARK string
	BFP string
}

// AssembleTicket serializes {sid, ftr, ark, bfp} in strict pool key order
// without HTML escaping and returns standard base64 for x-arp-session-id.
func AssembleTicket(t TicketPayload) string {
	var buf bytes.Buffer
	buf.WriteByte('{')
	fields := [][2]string{
		{"sid", t.SID},
		{"ftr", t.FTR},
		{"ark", t.ARK},
		{"bfp", t.BFP},
	}
	first := true
	for _, kv := range fields {
		if kv[1] == "" {
			continue
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		kBytes, _ := json.Marshal(kv[0])
		vBytes, _ := json.Marshal(kv[1])
		buf.Write(kBytes)
		buf.WriteByte(':')
		buf.Write(vBytes)
	}
	buf.WriteByte('}')
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

type ShapeReport struct {
	OK          bool     `json:"ok"`
	FtrPoolLike bool     `json:"pool_like_ftr"`
	EmptyTD     bool     `json:"empty_td"`
	ArkRegion   string   `json:"ark_region"`
	ArkSup      bool     `json:"ark_sup"`
	Gaps        []string `json:"gaps,omitempty"`
}

func ValidatePoolShape(t TicketPayload, requireUS bool) ShapeReport {
	var gaps []string
	if t.SID == "" {
		gaps = append(gaps, "missing:sid")
	}
	if t.FTR == "" {
		gaps = append(gaps, "missing:ftr")
	}
	if t.ARK == "" {
		gaps = append(gaps, "missing:ark")
	}
	if t.BFP == "" {
		gaps = append(gaps, "missing:bfp")
	}

	poolLike := matureFTR(t.FTR)
	emptyTD := strings.Contains(t.FTR, "__UDF")
	arkSup := strings.Contains(t.ARK, "sup=1")
	region := ""
	if m := reArkRegion.FindStringSubmatch(t.ARK); len(m) > 1 {
		region = m[1]
	}

	if !poolLike {
		gaps = append(gaps, "ftr_not_pool_like")
	}
	if !emptyTD {
		gaps = append(gaps, "ftr_td_not_empty")
	}
	if !arkSup {
		gaps = append(gaps, "ark_not_sup")
	}
	if requireUS && !strings.HasPrefix(region, "us-") {
		gaps = append(gaps, fmt.Sprintf("ark_region:%s", region))
	}

	return ShapeReport{
		OK:          len(gaps) == 0,
		FtrPoolLike: poolLike,
		EmptyTD:     emptyTD,
		ArkRegion:   region,
		ArkSup:      arkSup,
		Gaps:        gaps,
	}
}

// matureFTR is the Sherlock collector check: __UDF43 plus a real 31ck payload.
// Accepts live tickets (__UDF43_31ck_<pow>_tt) and older UDF43-mnf / UDF43-m4.
// Rejects the placeholder Forter writes before /g/index (31ck_tt with no proof).
func matureFTR(token string) bool {
	token = strings.TrimSpace(token)
	if !strings.Contains(token, "__UDF43") {
		return false
	}
	at := strings.Index(token, "31ck_")
	if at < 0 {
		return false
	}
	rest := token[at+len("31ck_"):]
	return len(rest) > 8 && rest != "tt"
}

// DecodeTicket reads standard Base64 JSON sid/ftr/ark/bfp.
func DecodeTicket(b64 string) (TicketPayload, bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		padded := strings.TrimSpace(b64)
		if m := len(padded) % 4; m != 0 {
			padded += strings.Repeat("=", 4-m)
		}
		raw, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			return TicketPayload{}, false
		}
	}
	var parsed struct {
		SID string `json:"sid"`
		FTR string `json:"ftr"`
		ARK string `json:"ark"`
		BFP string `json:"bfp"`
	}
	if json.Unmarshal(raw, &parsed) != nil {
		return TicketPayload{}, false
	}
	return TicketPayload{SID: parsed.SID, FTR: parsed.FTR, ARK: parsed.ARK, BFP: parsed.BFP}, true
}

var reBrowserVer = regexp.MustCompile(`(Chrome|CriOS|Edg|Firefox|Version)/(\d+)[\d.]*`)

// TicketShape is a log-safe structural summary of one ticket and the browser
// that minted it (lengths, ages and flag fields only, never the secrets).
func TicketShape(t TicketPayload, ua string, hdrs map[string]string, nowMS int64) string {
	var p []string
	f := strings.Split(t.FTR, "_")
	if len(f) >= 3 {
		age := "?"
		if ts, err := strconv.ParseInt(f[1], 10, 64); err == nil && ts > 0 {
			age = fmt.Sprintf("%ds", (nowMS-ts)/1000)
		}
		pow, tail := "", ""
		if at := strings.Index(t.FTR, "31ck_"); at >= 0 {
			rest := t.FTR[at+5:]
			if i := strings.Index(rest, "="); i >= 0 {
				pow, tail = rest[:i+1], rest[i+1:]
			} else {
				pow = rest
			}
		}
		p = append(p, fmt.Sprintf("ftr[h%d age=%s n=%s parts=%d pow%d tail=%s]", len(f[0]), age, f[2], len(f), len(pow), regexp.MustCompile(`\d+`).ReplaceAllString(tail, "N")))
	} else {
		p = append(p, fmt.Sprintf("ftr[len%d]", len(t.FTR)))
	}
	ark := strings.Split(t.ARK, "|")
	kv := []string{fmt.Sprintf("tok%d", len(ark[0]))}
	for _, a := range ark[1:] {
		k, v, _ := strings.Cut(a, "=")
		switch k {
		case "meta", "at", "rid", "ag", "sup", "r":
			kv = append(kv, k+"="+v)
		default:
			kv = append(kv, k)
		}
	}
	p = append(p, "ark["+strings.Join(kv, " ")+"]")
	p = append(p, fmt.Sprintf("bfp[len%d]", len(t.BFP)))
	bv := "?"
	if m := reBrowserVer.FindAllStringSubmatch(ua, -1); len(m) > 0 {
		bv = m[0][1] + "/" + m[0][2]
	}
	if strings.Contains(ua, "iPhone") || strings.Contains(ua, "Mobile") {
		bv += "-mobile"
	}
	p = append(p, "ua="+bv)
	for k, v := range hdrs {
		if strings.EqualFold(k, "sec-ch-ua") {
			p = append(p, "ch="+strings.Join(regexp.MustCompile(`v="(\d+)"`).FindAllString(v, -1), ","))
		}
	}
	return strings.Join(p, " ")
}

// FingerprintBrief is a log-safe ftr/ark/bfp summary (no full token).
func FingerprintBrief(t TicketPayload) string {
	flag := "ftr=?"
	if m := reFtrFlags.FindString(t.FTR); m != "" {
		flag = "ftr=" + m
	}
	region := "ark=?"
	if m := reArkRegion.FindStringSubmatch(t.ARK); len(m) > 1 {
		region = "ark=" + m[1]
		if strings.Contains(t.ARK, "sup=1") {
			region += ",sup=1"
		}
	}
	bfp := t.BFP
	if len(bfp) > 8 {
		bfp = bfp[:8]
	}
	return flag + " " + region + " bfp=" + bfp
}
