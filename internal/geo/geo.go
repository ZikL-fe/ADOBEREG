// Package geo maps a proxy's exit country (the `region-XX` tag of the proxy
// username) onto the browser locale every fingerprint part must agree on:
// IANA time zone, navigator.languages and the Accept-Language header.
package geo

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata" // Windows hosts (SubActivator.exe) have no system zoneinfo
)

type Locale struct {
	Country string   // ISO-3166 alpha-2, upper case
	TZ      string   // IANA zone, e.g. America/New_York
	Langs   []string // navigator.languages, first = navigator.language
}

// Lang is navigator.language.
func (l Locale) Lang() string { return l.Langs[0] }

// AcceptLanguage renders navigator.languages the way Chrome does:
// "ja,en-US;q=0.9,en;q=0.8".
func (l Locale) AcceptLanguage() string {
	parts := make([]string, len(l.Langs))
	for i, lang := range l.Langs {
		if i == 0 {
			parts[i] = lang
			continue
		}
		q := 10 - i
		if q < 1 {
			q = 1
		}
		parts[i] = fmt.Sprintf("%s;q=0.%d", lang, q)
	}
	return strings.Join(parts, ",")
}

// Offset is JS Date.prototype.getTimezoneOffset() at t: minutes *behind* UTC
// (New York summer = 240, winter = 300; Tokyo = -540).
func (l Locale) Offset(t time.Time) int {
	loc, err := time.LoadLocation(l.TZ)
	if err != nil {
		return 0
	}
	_, sec := t.In(loc).Zone()
	return -sec / 60
}

// SandboxLocale is the voice / language preset of data/arksandbox/bda_sandbox.js.
func (l Locale) SandboxLocale() string {
	if l.Country == "JP" {
		return "jp"
	}
	return "us"
}

var table = map[string]Locale{
	"US": {TZ: "America/New_York", Langs: []string{"en-US", "en"}},
	"CA": {TZ: "America/Toronto", Langs: []string{"en-US", "en"}},
	"GB": {TZ: "Europe/London", Langs: []string{"en-GB", "en-US", "en"}},
	"AU": {TZ: "Australia/Sydney", Langs: []string{"en-AU", "en-US", "en"}},
	"SG": {TZ: "Asia/Singapore", Langs: []string{"en-US", "en"}},
	"IN": {TZ: "Asia/Kolkata", Langs: []string{"en-US", "en"}},
	"PH": {TZ: "Asia/Manila", Langs: []string{"en-US", "en"}},
	"MY": {TZ: "Asia/Kuala_Lumpur", Langs: []string{"en-US", "en"}},
	"JP": {TZ: "Asia/Tokyo", Langs: []string{"ja", "en-US", "en"}},
	"KR": {TZ: "Asia/Seoul", Langs: []string{"ko-KR", "ko", "en-US", "en"}},
	"TW": {TZ: "Asia/Taipei", Langs: []string{"zh-TW", "zh", "en-US", "en"}},
	"HK": {TZ: "Asia/Hong_Kong", Langs: []string{"zh-HK", "zh", "en-US", "en"}},
	"ID": {TZ: "Asia/Jakarta", Langs: []string{"id-ID", "id", "en-US", "en"}},
	"TH": {TZ: "Asia/Bangkok", Langs: []string{"th-TH", "th", "en-US", "en"}},
	"VN": {TZ: "Asia/Ho_Chi_Minh", Langs: []string{"vi-VN", "vi", "en-US", "en"}},
	"DE": {TZ: "Europe/Berlin", Langs: []string{"de-DE", "de", "en-US", "en"}},
	"FR": {TZ: "Europe/Paris", Langs: []string{"fr-FR", "fr", "en-US", "en"}},
	"NL": {TZ: "Europe/Amsterdam", Langs: []string{"nl-NL", "nl", "en-US", "en"}},
	"BR": {TZ: "America/Sao_Paulo", Langs: []string{"pt-BR", "pt", "en-US", "en"}},
}

// Default is the locale used when the proxy carries no (known) region tag.
var Default = ForCountry("US")

// ForCountry returns the locale of an ISO country code; unknown codes fall
// back to US (the historical behaviour).
func ForCountry(cc string) Locale {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	l, ok := table[cc]
	if !ok {
		cc, l = "US", table["US"]
	}
	l.Country = cc
	return l
}

var reRegion = regexp.MustCompile(`(?i)region-([a-z]{2})\b`)

// ForProxy reads the exit country from a proxy URL's `region-XX` tag.
func ForProxy(proxy string) Locale {
	if m := reRegion.FindStringSubmatch(proxy); len(m) > 1 {
		return ForCountry(m[1])
	}
	return Default
}
