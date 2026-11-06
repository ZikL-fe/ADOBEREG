package activate

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"firefly-go/internal/mail"
)

func peekCodes(ctx context.Context, secret, email string) map[string]struct{} {
	out := map[string]struct{}{}
	sess, err := mail.Open(email, secret)
	if err != nil {
		return out
	}
	items, err := sess.List(ctx)
	if err != nil {
		return out
	}
	for _, item := range items {
		if code := ExtractCode(item.Subject + " " + item.Preview); code != "" {
			out[code] = struct{}{}
		}
	}
	return out
}

func waitCode(ctx context.Context, secret, email string, since time.Time, used map[string]struct{}, log func(string)) (string, error) {
	cred := mail.Parse(secret)
	if !cred.Ready() {
		return "", fmt.Errorf("收码小本本不完整")
	}
	if since.IsZero() {
		since = time.Now().Add(-90 * time.Second)
	}
	if used == nil {
		used = map[string]struct{}{}
	}
	// ReMail runs an upstream fetch job per mailbox, so the receive window is
	// longer than one IMAP read and the first code can take a while to land.
	deadline := time.Now().Add(120 * time.Second)
	if cred.ReMailMailbox() {
		deadline = time.Now().Add(300 * time.Second)
	}
	var lastErr error
	told := false
	// One session for the whole wait: ReMail keeps its pickup throttle
	// (nextFetchAllowedAt) on the session, a fresh one every round would forget it.
	sess, err := mail.Open(email, secret)
	if err != nil {
		return "", fmt.Errorf("收码信箱打不开")
	}
	for {
		items, err := sess.List(ctx)
		if err != nil {
			lastErr = err
			if !told && log != nil {
				told = true
				log("收件没读到：" + err.Error())
			}
		}
		if err == nil {
			for _, item := range items {
				if !mailLooksAdobe(item.From, item.Subject) {
					continue
				}
				if !item.ReceivedAt.IsZero() && item.ReceivedAt.Before(since) {
					continue
				}
				if code := ExtractCode(item.Subject + " " + item.Preview); code != "" {
					if _, seen := used[code]; seen {
						continue
					}
					return code, nil
				}
			}
			for i, item := range items {
				if i >= 8 || item.ID == "" {
					break
				}
				if !mailLooksAdobe(item.From, item.Subject) {
					continue
				}
				if !item.ReceivedAt.IsZero() && item.ReceivedAt.Before(since) {
					continue
				}
				detail, err := sess.Get(ctx, item.ID)
				if err != nil {
					continue
				}
				if code := ExtractCode(detail.Subject + "\n" + detail.Body); code != "" {
					if _, seen := used[code]; seen {
						continue
					}
					return code, nil
				}
			}
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return "", fmt.Errorf("验证码迟迟不来：%s", lastErr.Error())
			}
			return "", fmt.Errorf("验证码迟迟不来")
		}
		wait := 5 * time.Second
		// ReMail answers with fetch.nextFetchAllowedAt; going earlier is wasted.
		if next := sess.NextAllowed(); next.After(time.Now()) {
			if gap := time.Until(next) + 300*time.Millisecond; gap > wait {
				wait = gap
			}
		}
		if wait > 20*time.Second {
			wait = 20 * time.Second
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(wait):
		}
	}
}

func loginReferer(email, debugID string) string {
	state := `{"name":"access-token-flow","side":"popup","data":{"returnOrigin":"https://firefly.adobe.com","client_id":"` + fireflyID + `","relay":"` + debugID + `"}}`
	callback := imsHost + "/ims/adobeid/" + fireflyID + "/AdobeID/token?" + url.Values{
		"redirect_uri": {redirectURI}, "state": {state},
		"code_challenge_method": {"plain"}, "use_ms_for_expiry": {"false"},
	}.Encode()
	return authHost + "/en_US/deeplink.html?" + url.Values{
		"deeplink": {"ssofirst"}, "callback": {callback}, "client_id": {fireflyID},
		"scope": {fireflyScope}, "state": {state}, "relay": {debugID},
		"locale": {"en_US"}, "flow_type": {"token"}, "puser": {email},
		"idp_flow_type": {"login"}, "response_type": {"token"},
		"code_challenge_method": {"plain"}, "redirect_uri": {redirectURI},
		"use_ms_for_expiry": {"false"},
	}.Encode()
}

func cookiePoolLine(ctx context.Context, email string, sess *Session) string {
	ims := sess.Cookie("ims_sid")
	aux := sess.Cookie("aux_sid")
	if ims == "" {
		_, _ = send(ctx, sess, &tracker{}, "GET", "https://www.adobe.com/home", nil, susiClient, map[string]string{
			"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		})
		ims = sess.Cookie("ims_sid")
		aux = sess.Cookie("aux_sid")
	}
	if ims == "" {
		return ""
	}
	relay := ims
	if len(relay) > 48 {
		relay = relay[:48]
	}
	return email + "----relay=" + relay + "; ftrset=560; locale=en_US; ims_sid=" + ims + "; aux_sid=" + aux
}
