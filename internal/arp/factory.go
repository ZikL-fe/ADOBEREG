package arp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"firefly-go/internal/transport"
)

// FactoryTicket is one ticket taken from the external mint service.
type FactoryTicket struct {
	ID      string
	Token   string
	Proxy   string
	UA      string
	Headers map[string]string
	MaxUses int
}

// Empty-pool replies are retried: the mint service scales browsers up only
// after a request arrives, so the first pull often lands before a ticket exists.
var (
	factoryRetryFor = 2 * time.Minute
	factoryRetryGap = 3 * time.Second
)

// AcquireFactory asks the backup mint service for one ticket.
// The returned proxy is the exit that minted the ticket, rewritten to socks5h.
// A temporary empty pool is polled until a ticket appears or the wait expires.
func AcquireFactory(ctx context.Context, base, key string) (FactoryTicket, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	key = strings.TrimSpace(key)
	if base == "" || key == "" {
		return FactoryTicket{}, fmt.Errorf("备用铸票系统未配置地址或密钥")
	}
	deadline := time.Now().Add(factoryRetryFor)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	var last error
	for {
		if err := ctx.Err(); err != nil {
			if last != nil {
				return FactoryTicket{}, last
			}
			return FactoryTicket{}, err
		}
		tk, err, retry := acquireFactoryOnce(ctx, base, key)
		if err == nil {
			return tk, nil
		}
		last = err
		if !retry || !time.Now().Before(deadline) {
			return FactoryTicket{}, last
		}
		timer := time.NewTimer(factoryRetryGap)
		select {
		case <-ctx.Done():
			timer.Stop()
			return FactoryTicket{}, last
		case <-timer.C:
		}
	}
}

func acquireFactoryOnce(ctx context.Context, base, key string) (FactoryTicket, error, bool) {
	body, _ := json.Marshal(map[string]int{"count": 1})
	reqCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, base+"/api/ticket/acquire", bytes.NewReader(body))
	if err != nil {
		return FactoryTicket{}, err, false
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return FactoryTicket{}, fmt.Errorf("备用铸票系统连不上"), true
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var ar struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Tickets []struct {
			ID      string            `json:"id"`
			Token   string            `json:"token"`
			Proxy   string            `json:"proxy"`
			UA      string            `json:"ua"`
			ARP     bool              `json:"arp"`
			MaxUses int               `json:"maxUses"`
			Headers map[string]string `json:"headers"`
		} `json:"tickets"`
	}
	_ = json.Unmarshal(raw, &ar)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return FactoryTicket{}, fmt.Errorf("备用铸票系统拒绝了密钥"), false
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		msg := clipFactoryErr(ar.Error, "超出配额")
		return FactoryTicket{}, fmt.Errorf("备用铸票系统返回 429：%s", msg), false
	}
	empty := resp.StatusCode == http.StatusServiceUnavailable || strings.Contains(ar.Error, "票池为空") || strings.Contains(ar.Error, "没有可用的票")
	if resp.StatusCode != http.StatusOK {
		if empty || resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusGatewayTimeout {
			return FactoryTicket{}, fmt.Errorf("备用铸票系统暂时没有票"), true
		}
		return FactoryTicket{}, fmt.Errorf("备用铸票系统返回 %d", resp.StatusCode), false
	}
	if !ar.OK || len(ar.Tickets) == 0 || ar.Tickets[0].Token == "" {
		msg := clipFactoryErr(ar.Error, "没有可用的票")
		retry := strings.Contains(msg, "票池为空") || strings.Contains(msg, "没有可用的票")
		if retry {
			msg = "暂时没有票"
		}
		return FactoryTicket{}, fmt.Errorf("备用铸票系统: %s", msg), retry
	}
	t := ar.Tickets[0]
	return FactoryTicket{
		ID:      t.ID,
		Token:   t.Token,
		Proxy:   transport.CanonProxy(t.Proxy),
		UA:      t.UA,
		Headers: t.Headers,
		MaxUses: t.MaxUses,
	}, nil, false
}

func clipFactoryErr(msg, fallback string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		msg = fallback
	}
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return msg
}
