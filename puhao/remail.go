package main

// ReMail 接入层：从 remail.aishop6.com 的开放 API 拉邮箱，然后把邮箱当成本地
// 待注册账号入池。读信走 internal/mail 的 pickup 通道（只需要 serviceToken）。

import (
	"context"
	"fmt"
	"strings"
	"time"

	"firefly-go/internal/activate"
	"firefly-go/internal/mail"
)

// remailClient builds a client from settings (API key + optional custom host).
func remailClient(set Settings) *mail.ReMail {
	c := mail.NewReMail(set.ReMailKey)
	if base := strings.TrimSpace(set.ReMailBase); base != "" {
		c.Base = base
	}
	return c
}

// remailProjectFor resolves the project to order from: the configured id, or
// the first listed project that has an enabled product for the chosen mode.
func remailProjectFor(ctx context.Context, c *mail.ReMail, set Settings) (int64, string, error) {
	if set.ReMailProject > 0 {
		return set.ReMailProject, "", nil
	}
	projects, err := c.Projects(ctx, "", 100)
	if err != nil {
		return 0, "", err
	}
	mode := strings.ToLower(strings.TrimSpace(set.ReMailMode))
	for _, p := range projects {
		if p.Status != "" && p.Status != "listed" {
			continue
		}
		for _, prod := range p.Products {
			if prod.Status == "disabled" {
				continue
			}
			if mode == "purchase" {
				if prod.PurchaseEnabled {
					return p.ID, p.Name, nil
				}
				continue
			}
			if prod.CodeEnabled {
				return p.ID, p.Name, nil
			}
		}
	}
	return 0, "", fmt.Errorf("ReMail 里没找到可下单的项目，手动填项目编号")
}

// PullReMail orders n mailboxes and stores them as pending accounts. A single
// failed order does not discard the ones that worked.
func (e *Engine) PullReMail(n int, set Settings) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	c := remailClient(set)
	if !c.Ready() {
		return 0, mail.ErrReMailKey
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(n)*3*time.Minute+2*time.Minute)
	defer cancel()
	projectID, name, err := remailProjectFor(ctx, c, set)
	if err != nil {
		return 0, err
	}
	suffix := strings.TrimSpace(set.ReMailSuffix)
	mode := strings.ToLower(strings.TrimSpace(set.ReMailMode))
	if mode != "purchase" {
		mode = "code"
	}
	tag := "项目 " + itoa(int(projectID))
	if name != "" {
		tag += " " + name
	}
	e.log("info", "ReMail 下单 "+itoa(n)+" 个："+tag+"，后缀 "+suffixOrAuto(suffix)+"，"+mode)

	lines := make([]parsedLine, 0, n)
	var firstErr error
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		ord, err := c.Order(ctx, projectID, suffix, mode)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			break
		}
		ord, err = c.WaitDelivery(ctx, ord, 90*time.Second)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		email := strings.ToLower(strings.TrimSpace(ord.DeliveryEmail))
		token := strings.TrimSpace(ord.ServiceToken)
		lines = append(lines, parsedLine{email: email, secret: mail.ReMailSecret(token)})
		e.log("ok", "ReMail 交付 "+email+"（订单 "+ord.OrderNo+"）")
	}
	if len(lines) == 0 {
		if firstErr != nil {
			return 0, firstErr
		}
		return 0, fmt.Errorf("ReMail 一个邮箱也没拿到")
	}
	added, _ := e.store.Import(lines, set.Country)
	if firstErr != nil {
		e.log("warn", "ReMail 有一单没成："+firstErr.Error())
	}
	return added, nil
}

func suffixOrAuto(suffix string) string {
	if strings.TrimSpace(suffix) == "" {
		return "自动"
	}
	return suffix
}

// remailProbe checks the key and reports quota + the project that would be
// used, so the UI can show whether ordering is possible right now.
func remailProbe(ctx context.Context, set Settings) (map[string]any, error) {
	c := remailClient(set)
	if !c.Ready() {
		return nil, mail.ErrReMailKey
	}
	prof, err := c.Profile(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"keyPrefix":      prof.KeyPrefix,
		"enabled":        prof.Enabled,
		"balance":        prof.Balance,
		"remainingQuota": prof.RemainingQuota,
		"quotaUsed":      prof.QuotaUsed,
		"requestCount":   prof.RequestCount,
	}
	projects, err := c.Projects(ctx, "", 50)
	if err != nil {
		out["projectError"] = err.Error()
		return out, nil
	}
	list := make([]map[string]any, 0, len(projects))
	for _, p := range projects {
		row := map[string]any{"id": p.ID, "name": p.Name, "status": p.Status, "accessType": p.AccessType}
		prod := make([]map[string]any, 0, len(p.Products))
		for _, it := range p.Products {
			prod = append(prod, map[string]any{
				"type": it.Type, "status": it.Status,
				"codeEnabled": it.CodeEnabled, "purchaseEnabled": it.PurchaseEnabled,
				"codePrice": it.CodePrice, "purchasePrice": it.PurchasePrice,
				"available": it.TotalAvailable,
			})
		}
		row["products"] = prod
		list = append(list, row)
	}
	out["projects"] = list
	if id, name, err := remailProjectFor(ctx, c, set); err == nil {
		out["project"] = map[string]any{"id": id, "name": name}
	} else {
		out["projectError"] = err.Error()
	}
	return out, nil
}

// remailPreview pulls the newest messages of one stored mailbox (token only).
func remailPreview(ctx context.Context, set Settings, acc Account) ([]map[string]any, error) {
	cred := mail.Parse(acc.Secret)
	if !cred.ReMailMailbox() {
		return nil, fmt.Errorf("这个邮箱不是 ReMail 取件邮箱")
	}
	c := remailClient(set)
	items, fetch, err := c.Pickup(ctx, acc.Email, cred.Token)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{
			"id": it.ID, "from": it.From, "subject": it.Subject,
			"preview": it.Preview, "receivedAt": it.ReceivedAt,
			"code": activate.ExtractCode(it.Subject + " " + it.Preview),
		})
	}
	if len(out) > 10 {
		out = out[:10]
	}
	_ = fetch
	return out, nil
}
