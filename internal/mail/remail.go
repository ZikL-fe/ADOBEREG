package mail

// ReMail (https://remail.aishop6.com/docs) hands out mailboxes over HTTP
// instead of IMAP + OAuth, so a sub-account no longer needs a refresh token.
//
// Two halves matter here:
//
//	order   POST /v1/open/orders            Bearer rk-… key  -> deliveryEmail + serviceToken
//	pickup  GET  /v1/pickup?email=&token=   no key needed     -> messages + fetch state
//
// A mailbox is therefore stored as a normal account row with the secret
// "remail----<serviceToken>": ordering needs the API key, reading the inbox
// only needs the token that came with the order.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// ReMailBase is the documented production host.
	ReMailBase = "https://remail.aishop6.com"

	// ProviderReMail tags a credential that carries a ReMail service token.
	ProviderReMail = "remail"

	// remailSecretSep joins the provider tag and the service token.
	remailSecretSep = "----"
)

var (
	ErrReMailKey   = errors.New("没有填 ReMail 密钥")
	ErrReMailAuth  = errors.New("ReMail 密钥或取件凭证无效/过期")
	ErrReMailQuota = errors.New("ReMail 积分不够了")
	ErrReMailStock = errors.New("ReMail 这个后缀没货")
	ErrReMailBusy  = errors.New("ReMail 请求太频繁")
	ErrReMailDown  = errors.New("ReMail 服务暂时不可用")
	ErrNoPickup    = errors.New("这个邮箱没有 ReMail 取件凭证")
)

// ReMailHost resolves the API host, honouring REMAIL_BASE for a self-hosted
// mirror. Always without a trailing slash.
func ReMailHost() string {
	if v := strings.TrimSpace(os.Getenv("REMAIL_BASE")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return ReMailBase
}

// ReMailSecret builds the stored credential for a delivered mailbox.
func ReMailSecret(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	return ProviderReMail + remailSecretSep + token
}

var (
	remailOnce sync.Once
	remailHTTP *http.Client
)

func remailClient() *http.Client {
	remailOnce.Do(func() {
		remailHTTP = &http.Client{
			Timeout: 45 * time.Second,
			Transport: &http.Transport{
				ForceAttemptHTTP2:   true,
				MaxIdleConns:        16,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 15 * time.Second,
			},
		}
	})
	return remailHTTP
}

// ReMail is the open-API client. Key is only needed for orders / projects /
// wallet calls; pickup works with a service token alone.
type ReMail struct {
	Base string
	Key  string
	HTTP *http.Client
}

// NewReMail builds a client. An empty key still allows pickup.
func NewReMail(key string) *ReMail {
	return &ReMail{Base: ReMailHost(), Key: strings.TrimSpace(key), HTTP: remailClient()}
}

func (r *ReMail) Ready() bool { return r != nil && strings.TrimSpace(r.Key) != "" }

func (r *ReMail) endpoint(path string, query url.Values) string {
	base := strings.TrimRight(strings.TrimSpace(r.Base), "/")
	if base == "" {
		base = ReMailBase
	}
	out := base + path
	if len(query) > 0 {
		out += "?" + query.Encode()
	}
	return out
}

// send performs one request. Non-2xx answers become typed errors.
func (r *ReMail) send(ctx context.Context, method, path string, query url.Values, header map[string]string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.endpoint(path, query), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("user-agent", "puhao/1.0")
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	if key := strings.TrimSpace(r.Key); key != "" {
		req.Header.Set("authorization", "Bearer "+key)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	client := r.HTTP
	if client == nil {
		client = remailClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w：%s", ErrReMailDown, shortText(err.Error()))
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if readErr != nil {
			return nil, ErrReMailDown
		}
		return raw, nil
	}
	return nil, remailError(resp.StatusCode, raw)
}

func remailError(status int, raw []byte) error {
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &body)
	msg := shortText(body.Message)
	blob := strings.ToLower(body.Code + " " + body.Message)
	switch {
	case status == 401 || status == 403:
		return wrapMsg(ErrReMailAuth, msg)
	case status == 429:
		return wrapMsg(ErrReMailBusy, msg)
	case status >= 500:
		return wrapMsg(ErrReMailDown, msg)
	case strings.Contains(blob, "balance") || strings.Contains(blob, "quota") || strings.Contains(blob, "积分"):
		return wrapMsg(ErrReMailQuota, msg)
	case strings.Contains(blob, "inventory") || strings.Contains(blob, "stock") || strings.Contains(blob, "缺货") || strings.Contains(blob, "unavailable"):
		return wrapMsg(ErrReMailStock, msg)
	}
	if msg == "" {
		msg = "HTTP " + strconv.Itoa(status)
	}
	return fmt.Errorf("ReMail 拒绝：%s", msg)
}

func wrapMsg(base error, msg string) error {
	if msg == "" {
		return base
	}
	return fmt.Errorf("%w：%s", base, msg)
}

func shortText(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	rs := []rune(s)
	if len(rs) > 140 {
		return string(rs[:140]) + "…"
	}
	return s
}

// ReMailProfile is GET /v1/open/apikey/profile#apiKey.
type ReMailProfile struct {
	ID               int64  `json:"id"`
	Name             string `json:"name"`
	KeyPrefix        string `json:"keyPrefix"`
	Enabled          bool   `json:"enabled"`
	QuotaLimit       *int64 `json:"quotaLimit"`
	QuotaUsed        string `json:"quotaUsed"`
	RemainingQuota   string `json:"remainingQuota"`
	Balance          string `json:"balance"`
	RequestCount     int64  `json:"requestCount"`
	ActiveRequests   int    `json:"activeRequests"`
	ConcurrencyLimit *int   `json:"concurrencyLimit"`
	ExpireAt         string `json:"expireAt"`
}

func (r *ReMail) Profile(ctx context.Context) (ReMailProfile, error) {
	if !r.Ready() {
		return ReMailProfile{}, ErrReMailKey
	}
	raw, err := r.send(ctx, http.MethodGet, "/v1/open/apikey/profile", nil, nil, nil)
	if err != nil {
		return ReMailProfile{}, err
	}
	var out struct {
		APIKey ReMailProfile `json:"apiKey"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return ReMailProfile{}, ErrReMailDown
	}
	return out.APIKey, nil
}

// ReMailProduct is one sellable product row inside a project.
type ReMailProduct struct {
	Type            string `json:"type"`
	Status          string `json:"status"`
	CodeEnabled     bool   `json:"codeEnabled"`
	PurchaseEnabled bool   `json:"purchaseEnabled"`
	CodePrice       string `json:"codePrice"`
	PurchasePrice   string `json:"purchasePrice"`
	TotalAvailable  int64  `json:"totalAvailable"`
	PublicAvailable int64  `json:"publicAvailable"`
	CodeAvailable   int64  `json:"codeAvailable"`
}

// ReMailProject is one project (one service's mail rule + products).
type ReMailProject struct {
	ID         int64           `json:"id"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	AccessType string          `json:"accessType"`
	Products   []ReMailProduct `json:"products"`
}

func (r *ReMail) Projects(ctx context.Context, productType string, limit int) ([]ReMailProject, error) {
	if !r.Ready() {
		return nil, ErrReMailKey
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	q := url.Values{}
	q.Set("scope", "visible")
	q.Set("limit", strconv.Itoa(limit))
	if strings.TrimSpace(productType) != "" {
		q.Set("productType", strings.TrimSpace(productType))
	}
	raw, err := r.send(ctx, http.MethodGet, "/v1/open/projects", q, nil, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Items []ReMailProject `json:"items"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, ErrReMailDown
	}
	return out.Items, nil
}

// ReMailOrder mirrors the documented Order object (only the useful half).
type ReMailOrder struct {
	ID               int64  `json:"id"`
	OrderNo          string `json:"orderNo"`
	ProjectID        int64  `json:"projectId"`
	ProjectName      string `json:"projectName"`
	ProductType      string `json:"productType"`
	ServiceMode      string `json:"serviceMode"`
	Status           string `json:"status"`
	FailureCode      string `json:"failureCode"`
	PayAmount        string `json:"payAmount"`
	DeliveryEmail    string `json:"deliveryEmail"`
	ServiceToken     string `json:"serviceToken"`
	VerificationCode string `json:"verificationCode"`
	ReceiveUntil     string `json:"receiveUntil"`
	HasDelivery      bool   `json:"hasDelivery"`
	CreatedAt        string `json:"createdAt"`
}

// Delivered reports whether the order already carries a usable mailbox.
func (o ReMailOrder) Delivered() bool {
	return strings.Contains(o.DeliveryEmail, "@") && strings.TrimSpace(o.ServiceToken) != ""
}

func (o ReMailOrder) failed() bool {
	switch strings.ToLower(strings.TrimSpace(o.Status)) {
	case "failed", "refunded", "closed":
		return true
	}
	return false
}

func orderFailure(o ReMailOrder) error {
	code := strings.TrimSpace(o.FailureCode)
	switch code {
	case "insufficient_inventory":
		return ErrReMailStock
	case "insufficient_balance":
		return ErrReMailQuota
	case "service_token_failed", "activation_failed", "allocation_failed":
		return fmt.Errorf("ReMail 订单 %s 分配失败（%s）", o.OrderNo, code)
	case "":
		return fmt.Errorf("ReMail 订单 %s 变成了 %s", o.OrderNo, o.Status)
	}
	return fmt.Errorf("ReMail 订单 %s 失败：%s", o.OrderNo, code)
}

// Order creates one order. mode is "code" (short-lived receive window) or
// "purchase" (long-lived mailbox); suffix is the商品后缀 such as outlook.com,
// "outlook" / "domain" for stock-weighted random, or empty to let ReMail pick.
func (r *ReMail) Order(ctx context.Context, projectID int64, suffix, mode string) (ReMailOrder, error) {
	if !r.Ready() {
		return ReMailOrder{}, ErrReMailKey
	}
	if projectID <= 0 {
		return ReMailOrder{}, fmt.Errorf("先填 ReMail 项目编号")
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "purchase" {
		mode = "code"
	}
	// emailSuffix is mandatory; "outlook" makes ReMail pick a random Microsoft
	// suffix that still has stock, which is what a fresh Adobe account wants.
	suffix = strings.TrimSpace(suffix)
	if suffix == "" {
		suffix = "outlook"
	}
	q := url.Values{}
	q.Set("serviceMode", mode)
	q.Set("supply", "private_first")
	body := map[string]any{"projectId": projectID, "emailSuffix": suffix}
	header := map[string]string{"idempotency-key": idemKey()}
	raw, err := r.send(ctx, http.MethodPost, "/v1/open/orders", q, header, body)
	if err != nil {
		return ReMailOrder{}, err
	}
	var out ReMailOrder
	if err := json.Unmarshal(raw, &out); err != nil {
		return ReMailOrder{}, ErrReMailDown
	}
	return out, nil
}

// OrderStatus re-reads one order (delivery may land a moment later).
func (r *ReMail) OrderStatus(ctx context.Context, orderNo string) (ReMailOrder, error) {
	orderNo = strings.TrimSpace(orderNo)
	if orderNo == "" {
		return ReMailOrder{}, fmt.Errorf("订单号是空的")
	}
	raw, err := r.send(ctx, http.MethodGet, "/v1/open/orders/"+url.PathEscape(orderNo), nil, nil, nil)
	if err != nil {
		return ReMailOrder{}, err
	}
	var out ReMailOrder
	if err := json.Unmarshal(raw, &out); err != nil {
		return ReMailOrder{}, ErrReMailDown
	}
	return out, nil
}

// WaitDelivery polls an order until ReMail hands over the address + token.
func (r *ReMail) WaitDelivery(ctx context.Context, ord ReMailOrder, wait time.Duration) (ReMailOrder, error) {
	if ord.Delivered() {
		return ord, nil
	}
	if wait <= 0 {
		wait = 90 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		if ord.failed() {
			return ord, orderFailure(ord)
		}
		if ord.OrderNo != "" {
			cur, err := r.OrderStatus(ctx, ord.OrderNo)
			if err == nil {
				ord = cur
				if ord.Delivered() {
					return ord, nil
				}
			}
		}
		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return ord, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	if ord.Delivered() {
		return ord, nil
	}
	if ord.failed() {
		return ord, orderFailure(ord)
	}
	return ord, fmt.Errorf("ReMail 订单 %s 一直没交付邮箱（%s）", ord.OrderNo, ord.Status)
}

// ReMailFetch is the pickup job state ReMail reports for one mailbox.
type ReMailFetch struct {
	LastStatus         string `json:"lastStatus"`
	NextFetchAllowedAt string `json:"nextFetchAllowedAt"`
	LastReceivedAt     string `json:"lastReceivedAt"`
	LastSafeError      string `json:"lastSafeError"`
}

// ReMailMessage is one pickup message / message detail.
type ReMailMessage struct {
	ID               int64  `json:"id"`
	Sender           string `json:"sender"`
	Recipient        string `json:"recipient"`
	ReceivedAt       string `json:"receivedAt"`
	Subject          string `json:"subject"`
	BodyPreview      string `json:"bodyPreview"`
	VerificationCode string `json:"verificationCode"`
	Body             string `json:"body"`
}

func (m ReMailMessage) item() Item {
	it := Item{
		From:       strings.TrimSpace(m.Sender),
		Subject:    strings.TrimSpace(m.Subject),
		Preview:    strings.TrimSpace(m.BodyPreview),
		ReceivedAt: parseReMailTime(m.ReceivedAt),
	}
	if code := strings.TrimSpace(m.VerificationCode); code != "" && !strings.Contains(it.Preview, code) {
		it.Preview = strings.TrimSpace(it.Preview + " " + code)
	}
	if m.ID > 0 {
		it.ID = "remail:" + strconv.FormatInt(m.ID, 10)
	}
	return it
}

// Pickup reads the newest messages of one delivered mailbox. Neither an API
// key nor the mailbox password is involved: email + serviceToken are enough.
func (r *ReMail) Pickup(ctx context.Context, email, token string) ([]Item, ReMailFetch, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	token = strings.TrimSpace(token)
	if email == "" || token == "" {
		return nil, ReMailFetch{}, ErrNoPickup
	}
	q := url.Values{}
	q.Set("email", email)
	q.Set("token", token)
	raw, err := r.send(ctx, http.MethodGet, "/v1/pickup", q, nil, nil)
	if err != nil {
		return nil, ReMailFetch{}, err
	}
	var out struct {
		Items []ReMailMessage `json:"items"`
		Fetch ReMailFetch     `json:"fetch"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, ReMailFetch{}, ErrReMailDown
	}
	items := make([]Item, 0, len(out.Items))
	for _, m := range out.Items {
		items = append(items, m.item())
	}
	return items, out.Fetch, nil
}

// PickupMessage reads one full message body.
func (r *ReMail) PickupMessage(ctx context.Context, email, token string, id int64) (ReMailMessage, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	token = strings.TrimSpace(token)
	if email == "" || token == "" {
		return ReMailMessage{}, ErrNoPickup
	}
	if id <= 0 {
		return ReMailMessage{}, ErrNotFound
	}
	q := url.Values{}
	q.Set("email", email)
	q.Set("token", token)
	raw, err := r.send(ctx, http.MethodGet, "/v1/pickup/messages/"+strconv.FormatInt(id, 10), q, nil, nil)
	if err != nil {
		// Keep the credential / availability errors, only a plain "gone" answer
		// becomes ErrNotFound.
		if errors.Is(err, ErrReMailAuth) || errors.Is(err, ErrReMailDown) || errors.Is(err, ErrReMailBusy) {
			return ReMailMessage{}, err
		}
		return ReMailMessage{}, ErrNotFound
	}
	var out ReMailMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return ReMailMessage{}, ErrReMailDown
	}
	return out, nil
}

// ReMailMessageID unwraps "remail:5012" (or a bare number) into the API id.
func ReMailMessageID(id string) (int64, bool) {
	id = strings.TrimSpace(id)
	id = strings.TrimPrefix(id, "remail:")
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func parseReMailTime(s string) time.Time {
	t, ok := parseReMailTimeOK(s)
	if !ok {
		return time.Time{}
	}
	return t
}

func parseReMailTimeOK(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func idemKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// PickupSession opens a token-only reader for one delivered mailbox.
func PickupSession(email, token string) *Session {
	s, err := Open(email, ReMailSecret(token))
	if err != nil || s == nil {
		return nil
	}
	return s
}
