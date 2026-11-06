// Package mail reads a sub-account mailbox. Two transports exist:
//
//   - Microsoft consumer mailboxes (Hotmail / Outlook) over IMAP XOAUTH2 or
//     Graph, using the refresh token stored with the sub-account;
//   - ReMail (remail.aishop6.com) delivered mailboxes, read over its open
//     pickup API with the service token that came with the order.
//
// Connections are always direct — no proxy — so Adobe exit IPs are never used.
package mail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrNoToken     = errors.New("这个邮箱没有刷新令牌")
	ErrNoClient    = errors.New("这个邮箱没有客户端编号")
	ErrRejected    = errors.New("刷新令牌被拒绝")
	ErrUnreachable = errors.New("邮箱服务器连不上")
	ErrNotFound    = errors.New("这封邮件不存在")
)

// Item is one inbox / junk row.
type Item struct {
	ID         string    `json:"id"`
	Subject    string    `json:"subject"`
	From       string    `json:"from"`
	ReceivedAt time.Time `json:"receivedAt"`
	Preview    string    `json:"preview"`
	Unread     bool      `json:"unread"`
}

// Detail is one opened message.
type Detail struct {
	Subject     string    `json:"subject"`
	From        string    `json:"from"`
	ReceivedAt  time.Time `json:"receivedAt"`
	ContentType string    `json:"contentType"` // text | html
	Body        string    `json:"body"`
}

// Credential is the mailbox half of a sub-account import line. Two shapes are
// supported: a Microsoft mailbox (password/clientId/refresh) and a ReMail
// delivered mailbox (Provider == ProviderReMail plus Token).
type Credential struct {
	Provider    string // "" = Microsoft IMAP/Graph, "remail" = token-only pickup
	Token       string // ReMail service token
	Password    string
	ClientID    string
	Refresh     string
	AuxEmail    string
	AuxPassword string
	sep         string
}

// Parse splits "password----clientId----refresh[----auxEmail----auxPassword]".
//
// A ReMail row may use any of these forms:
//
//	remail----st_xxx      remail|st_xxx      remail:st_xxx      st_xxx
func Parse(secret string) Credential {
	secret = strings.TrimSpace(secret)
	sep := "----"
	if !strings.Contains(secret, sep) && strings.Contains(secret, "|") {
		sep = "|"
	}
	c := Credential{sep: sep}
	for _, prefix := range []string{"remail://", "remail//", "remail:"} {
		if rest, ok := stripPrefixFold(secret, prefix); ok {
			c.Provider = ProviderReMail
			c.Token = strings.Trim(strings.TrimSpace(rest), "/")
			return c
		}
	}
	p := strings.Split(secret, sep)
	if len(p) > 0 {
		c.Password = strings.TrimSpace(p[0])
	}
	if len(p) > 1 {
		c.ClientID = strings.TrimSpace(p[1])
	}
	if len(p) > 2 {
		c.Refresh = strings.TrimSpace(p[2])
	}
	if len(p) > 3 {
		c.AuxEmail = strings.ToLower(strings.TrimSpace(p[3]))
	}
	if len(p) > 4 {
		c.AuxPassword = strings.TrimSpace(p[4])
	}
	if strings.EqualFold(c.Password, ProviderReMail) {
		c.Provider, c.Token = ProviderReMail, strings.TrimSpace(c.ClientID)
		c.Password, c.ClientID, c.Refresh = "", "", ""
		c.AuxEmail, c.AuxPassword = "", ""
		return c
	}
	if strings.HasPrefix(strings.ToLower(c.Password), "st_") {
		c.Provider, c.Token, c.Password = ProviderReMail, c.Password, ""
	}
	return c
}

// Format rebuilds the secret (rotated refresh is substituted in place).
func (c Credential) Format() string {
	if c.Provider == ProviderReMail {
		return ReMailSecret(c.Token)
	}
	sep := c.sep
	if sep == "" {
		sep = "----"
	}
	parts := []string{c.Password, c.ClientID, c.Refresh}
	if c.AuxEmail != "" || c.AuxPassword != "" {
		parts = append(parts, c.AuxEmail, c.AuxPassword)
	}
	return strings.Join(parts, sep)
}

// Ready reports whether the mailbox can be read at all: a ReMail row needs its
// service token, a Microsoft row needs clientId + refresh.
func (c Credential) Ready() bool {
	if c.Provider == ProviderReMail {
		return strings.TrimSpace(c.Token) != ""
	}
	return c.ClientID != "" && c.Refresh != ""
}

// ReMailMailbox reports whether this credential is a token-only ReMail row.
func (c Credential) ReMailMailbox() bool { return c.Provider == ProviderReMail }

func stripPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

// Session reads one mailbox with no proxy.
type Session struct {
	Email   string
	cred    Credential
	rotated bool

	mu     sync.Mutex
	nextAt time.Time // ReMail pickup throttle (fetch.nextFetchAllowedAt)
}

// Open builds a session. email is the mailbox address; secret is the stored
// credential half (password----clientId----refresh… or remail----token).
func Open(email, secret string) (*Session, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") {
		return nil, fmt.Errorf("邮箱地址不正确")
	}
	return &Session{Email: email, cred: Parse(secret)}, nil
}

func (s *Session) Secret() string         { return s.cred.Format() }
func (s *Session) Rotated() bool          { return s.rotated }
func (s *Session) Credential() Credential { return s.cred }

// ReMail reports whether this session reads over the ReMail open API.
func (s *Session) ReMail() bool { return s.cred.Provider == ProviderReMail }

// NextAllowed is the earliest moment ReMail accepts another pickup for this
// mailbox; zero means "now".
func (s *Session) NextAllowed() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextAt
}

func (s *Session) setNextAllowed(t time.Time) {
	if t.IsZero() {
		return
	}
	s.mu.Lock()
	if t.After(s.nextAt) {
		s.nextAt = t
	}
	s.mu.Unlock()
}

// List returns the newest messages from Inbox + Junk (max 40).
func (s *Session) List(ctx context.Context) ([]Item, error) {
	if s.ReMail() {
		return s.listReMail(ctx)
	}
	if access, err := s.accessKind(ctx, "imap"); err == nil {
		if items, err := s.listIMAP(ctx, access); err == nil {
			return items, nil
		}
	}
	if access, err := s.accessKind(ctx, "graph"); err == nil {
		return s.listGraph(ctx, access)
	}
	if s.cred.Password != "" {
		if items, err := s.listIMAP(ctx, ""); err == nil {
			return items, nil
		}
	}
	if s.cred.Refresh == "" {
		return nil, ErrNoToken
	}
	if s.cred.ClientID == "" {
		return nil, ErrNoClient
	}
	return nil, ErrRejected
}

// listReMail reads one mailbox over GET /v1/pickup (email + service token).
func (s *Session) listReMail(ctx context.Context) ([]Item, error) {
	if strings.TrimSpace(s.cred.Token) == "" {
		return nil, ErrNoPickup
	}
	items, fetch, err := NewReMail("").Pickup(ctx, s.Email, s.cred.Token)
	if err != nil {
		return nil, err
	}
	if next, ok := parseReMailTimeOK(fetch.NextFetchAllowedAt); ok {
		s.setNextAllowed(next)
	}
	sortItemsNewestFirst(items)
	if len(items) > 40 {
		items = items[:40]
	}
	return items, nil
}

// Get opens one message by its List id (imap:… / graph:… / remail:…).
func (s *Session) Get(ctx context.Context, id string) (Detail, error) {
	id = strings.TrimSpace(id)
	switch {
	case strings.HasPrefix(id, "imap:"):
		access, err := s.accessKind(ctx, "imap")
		if err != nil {
			if s.cred.Password == "" {
				return Detail{}, err
			}
			access = ""
		}
		return s.getIMAP(ctx, access, strings.TrimPrefix(id, "imap:"))
	case strings.HasPrefix(id, "graph:"):
		access, err := s.accessKind(ctx, "graph")
		if err != nil {
			return Detail{}, err
		}
		return s.getGraph(ctx, access, strings.TrimPrefix(id, "graph:"))
	case strings.HasPrefix(id, "remail:"):
		n, ok := ReMailMessageID(id)
		if !ok {
			return Detail{}, ErrNotFound
		}
		return s.getReMail(ctx, n)
	default:
		return Detail{}, ErrNotFound
	}
}

// getReMail reads one full body over GET /v1/pickup/messages/{id}.
func (s *Session) getReMail(ctx context.Context, id int64) (Detail, error) {
	if strings.TrimSpace(s.cred.Token) == "" {
		return Detail{}, ErrNoPickup
	}
	msg, err := NewReMail("").PickupMessage(ctx, s.Email, s.cred.Token, id)
	if err != nil {
		return Detail{}, err
	}
	body := strings.TrimSpace(msg.Body)
	if body == "" {
		body = strings.TrimSpace(msg.BodyPreview)
	}
	return Detail{
		Subject:     strings.TrimSpace(msg.Subject),
		From:        strings.TrimSpace(msg.Sender),
		ReceivedAt:  parseReMailTime(msg.ReceivedAt),
		ContentType: "text",
		Body:        body,
	}, nil
}

func (s *Session) do(ctx context.Context, req *http.Request) (*http.Response, error) {
	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, ErrUnreachable
	}
	return resp, nil
}

func readLimited(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, n))
}

func sortItemsNewestFirst(items []Item) {
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].ReceivedAt.After(items[i].ReceivedAt) {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
}
