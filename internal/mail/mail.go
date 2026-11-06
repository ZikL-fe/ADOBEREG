// Package mail reads a Microsoft consumer mailbox (Hotmail / Outlook) over
// IMAP XOAUTH2 or Graph, using the refresh token stored with the sub-account.
// Connections are always direct — no proxy — so Adobe exit IPs are never used.
package mail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// Credential is the mailbox half of a sub-account import line.
type Credential struct {
	Password    string
	ClientID    string
	Refresh     string
	AuxEmail    string
	AuxPassword string
	sep         string
}

// Parse splits "password----clientId----refresh[----auxEmail----auxPassword]".
func Parse(secret string) Credential {
	secret = strings.TrimSpace(secret)
	sep := "----"
	if !strings.Contains(secret, sep) && strings.Contains(secret, "|") {
		sep = "|"
	}
	p := strings.Split(secret, sep)
	c := Credential{sep: sep}
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
	return c
}

// Format rebuilds the secret (rotated refresh is substituted in place).
func (c Credential) Format() string {
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

func (c Credential) Ready() bool {
	return c.ClientID != "" && c.Refresh != ""
}

// Session reads one Microsoft mailbox with no proxy.
type Session struct {
	Email   string
	cred    Credential
	rotated bool
}

// Open builds a session. email is the Hotmail address; secret is the stored
// credential half (password----clientId----refresh...).
func Open(email, secret string) (*Session, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !strings.Contains(email, "@") {
		return nil, fmt.Errorf("邮箱地址不正确")
	}
	return &Session{Email: email, cred: Parse(secret)}, nil
}

func (s *Session) Secret() string { return s.cred.Format() }
func (s *Session) Rotated() bool  { return s.rotated }

// List returns the newest messages from Inbox + Junk (max 40).
func (s *Session) List(ctx context.Context) ([]Item, error) {
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

// Get opens one message by its List id (imap:… / graph:…).
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
	default:
		return Detail{}, ErrNotFound
	}
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
