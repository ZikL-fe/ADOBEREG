package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

const imapHost = "imap-mail.outlook.com"
const imapAddr = imapHost + ":993"

var imapFolders = []string{"INBOX", "Junk", "Spam"}

func (s *Session) listIMAP(ctx context.Context, access string) ([]Item, error) {
	c, err := s.imapDial(ctx, access)
	if err != nil {
		return nil, err
	}
	defer c.Logout()

	var items []Item
	seen := map[string]struct{}{}
	for _, folder := range imapFolders {
		mbox, err := c.Select(folder, true)
		if err != nil || mbox == nil || mbox.Messages == 0 {
			continue
		}
		from := uint32(1)
		if mbox.Messages > 20 {
			from = mbox.Messages - 19
		}
		seq := new(imap.SeqSet)
		seq.AddRange(from, mbox.Messages)
		ch := make(chan *imap.Message, 20)
		done := make(chan error, 1)
		go func() {
			done <- c.Fetch(seq, []imap.FetchItem{imap.FetchEnvelope, imap.FetchUid, imap.FetchFlags}, ch)
		}()
		for msg := range ch {
			if msg == nil || msg.Envelope == nil || msg.Uid == 0 {
				continue
			}
			id := "imap:" + folder + ":" + strconv.FormatUint(uint64(msg.Uid), 10)
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			items = append(items, Item{
				ID: id, Subject: msg.Envelope.Subject, From: formatAddress(msg.Envelope.From),
				ReceivedAt: msg.Envelope.Date.UTC(), Unread: !hasFlag(msg.Flags, imap.SeenFlag),
			})
		}
		<-done
	}
	sortItemsNewestFirst(items)
	if len(items) > 40 {
		items = items[:40]
	}
	return items, nil
}

func (s *Session) getIMAP(ctx context.Context, access, id string) (Detail, error) {
	folder, uid, ok := parseIMAPID(id)
	if !ok {
		return Detail{}, ErrNotFound
	}
	c, err := s.imapDial(ctx, access)
	if err != nil {
		return Detail{}, err
	}
	defer c.Logout()
	if _, err := c.Select(folder, true); err != nil {
		return Detail{}, ErrUnreachable
	}
	seq := new(imap.SeqSet)
	seq.AddNum(uid)
	section := &imap.BodySectionName{Peek: true}
	ch := make(chan *imap.Message, 1)
	done := make(chan error, 1)
	go func() {
		done <- c.UidFetch(seq, []imap.FetchItem{section.FetchItem(), imap.FetchEnvelope}, ch)
	}()
	var msg *imap.Message
	for item := range ch {
		msg = item
	}
	if err := <-done; err != nil {
		return Detail{}, ErrUnreachable
	}
	if msg == nil {
		return Detail{}, ErrNotFound
	}
	literal := msg.GetBody(section)
	if literal == nil {
		return Detail{}, ErrNotFound
	}
	raw, err := io.ReadAll(io.LimitReader(literal, 1<<20))
	if err != nil {
		return Detail{}, ErrUnreachable
	}
	parsed, err := parseRFC822(raw)
	if err != nil {
		return Detail{}, ErrUnreachable
	}
	if parsed.Subject == "" && msg.Envelope != nil {
		parsed.Subject = msg.Envelope.Subject
	}
	if parsed.From == "" && msg.Envelope != nil {
		parsed.From = formatAddress(msg.Envelope.From)
	}
	if parsed.ReceivedAt.IsZero() && msg.Envelope != nil {
		parsed.ReceivedAt = msg.Envelope.Date.UTC()
	}
	return Detail{
		Subject: parsed.Subject, From: parsed.From, ReceivedAt: parsed.ReceivedAt,
		ContentType: parsed.ContentType, Body: parsed.Body,
	}, nil
}

func parseIMAPID(id string) (folder string, uid uint32, ok bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", 0, false
	}
	if i := strings.LastIndex(id, ":"); i > 0 {
		folder = id[:i]
		n, err := strconv.ParseUint(id[i+1:], 10, 32)
		if err == nil && n > 0 && folder != "" {
			return folder, uint32(n), true
		}
	}
	n, err := strconv.ParseUint(id, 10, 32)
	if err != nil || n == 0 {
		return "", 0, false
	}
	return "INBOX", uint32(n), true
}

func (s *Session) imapDial(ctx context.Context, access string) (*client.Client, error) {
	raw, err := dialDirect(ctx, "tcp", imapAddr)
	if err != nil {
		return nil, ErrUnreachable
	}
	tlsConn := tls.Client(raw, &tls.Config{ServerName: imapHost})
	handshake := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(handshake) {
		handshake = dl
	}
	_ = tlsConn.SetDeadline(handshake)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tlsConn.Close()
		return nil, ErrUnreachable
	}
	c, err := client.New(tlsConn)
	_ = tlsConn.SetDeadline(time.Time{})
	if err != nil {
		tlsConn.Close()
		return nil, ErrUnreachable
	}
	c.Timeout = 20 * time.Second
	if access == "" {
		if err := c.Login(s.Email, s.cred.Password); err != nil {
			c.Logout()
			return nil, ErrNoToken
		}
		return c, nil
	}
	if err := c.Authenticate(xoauth2{user: s.Email, token: access}); err != nil {
		c.Logout()
		return nil, ErrRejected
	}
	return c, nil
}

type xoauth2 struct {
	user  string
	token string
}

func (x xoauth2) Start() (string, []byte, error) {
	raw := fmt.Sprintf("user=%s\x01auth=Bearer %s\x01\x01", x.user, x.token)
	return "XOAUTH2", []byte(raw), nil
}

func (x xoauth2) Next([]byte) ([]byte, error) {
	return nil, errors.New("xoauth2: done")
}

func formatAddress(list []*imap.Address) string {
	if len(list) == 0 || list[0] == nil {
		return ""
	}
	addr := list[0]
	mailbox := strings.TrimSpace(addr.MailboxName + "@" + addr.HostName)
	name := strings.TrimSpace(addr.PersonalName)
	if name == "" {
		return mailbox
	}
	if mailbox == "@" || mailbox == "" {
		return name
	}
	return name + " <" + mailbox + ">"
}

func hasFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if strings.EqualFold(flag, want) {
			return true
		}
	}
	return false
}
