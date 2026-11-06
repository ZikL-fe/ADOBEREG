package mail

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseReMailSecret(t *testing.T) {
	cases := []struct{ secret, token string }{
		{"remail----st_550e8400", "st_550e8400"},
		{"remail|st_550e8400", "st_550e8400"},
		{"remail:st_550e8400", "st_550e8400"},
		{"remail://st_550e8400", "st_550e8400"},
		{"st_550e8400", "st_550e8400"},
	}
	for _, c := range cases {
		cred := Parse(c.secret)
		if cred.Provider != ProviderReMail {
			t.Fatalf("%q: provider = %q", c.secret, cred.Provider)
		}
		if cred.Token != c.token {
			t.Fatalf("%q: token = %q, want %q", c.secret, cred.Token, c.token)
		}
		if !cred.Ready() {
			t.Fatalf("%q: not ready", c.secret)
		}
		if got := cred.Format(); got != ReMailSecret(c.token) {
			t.Fatalf("%q: format = %q", c.secret, got)
		}
	}
}

func TestParseMicrosoftUnchanged(t *testing.T) {
	cred := Parse("pw----client----refresh----aux@x.com----auxpw")
	if cred.Provider != "" {
		t.Fatalf("provider = %q", cred.Provider)
	}
	if cred.ClientID != "client" || cred.Refresh != "refresh" || cred.AuxEmail != "aux@x.com" {
		t.Fatalf("parsed %+v", cred)
	}
	if !cred.Ready() {
		t.Fatal("microsoft credential should be ready")
	}
	if got := cred.Format(); got != "pw----client----refresh----aux@x.com----auxpw" {
		t.Fatalf("format = %q", got)
	}
	if cred.ReMailMailbox() {
		t.Fatal("microsoft row tagged as remail")
	}
	// A half-filled Microsoft row is not ready but must not look like ReMail.
	half := Parse("pw----client")
	if half.Ready() || half.ReMailMailbox() {
		t.Fatalf("half row ready=%v remail=%v", half.Ready(), half.ReMailMailbox())
	}
}

func TestSessionRoutesReMail(t *testing.T) {
	s, err := Open("someone@outlook.com", "remail----st_abc")
	if err != nil {
		t.Fatal(err)
	}
	if !s.ReMail() {
		t.Fatal("session should route to ReMail")
	}
	if s.NextAllowed().IsZero() == false {
		t.Fatal("throttle should start at zero")
	}
	next := time.Now().Add(30 * time.Second)
	s.setNextAllowed(next)
	if !s.NextAllowed().Equal(next) {
		t.Fatal("throttle not stored")
	}
	s.setNextAllowed(time.Now())
	if !s.NextAllowed().Equal(next) {
		t.Fatal("throttle must not move backwards")
	}
}

func TestReMailMessageID(t *testing.T) {
	for _, in := range []string{"remail:5012", "5012", " remail:5012 "} {
		if n, ok := ReMailMessageID(in); !ok || n != 5012 {
			t.Fatalf("%q -> %d,%v", in, n, ok)
		}
	}
	for _, in := range []string{"", "imap:INBOX:7", "remail:0", "remail:abc"} {
		if _, ok := ReMailMessageID(in); ok {
			t.Fatalf("%q should not parse", in)
		}
	}
}

func TestReMailMessageItem(t *testing.T) {
	m := ReMailMessage{
		ID: 9, Sender: "account-security-noreply@accountprotection.microsoft.com",
		Subject: "Microsoft account security code", BodyPreview: "Your security code is",
		VerificationCode: "829104", ReceivedAt: "2026-07-09T13:58:00Z",
	}
	it := m.item()
	if it.ID != "remail:9" {
		t.Fatalf("id = %q", it.ID)
	}
	if !strings.Contains(it.Preview, "829104") {
		t.Fatalf("preview lost the code: %q", it.Preview)
	}
	if it.ReceivedAt.UTC().Format(time.RFC3339) != "2026-07-09T13:58:00Z" {
		t.Fatalf("time = %v", it.ReceivedAt)
	}
}

func TestReMailErrorMapping(t *testing.T) {
	if err := remailError(401, []byte(`{"code":"credential_invalid","message":"token bad"}`)); !strings.Contains(err.Error(), "密钥") {
		t.Fatalf("401 mapped to %v", err)
	}
	if err := remailError(429, []byte(`{"message":"slow down"}`)); !strings.Contains(err.Error(), "频繁") {
		t.Fatalf("429 mapped to %v", err)
	}
	if err := remailError(422, []byte(`{"code":"insufficient_inventory","message":"no stock"}`)); !strings.Contains(err.Error(), "没货") {
		t.Fatalf("stock mapped to %v", err)
	}
	if err := remailError(503, nil); err != ErrReMailDown {
		t.Fatalf("503 mapped to %v", err)
	}
}

// TestReMailPickupLive talks to the real service when REMAIL_TEST_EMAIL and
// REMAIL_TEST_TOKEN are set; skipped otherwise.
func TestReMailPickupLive(t *testing.T) {
	email, token := os.Getenv("REMAIL_TEST_EMAIL"), os.Getenv("REMAIL_TEST_TOKEN")
	if email == "" || token == "" {
		t.Skip("REMAIL_TEST_EMAIL / REMAIL_TEST_TOKEN 没有设置")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	items, fetch, err := NewReMail("").Pickup(ctx, email, token)
	if err != nil {
		t.Fatalf("pickup: %v", err)
	}
	t.Logf("status=%s next=%s items=%d", fetch.LastStatus, fetch.NextFetchAllowedAt, len(items))
	for _, it := range items {
		t.Logf("%s | %s | %s", it.ReceivedAt.Format(time.RFC3339), it.From, it.Subject)
	}
}

// TestReMailProfileLive checks the API key when REMAIL_TEST_KEY is set.
func TestReMailProfileLive(t *testing.T) {
	key := os.Getenv("REMAIL_TEST_KEY")
	if key == "" {
		t.Skip("REMAIL_TEST_KEY 没有设置")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p, err := NewReMail(key).Profile(ctx)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	t.Logf("key=%s enabled=%v balance=%s remaining=%s", p.KeyPrefix, p.Enabled, p.Balance, p.RemainingQuota)
}
