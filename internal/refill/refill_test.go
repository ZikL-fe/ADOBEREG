package refill

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestParseLine(t *testing.T) {
	cases := []struct {
		in, email, secret string
		ok                bool
	}{
		{"A@Hotmail.com----pw----cid----rt", "a@hotmail.com", "pw----cid----rt", true},
		{"a@x.com|pw|cid|rt", "a@x.com", "pw----cid----rt", true},
		{"a@x.com", "a@x.com", "", true},
		{"  ", "", "", false},
		{"# comment", "", "", false},
		{"not-an-email----pw", "", "", false},
		{"a b@x.com----pw", "", "", false},
	}
	for _, c := range cases {
		e, s, ok := ParseLine(c.in)
		if e != c.email || s != c.secret || ok != c.ok {
			t.Fatalf("%q => %q %q %v, want %q %q %v", c.in, e, s, ok, c.email, c.secret, c.ok)
		}
	}
}

func TestManagerLifecycle(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	a, u, bad := m.Import("a@x.com----pw----cid----rt\nb@x.com\nbroken\na@x.com----pw----cid----rt2", "sg")
	if a != 2 || u != 1 || bad != 1 {
		t.Fatalf("import added=%d updated=%d invalid=%d", a, u, bad)
	}
	items, total := m.List(Filter{}, 1, 10)
	if total != 2 || len(items) != 2 {
		t.Fatalf("list total=%d", total)
	}
	var withMail, without Item
	for _, s := range items {
		if s.Email == "a@x.com" {
			withMail = s
		} else {
			without = s
		}
	}
	if !withMail.MailReady() || without.MailReady() || withMail.Country != "SG" {
		t.Fatalf("mail ready flags wrong: %+v / %+v", withMail, without)
	}
	if withMail.Profile == "" || withMail.Profile == without.Profile {
		t.Fatalf("each sub must own a distinct device profile: %q %q", withMail.Profile, without.Profile)
	}
	m.Update(withMail.ID, func(s *Item) { s.Status = StatusRunning })
	if n := m.Delete([]string{withMail.ID}); n != 0 {
		t.Fatalf("a running sub must not be deleted")
	}
	m.Update(withMail.ID, func(s *Item) { s.Status, s.Cookie = StatusActivated, "c" })
	if s, _ := m.Get(withMail.ID); !s.HasCookie {
		t.Fatalf("HasCookie must follow Cookie")
	}
	m.Flush()

	// restart: a "running" row must come back as failed, identity kept
	m.Update(without.ID, func(s *Item) { s.Status = StatusRunning })
	m.Flush()
	m2, err := Open(db)
	if err != nil {
		t.Fatal(err)
	}
	s2, ok := m2.Get(without.ID)
	if !ok || s2.Status != StatusFailed || s2.Profile != without.Profile {
		t.Fatalf("after reopen: %+v", s2)
	}
	if sum := m2.Summary(); sum.Total != 2 || sum.Activated != 1 || sum.Failed != 1 {
		t.Fatalf("summary %+v", sum)
	}
	if n := m2.Delete([]string{without.ID}); n != 1 {
		t.Fatalf("delete = %d", n)
	}
	m2.Flush()
	if _, total := m2.List(Filter{Status: "failed"}, 1, 10); total != 0 {
		t.Fatalf("failed total = %d", total)
	}
}
