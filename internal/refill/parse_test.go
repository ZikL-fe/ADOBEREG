package refill

import (
	"strings"
	"testing"
)

func TestParseOwnMailboxLine(t *testing.T) {
	line := "A@Hotmail.com----pw1----9e5f94bc-e8a4-4e73-b8be-63364c29d753----M.C537_BAY.refresh$$----aux@mail.cat9mail.com----auxPW"
	email, secret, ok := ParseLine(line)
	if !ok || email != "a@hotmail.com" {
		t.Fatalf("email=%q ok=%v", email, ok)
	}
	c := ParseSecret(secret)
	if c.Password != "pw1" || c.ClientID != "9e5f94bc-e8a4-4e73-b8be-63364c29d753" || !strings.HasPrefix(c.Refresh, "M.C537") {
		t.Fatalf("cred=%+v", c)
	}
	if c.AuxEmail != "aux@mail.cat9mail.com" || c.AuxPassword != "auxPW" {
		t.Fatalf("aux=%q / %q", c.AuxEmail, c.AuxPassword)
	}
	s := Item{Email: email, Secret: secret}
	if !s.MailReady() || !s.HasAux() {
		t.Fatalf("ready flags")
	}
	// 4-part still works (no aux)
	_, sec2, ok2 := ParseLine("b@x.com----p----cid----rt")
	if !ok2 || !ParseSecret(sec2).Ready() || ParseSecret(sec2).HasAux() {
		t.Fatalf("4-part: %+v", ParseSecret(sec2))
	}
}
