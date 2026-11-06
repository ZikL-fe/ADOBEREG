package mail

import (
	"net"
	"testing"
)

func TestBypassResolvesPublic(t *testing.T) {
	local, bypass := mailRoute()
	if !bypass {
		t.Skip("no fake-ip tunnel")
	}
	if local == nil {
		t.Fatal("tunnel is up but no physical exit")
	}
	got := resolveDirect("imap-mail.outlook.com", local)
	parsed := net.ParseIP(got)
	if parsed == nil || isFakeIP(parsed) {
		t.Fatalf("resolved %q via %s", got, local)
	}
}
