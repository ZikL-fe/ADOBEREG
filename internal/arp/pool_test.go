package arp

import (
	"testing"
	"time"
)

func TestConfigureRewritesLiveMaxUses(t *testing.T) {
	tp := NewTicketPool(nil)
	exp := time.Now().Add(time.Hour).UnixMilli()
	tp.byAcc["a"] = &PooledTicket{ID: "1", AccountID: "a", ARP: true, Uses: 1, MaxUses: 5, ExpiresAt: exp}
	tp.byAcc["b"] = &PooledTicket{ID: "2", AccountID: "b", ARP: true, Uses: 2, MaxUses: 5, ExpiresAt: exp}
	tp.Configure(2, time.Minute, 4)
	if tp.byAcc["a"] == nil || tp.byAcc["a"].MaxUses != 2 {
		t.Fatal("live ticket should adopt the new cap")
	}
	if _, ok := tp.byAcc["b"]; ok {
		t.Fatal("a ticket that already reached the new cap should be dropped")
	}
	if _, _, live := tp.Peek("a"); !live {
		t.Fatal("remaining ticket should still be live")
	}
}
