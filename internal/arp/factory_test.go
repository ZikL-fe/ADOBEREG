package arp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAcquireFactoryRetriesEmptyPool(t *testing.T) {
	factoryRetryGap = 5 * time.Millisecond
	factoryRetryFor = 2 * time.Second
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"ok":false,"error":"票池为空"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"tickets":[{"id":"T1","token":"tok","maxUses":5}]}`))
	}))
	defer srv.Close()
	tk, err := AcquireFactory(context.Background(), srv.URL, "k")
	if err != nil {
		t.Fatal(err)
	}
	if tk.ID != "T1" || tk.Token != "tok" || tk.MaxUses != 5 {
		t.Fatalf("ticket = %+v", tk)
	}
	if hits.Load() != 3 {
		t.Fatalf("hits = %d", hits.Load())
	}
}

func TestAcquireFactoryDoesNotRetryRejectedKey(t *testing.T) {
	factoryRetryGap = 5 * time.Millisecond
	factoryRetryFor = 2 * time.Second
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"error":"bad"}`))
	}))
	defer srv.Close()
	_, err := AcquireFactory(context.Background(), srv.URL, "k")
	if err == nil {
		t.Fatal("expected error")
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d", hits.Load())
	}
}
