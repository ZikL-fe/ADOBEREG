package arp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firefly-go/internal/config"
	"firefly-go/internal/geo"

	"golang.org/x/sync/singleflight"
)

// DefaultClientHints matches the Chrome 150.0.7871.115 worker that minted a
// working 著票 ticket, including the high-entropy hints that worker sends.
var DefaultClientHints = map[string]string{
	"sec-ch-ua":                   config.SecCHUA,
	"sec-ch-ua-arch":              config.SecCHUAArch,
	"sec-ch-ua-bitness":           config.SecCHUABitness,
	"sec-ch-ua-full-version":      config.SecCHUAFullVersion,
	"sec-ch-ua-full-version-list": config.SecCHUAFullVersionList,
	"sec-ch-ua-mobile":            config.SecCHUAMobile,
	"sec-ch-ua-model":             config.SecCHUAModel,
	"sec-ch-ua-platform":          config.SecCHUAPlatform,
	"sec-ch-ua-platform-version":  config.SecCHUAPlatformVersion,
}

type PooledTicket struct {
	ID         string            `json:"id"`
	Token      string            `json:"token"`
	Uses       int               `json:"uses"`
	MaxUses    int               `json:"maxUses"`
	ConsecFail int               `json:"consecFail"`
	ExpiresAt  int64             `json:"expiresAt"`
	CreatedAt  int64             `json:"createdAt"`
	MintMS     int64             `json:"mintMs"`
	Region     string            `json:"region"`
	ARP        bool              `json:"arp"`
	UA         string            `json:"ua"`
	Headers    map[string]string `json:"headers"`
	Proxy      string            `json:"proxy"`
	Source     string            `json:"source"` // always "local_sandbox" (protocol-computed)
	AccountID  string            `json:"accountId,omitempty"`
	ProfileID  string            `json:"profileId,omitempty"`
}

// TicketPool keeps ARP tickets. Local tickets are strictly bound 1:1 to an
// account: minted with that account's device profile on a fresh, unique proxy
// SID, reused only by that account (max N times, until the SID expires) and
// never handed to another account.
type TicketPool struct {
	mu     sync.Mutex
	minter *Minter
	byAcc  map[string]*PooledTicket
	sf     singleflight.Group
	seq    atomic.Uint64

	maxUses     int
	maxFailDrop int
	ttl         time.Duration

	mintLimit  atomic.Int32
	mintActive atomic.Int32
	MintCount  atomic.Int64
	MintFail   atomic.Int64
	MintTotMS  atomic.Int64

	// Optional hooks for stable-session mode (wired by fireflyd).
	// ResolveReuse returns pinned ARP/proxy identity for an account; empty = fresh.
	ResolveReuse func(accID string) MintReuse
	// Remember persists the identity actually used after a successful mint.
	Remember func(accID string, used MintReuse)

	// Factory, when it reports On, replaces local mint with the backup service.
	Factory func() FactorySpec
}

// FactorySpec selects the backup mint service. On false keeps local Sherlock.
type FactorySpec struct {
	On   bool
	Base string
	Key  string
}

func NewTicketPool(minter *Minter) *TicketPool {
	tp := &TicketPool{
		minter:      minter,
		byAcc:       map[string]*PooledTicket{},
		maxUses:     5,
		maxFailDrop: 2,
		ttl:         8 * time.Minute,
	}
	tp.mintLimit.Store(24)
	return tp
}

func (tp *TicketPool) Configure(maxUses int, ttl time.Duration, mintLimit int) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if maxUses > 0 {
		tp.maxUses = maxUses
		for id, t := range tp.byAcc {
			t.MaxUses = maxUses
			if t.Uses >= t.MaxUses {
				delete(tp.byAcc, id)
			}
		}
	}
	if ttl > 0 {
		tp.ttl = ttl
	}
	if mintLimit > 0 {
		tp.mintLimit.Store(int32(mintLimit))
	}
}

func liveLocked(t *PooledTicket, nowMS int64, minLeftMS int64) bool {
	return t != nil && t.ARP && t.Uses < t.MaxUses && t.ExpiresAt-nowMS > minLeftMS
}

// HasLive reports whether the account owns a ticket that can still serve a call.
func (tp *TicketPool) HasLive(accID string) bool {
	_, _, live := tp.Peek(accID)
	return live
}

// Peek reports how many times a live ticket has already been used.
func (tp *TicketPool) Peek(accID string) (uses, maxUses int, live bool) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	t := tp.byAcc[accID]
	if !liveLocked(t, time.Now().UnixMilli(), 45_000) {
		return 0, 0, false
	}
	return t.Uses, t.MaxUses, true
}

// AcquireForAccount returns the account's own ticket (mint on demand).
func (tp *TicketPool) AcquireForAccount(ctx context.Context, accID, seed, baseProxy string) (*PooledTicket, error) {
	if t := tp.take(accID); t != nil {
		return t, nil
	}
	if err := tp.MintFor(ctx, accID, seed, baseProxy); err != nil {
		return nil, err
	}
	if t := tp.take(accID); t != nil {
		return t, nil
	}
	return nil, fmt.Errorf("ticket vanished after mint")
}

func (tp *TicketPool) take(accID string) *PooledTicket {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	t := tp.byAcc[accID]
	if !liveLocked(t, time.Now().UnixMilli(), 20_000) {
		delete(tp.byAcc, accID)
		return nil
	}
	t.Uses++
	c := *t
	return &c
}

// MintFor mints (once per account at a time) a fresh ticket for the account.
func (tp *TicketPool) MintFor(ctx context.Context, accID, seed, baseProxy string) error {
	_, err, _ := tp.sf.Do(accID, func() (any, error) {
		// bounded concurrent mints so a burst never starves the server
		for {
			if tp.mintActive.Add(1) <= tp.mintLimit.Load() {
				break
			}
			tp.mintActive.Add(-1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(150 * time.Millisecond):
			}
		}
		defer tp.mintActive.Add(-1)

		// Backup-service tickets are minted for firefly.adobe.com, so an
		// Express site always mints its own.
		if tp.Factory != nil && !config.ExpressSite() {
			spec := tp.Factory()
			if spec.On {
				return nil, tp.storeFactory(ctx, accID, spec)
			}
		}
		prof := tp.minter.Profiles.For(seed)
		var reuse MintReuse
		if tp.ResolveReuse != nil {
			reuse = tp.ResolveReuse(accID)
		}
		report, err := tp.minter.MintPure(ctx, "", strings.TrimSpace(baseProxy), config.DefaultUserAgent, prof, &reuse)
		if err != nil || !report.OK {
			tp.MintFail.Add(1)
			return nil, fmt.Errorf("mint arp failed: err=%v gaps=%v ark=%s", err, report.Shape.Gaps, report.Ark.Error)
		}
		hdrs := make(map[string]string, len(DefaultClientHints)+1)
		for k, v := range DefaultClientHints {
			hdrs[k] = v
		}
		hdrs["User-Agent"] = config.DefaultUserAgent

		tp.mu.Lock()
		t := &PooledTicket{
			ID:        fmt.Sprintf("G%06d", tp.seq.Add(1)),
			Token:     report.Token,
			MaxUses:   tp.maxUses,
			CreatedAt: time.Now().UnixMilli(),
			ExpiresAt: time.Now().Add(tp.ttl).UnixMilli(),
			MintMS:    report.ElapsedMS,
			Region:    report.Shape.ArkRegion,
			ARP:       true,
			UA:        config.DefaultUserAgent,
			Headers:   hdrs,
			Proxy:     report.EffectiveProxy,
			Source:    "parallel",
			AccountID: accID,
			ProfileID: report.ProfileID,
		}
		tp.byAcc[accID] = t
		tp.mu.Unlock()
		tp.MintCount.Add(1)
		tp.MintTotMS.Add(report.ElapsedMS)
		if tp.Remember != nil {
			tp.Remember(accID, MintReuse{ArpSID: report.ArpSID, StickySID: report.StickySID,
				Region: geo.ForProxy(report.EffectiveProxy).Country})
		}
		return nil, nil
	})
	return err
}

func (tp *TicketPool) storeFactory(ctx context.Context, accID string, spec FactorySpec) error {
	started := time.Now()
	tk, err := AcquireFactory(ctx, spec.Base, spec.Key)
	if err != nil {
		tp.MintFail.Add(1)
		return err
	}
	hdrs := make(map[string]string, len(tk.Headers)+1)
	for k, v := range tk.Headers {
		hdrs[k] = v
	}
	if len(hdrs) == 0 {
		for k, v := range DefaultClientHints {
			hdrs[k] = v
		}
	}
	ua := tk.UA
	if ua == "" {
		ua = config.DefaultUserAgent
	}
	hdrs["User-Agent"] = ua
	uses := tk.MaxUses
	if uses <= 0 || uses > 30 {
		tp.mu.Lock()
		uses = tp.maxUses
		tp.mu.Unlock()
	}
	id := tk.ID
	if id == "" {
		id = fmt.Sprintf("F%06d", tp.seq.Add(1))
	}
	region := ""
	if payload, ok := DecodeTicket(tk.Token); ok {
		region = ValidatePoolShape(payload, false).ArkRegion
	}
	tp.mu.Lock()
	tp.byAcc[accID] = &PooledTicket{
		ID:        id,
		Token:     tk.Token,
		MaxUses:   uses,
		CreatedAt: time.Now().UnixMilli(),
		ExpiresAt: time.Now().Add(tp.ttl).UnixMilli(),
		MintMS:    time.Since(started).Milliseconds(),
		Region:    region,
		ARP:       true,
		UA:        ua,
		Headers:   hdrs,
		Proxy:     tk.Proxy,
		Source:    "factory",
		AccountID: accID,
	}
	tp.mu.Unlock()
	tp.MintCount.Add(1)
	tp.MintTotMS.Add(time.Since(started).Milliseconds())
	return nil
}

// TakeFactory pulls one ticket from the backup mint service for this account,
// replacing whatever ticket it held. Local mode uses this after a self-minted
// ticket is refused with HTTP 408.
func (tp *TicketPool) TakeFactory(ctx context.Context, accID string, spec FactorySpec) (*PooledTicket, error) {
	if err := tp.storeFactory(ctx, accID, spec); err != nil {
		return nil, err
	}
	if t := tp.take(accID); t != nil {
		return t, nil
	}
	return nil, fmt.Errorf("ticket vanished after mint")
}

// DropAccount discards the account's ticket (e.g. account deleted / blamed).
func (tp *TicketPool) DropAccount(accID string) {
	tp.mu.Lock()
	delete(tp.byAcc, accID)
	tp.mu.Unlock()
}

// DropAll discards every live ticket (used when flipping stable-session mode).
func (tp *TicketPool) DropAll() {
	tp.mu.Lock()
	tp.byAcc = map[string]*PooledTicket{}
	tp.mu.Unlock()
}

// RecordOutcome tracks failures on a ticket.
// HTTP 408/429: drop the ticket immediately — a rate-limited exit must never be
// reused for remaining MaxUses. 429 does not cool the account; that is decided
// by the caller.
// Other non-200: drop after maxFailDrop consecutive failures.
func (tp *TicketPool) RecordOutcome(t *PooledTicket, status int) {
	if t == nil {
		return
	}
	tp.mu.Lock()
	defer tp.mu.Unlock()
	cur := tp.byAcc[t.AccountID]
	if cur == nil || cur.ID != t.ID {
		return
	}
	if status == 200 {
		cur.ConsecFail = 0
		return
	}
	if status == 408 || status == 429 {
		delete(tp.byAcc, t.AccountID)
		return
	}
	cur.ConsecFail++
	if cur.ConsecFail >= tp.maxFailDrop {
		delete(tp.byAcc, t.AccountID)
	}
}

type PoolStats struct {
	Online        int            `json:"online"`
	RemainingUses int            `json:"remainingUses"`
	MaxUsesPer    int            `json:"maxUsesPer"`
	Minting       int32          `json:"minting"`
	MintCount     int64          `json:"mintCount"`
	MintFail      int64          `json:"mintFail"`
	AvgMintMS     int64          `json:"avgMintMs"`
	Tickets       []PooledTicket `json:"tickets"`
}

func (tp *TicketPool) Stats() PoolStats {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	now := time.Now().UnixMilli()
	st := PoolStats{MaxUsesPer: tp.maxUses, Minting: tp.mintActive.Load(), MintCount: tp.MintCount.Load(), MintFail: tp.MintFail.Load()}
	if st.MintCount > 0 {
		st.AvgMintMS = tp.MintTotMS.Load() / st.MintCount
	}
	add := func(t *PooledTicket) {
		if t.ExpiresAt <= now || t.Uses >= t.MaxUses {
			return
		}
		st.Online++
		st.RemainingUses += t.MaxUses - t.Uses
		p := *t
		if len(p.Token) > 40 {
			p.Token = p.Token[:40] + fmt.Sprintf("...(len=%d)", len(t.Token))
		}
		p.Headers = nil
		st.Tickets = append(st.Tickets, p)
	}
	for id, t := range tp.byAcc {
		if t.ExpiresAt <= now || t.Uses >= t.MaxUses {
			delete(tp.byAcc, id)
			continue
		}
		add(t)
	}
	return st
}
