package arp

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firefly-go/internal/config"
	"firefly-go/internal/geo"
	"firefly-go/internal/transport"

	"github.com/google/uuid"
)

type Minter struct {
	tlsPool  *transport.Pool
	sandbox  *SandboxPool
	bfp      *BFPCollector
	Profiles *ProfileBook
	// Serial runs Forter -> Arkose -> BFP one after another instead of concurrently.
	Serial atomic.Bool
}

func NewMinter(cfg config.Config, tlsPool *transport.Pool) *Minter {
	return &Minter{
		tlsPool:  tlsPool,
		sandbox:  NewSandboxPool(cfg.SandboxPoolSize, cfg.NodeBin, cfg.ArkSandboxDir, cfg.SherlockDir, tlsPool),
		bfp:      NewBFPCollector(cfg.BFPTemplatePath),
		Profiles: NewProfileBook(cfg.ArkSandboxDir),
	}
}

// CaptureBFP posts the genuine fingerprint for the account's device profile.
func (m *Minter) CaptureBFP(sessionID, proxy, userAgent string, prof *Profile) (BFPResult, error) {
	if sessionID == "" {
		sessionID = "bfp-" + uuid.NewString()
	}
	return m.bfp.Capture(m.tlsPool, sessionID, proxy, userAgent, prof)
}

type MintReport struct {
	OK             bool         `json:"ok"`
	Token          string       `json:"token"`
	EffectiveProxy string       `json:"effective_proxy,omitempty"`
	ProfileID      string       `json:"profile_id,omitempty"`
	ArpSID         string       `json:"arp_sid,omitempty"`
	StickySID      string       `json:"sticky_sid,omitempty"`
	Shape          ShapeReport  `json:"shape"`
	Forter         ForterResult `json:"forter"`
	Ark            ArkResult    `json:"ark"`
	BFP            BFPResult    `json:"bfp"`
	ElapsedMS      int64        `json:"elapsed_ms"`
}

// MintReuse optionally pins ARP sid + proxy sticky exit across remints.
// Empty fields mean "mint fresh" (legacy behaviour).
type MintReuse struct {
	ArpSID    string
	StickySID string
	Region    string // exit country StickySID belongs to; "" = US (older records)
}

func profID(p *Profile) string {
	if p == nil {
		return ""
	}
	return p.ID
}

// MintPure runs Forter, the Arkose sandbox and the idg BFP capture
// concurrently. They share one sticky proxy and one device profile, so the
// wait is the slowest stage. Arkose still comes from the Node sandbox
// (cached api.js, gt2 intercept); that script is refreshed on a timer.
//
// reuse==nil (or empty) mints a brand-new proxy sticky SID and a fresh ARP
// payload sid. When reuse pins StickySID / ArpSID, remints keep the same
// exit and session identity.
func (m *Minter) MintPure(ctx context.Context, sessionID, proxy, userAgent string, prof *Profile, reuse *MintReuse) (MintReport, error) {
	started := time.Now()
	if sessionID == "" {
		sessionID = uuid.NewString()
	}
	if userAgent == "" {
		userAgent = config.DefaultUserAgent
	}
	if prof == nil {
		prof = DefaultProfile()
	}
	if reuse == nil {
		reuse = &MintReuse{}
	}

	var (
		ftrRes ForterResult
		arkRes ArkResult
		bfpRes BFPResult
	)

	// A sticky SID keeps the exit IP it was created with, so one minted under
	// another country must not be reused after the proxy region changed.
	if reuse.StickySID != "" {
		was := reuse.Region
		if was == "" {
			was = "US"
		}
		if !strings.EqualFold(was, geo.ForProxy(proxy).Country) {
			reuse.StickySID = ""
		}
	}

	pickProxy := func(forceFresh bool) string {
		if !forceFresh && reuse.StickySID != "" {
			return transport.ApplyStickySID(proxy, reuse.StickySID)
		}
		reuse.StickySID = ""
		return transport.FreshUniqueSID(proxy)
	}

	// Dead exits fail the 4s cdn123 probe and rotate before Forter / Arkose / BFP start.
	activeProxy := pickProxy(false)
	for probeTry := 0; probeTry < 5; probeTry++ {
		if probeTry > 0 {
			activeProxy = pickProxy(true)
		}
		st, _, _, pErr := m.tlsPool.DoFast("probe-"+uuid.NewString()[:8], activeProxy, "GET", "https://cdn123.forter.com/?u=probe&v=2", [][2]string{
			{"user-agent", userAgent},
		}, nil)
		if pErr == nil && st > 0 {
			break
		}
		log.Printf("[ARP] Proxy SID unreachable in 4s (%v), rotating to fresh sticky SID...", pErr)
	}
	proxy = activeProxy

	var (
		wg                     sync.WaitGroup
		ftrErr, arkErr, bfpErr error
	)
	wg.Add(3)
	serial := m.Serial.Load()
	launch := func(fn func()) {
		if serial {
			fn()
			return
		}
		go fn()
	}
	launch(func() {
		defer wg.Done()
		for attempt := 0; attempt < 2; attempt++ {
			ftrRes, ftrErr = MintForterFTR(m.tlsPool, sessionID, proxy, userAgent, prof)
			if ftrErr == nil && ftrRes.OK {
				break
			}
		}
	})
	launch(func() {
		defer wg.Done()
		for attempt := 0; attempt < 2; attempt++ {
			arkRes, arkErr = m.sandbox.MintArk(ctx, proxy, prof)
			if arkErr == nil && arkRes.OK {
				break
			}
		}
	})
	launch(func() {
		defer wg.Done()
		for attempt := 0; attempt < 2; attempt++ {
			bfpRes, bfpErr = m.bfp.Capture(m.tlsPool, "bfp-"+sessionID, proxy, userAgent, prof)
			if bfpErr == nil && bfpRes.OK {
				break
			}
		}
	})
	wg.Wait()

	fail := func(e error) (MintReport, error) {
		return MintReport{Forter: ftrRes, Ark: arkRes, BFP: bfpRes, ElapsedMS: time.Since(started).Milliseconds()}, e
	}
	if ftrErr != nil || !ftrRes.OK {
		return fail(fmt.Errorf("forter failed: %v", ftrErr))
	}
	if arkErr != nil || !arkRes.OK {
		return fail(fmt.Errorf("arkose failed: %s (%v)", arkRes.Error, arkErr))
	}
	if bfpErr != nil || !bfpRes.OK {
		return fail(fmt.Errorf("bfp failed: %v", bfpErr))
	}

	arpSID := strings.TrimSpace(reuse.ArpSID)
	if arpSID == "" {
		arpSID = uuid.NewString()
	}
	payload := TicketPayload{
		SID: arpSID,
		FTR: ftrRes.FTR,
		ARK: arkRes.Token,
		BFP: bfpRes.BFP,
	}
	token := AssembleTicket(payload)
	shape := ValidatePoolShape(payload, false)

	return MintReport{
		OK:             shape.OK,
		Token:          token,
		EffectiveProxy: proxy,
		ProfileID:      profID(prof),
		ArpSID:         arpSID,
		StickySID:      transport.ExtractStickySID(proxy),
		Shape:          shape,
		Forter:         ftrRes,
		Ark:            arkRes,
		BFP:            bfpRes,
		ElapsedMS:      time.Since(started).Milliseconds(),
	}, nil
}
