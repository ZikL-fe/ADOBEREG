package arp

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Profile is the stable "machine" an account always presents: the same device
// file drives the Arkose VM, the Forter events and the BFP payload so the three
// parts of one ticket describe ONE consistent computer, and two accounts never
// share one.
type Profile struct {
	ID          string
	File        string // Arkose device json (BDA_DEVICE)
	W, H        int
	AW, AH      int
	OW, OH      int
	IW, IH      int
	DPR         float64
	HC, DM      int
	GPUVendor   string
	GPURenderer string
	Fonts       []string
	AudioValue  float64
	seed        string
}

func DefaultProfile() *Profile {
	return &Profile{
		ID: "default", W: 1920, H: 1080, AW: 1920, AH: 1040, OW: 1920, OH: 1040, IW: 1920, IH: 969, DPR: 1,
		HC: 8, DM: 8,
		GPUVendor:   "Google Inc. (Intel)",
		GPURenderer: "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)",
	}
}

// CanvasHash derives a stable per-account canvas hash (md5-shaped).
func (p *Profile) CanvasHash(kind string) string {
	h := md5.Sum([]byte(p.seed + "|" + p.ID + "|" + kind))
	return hex.EncodeToString(h[:])
}

type ProfileBook struct {
	dir   string
	once  sync.Once
	files []string
	mu    sync.Mutex
	cache map[string]*Profile
}

func NewProfileBook(sandboxDir string) *ProfileBook {
	dir := filepath.Join(sandboxDir, "profiles", "devices")
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs // node runs with cwd=sandboxDir, so BDA_DEVICE must be absolute
	}
	return &ProfileBook{dir: dir, cache: map[string]*Profile{}}
}

// For returns the deterministic profile for an account seed.
func (b *ProfileBook) For(seed string) *Profile {
	b.once.Do(func() {
		ents, _ := os.ReadDir(b.dir)
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".json") {
				b.files = append(b.files, filepath.Join(b.dir, e.Name()))
			}
		}
		sort.Strings(b.files)
	})
	if seed == "" || len(b.files) == 0 {
		return DefaultProfile()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if p, ok := b.cache[seed]; ok {
		return p
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(seed))
	file := b.files[int(h.Sum32())%len(b.files)]
	p := loadProfile(file, seed)
	b.cache[seed] = p
	return p
}

func loadProfile(file, seed string) *Profile {
	p := DefaultProfile()
	raw, err := os.ReadFile(file)
	if err != nil {
		return p
	}
	var d struct {
		ID     string `json:"id"`
		HC     int    `json:"hardwareConcurrency"`
		DM     int    `json:"deviceMemory"`
		Fonts  []string
		Screen struct{ W, H, AW, AH int } `json:"screen"`
		Win    struct {
			DPR            float64
			OW, OH, IW, IH int
		} `json:"win"`
		WebGL1 struct {
			Vendor   string `json:"unmaskedVendor"`
			Renderer string `json:"unmaskedRenderer"`
		} `json:"webgl1"`
	}
	if json.Unmarshal(raw, &d) != nil {
		return p
	}
	p.File, p.seed = file, seed
	if d.ID != "" {
		p.ID = d.ID
	} else {
		p.ID = strings.TrimSuffix(filepath.Base(file), ".json")
	}
	if d.Screen.W > 0 && d.Screen.H > 0 {
		p.W, p.H, p.AW, p.AH = d.Screen.W, d.Screen.H, d.Screen.AW, d.Screen.AH
		if p.AW == 0 {
			p.AW = p.W
		}
		if p.AH == 0 {
			p.AH = p.H - 40
		}
	}
	if d.Win.OW > 0 {
		p.OW, p.OH, p.IW, p.IH = d.Win.OW, d.Win.OH, d.Win.IW, d.Win.IH
		if d.Win.DPR > 0 {
			p.DPR = d.Win.DPR
		}
	} else {
		p.OW, p.OH, p.IW, p.IH = p.AW, p.AH, p.AW, p.AH-70
	}
	if d.HC > 0 {
		p.HC = d.HC
	}
	if d.DM > 0 {
		p.DM = d.DM
	}
	if p.DM > 8 { // navigator.deviceMemory is capped at 8 by Chrome
		p.DM = 8
	}
	p.Fonts = d.Fonts
	if d.WebGL1.Renderer != "" {
		p.GPURenderer = d.WebGL1.Renderer
		if d.WebGL1.Vendor != "" {
			p.GPUVendor = d.WebGL1.Vendor
		}
	}
	return p
}
