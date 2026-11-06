// Package subs is the refill pool (补号/普号): own mailboxes that have not
// been registered on Adobe yet. Import format is the 6-part "自己邮箱" line:
//
// Everything lives in the shared ./data/app.db (table refill_accounts, one JSON
// row per sub) like the R2 pool: mutated in memory, flushed in batches.
package refill

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusActivated = "activated"
	StatusFailed    = "failed"
)

// Item is one refill mailbox waiting for plain Adobe signup.
//
// Identity rules (same as the main pool): a sub owns exactly one device
// profile (Profile) for its whole life - retries reuse it - and every
// activation attempt runs from its own fresh proxy SID.
type Item struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Secret  string `json:"secret"` // password----clientId----refresh[----auxEmail----auxPassword]
	Country string `json:"country"`

	Status  string `json:"status"`
	Message string `json:"message"`
	Tries   int    `json:"tries"`

	Profile   string `json:"profile"`   // device-profile seed, bound 1:1 to this sub
	LastSID   string `json:"lastSid"`   // proxy session id of the last attempt (never reused)
	Cookie    string `json:"cookie"`    // resulting cookie line, "" until activated
	HasCookie bool   `json:"hasCookie"` // Cookie != ""
	Pooled    bool   `json:"pooled"`    // admitted into the main pool

	CreatedAt   int64 `json:"createdAt"`
	UpdatedAt   int64 `json:"updatedAt"`
	ActivatedAt int64 `json:"activatedAt"`
}

// MailReady: the mailbox has password + OAuth clientId + refresh token
// (enough to read inbox / later register Adobe).
func (s *Item) MailReady() bool { return ParseSecret(s.Secret).Ready() }

// HasAux reports whether an auxiliary catch-all mailbox was imported with the sub.
func (s *Item) HasAux() bool { return ParseSecret(s.Secret).HasAux() }

// Credential is the mailbox half of an import line (everything after the email).
type Credential struct {
	Password    string
	ClientID    string
	Refresh     string
	AuxEmail    string // optional catch-all / forward mailbox
	AuxPassword string
}

// Ready: a Microsoft row needs password + clientId + refresh; a ReMail row is
// "remail----<serviceToken>" and needs the token only.
func (c Credential) Ready() bool {
	if strings.EqualFold(c.Password, "remail") {
		return c.ClientID != ""
	}
	return c.Password != "" && c.ClientID != "" && c.Refresh != ""
}
func (c Credential) HasAux() bool { return strings.Contains(c.AuxEmail, "@") && c.AuxPassword != "" }

// ParseSecret splits the secret half of a line. Accepts both the 3-part
// (password----clientId----refresh) and the 5-part 自己邮箱 form
// (...----auxEmail----auxPassword). "|" works as a separator too.
func ParseSecret(secret string) Credential {
	secret = strings.TrimSpace(secret)
	sep := "----"
	if !strings.Contains(secret, sep) && strings.Contains(secret, "|") {
		sep = "|"
	}
	p := strings.Split(secret, sep)
	var c Credential
	if len(p) > 0 {
		c.Password = strings.TrimSpace(p[0])
	}
	if len(p) > 1 {
		c.ClientID = strings.TrimSpace(p[1])
	}
	if len(p) > 2 {
		c.Refresh = strings.TrimSpace(p[2])
	}
	if len(p) > 3 {
		c.AuxEmail = strings.ToLower(strings.TrimSpace(p[3]))
	}
	if len(p) > 4 {
		c.AuxPassword = strings.TrimSpace(p[4])
	}
	return c
}

// ParseLine reads one import line. Preferred format (自己邮箱):
//
//	email----password----clientId----refresh----auxEmail----auxPassword
//
// Also accepts 4-part (no aux), "|" / Tab separators, or a bare email.
func ParseLine(line string) (email, secret string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	sep := "----"
	if !strings.Contains(line, sep) {
		switch {
		case strings.Contains(line, "|"):
			sep = "|"
		case strings.Contains(line, "\t"):
			sep = "\t"
		default:
			sep = ""
		}
	}
	if sep == "" {
		email = line
	} else {
		i := strings.Index(line, sep)
		email, secret = strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+len(sep):])
		if sep != "----" {
			secret = strings.ReplaceAll(secret, sep, "----")
		}
	}
	at := strings.Index(email, "@")
	if at <= 0 || at == len(email)-1 || strings.ContainsAny(email, " \t") {
		return "", "", false
	}
	return strings.ToLower(email), secret, true
}

// Filter selects subs for List.
type Filter struct {
	Status string // "", all, pending, running, activated, failed, pooled
	Q      string // email / message substring
}

func (f Filter) match(s *Item) bool {
	switch f.Status {
	case "", "all":
	case "pooled":
		if !s.Pooled {
			return false
		}
	default:
		if s.Status != f.Status {
			return false
		}
	}
	if q := strings.ToLower(strings.TrimSpace(f.Q)); q != "" {
		if !strings.Contains(strings.ToLower(s.Email+" "+s.Message+" "+s.Profile+" "+s.ID), q) {
			return false
		}
	}
	return true
}

// Summary are the per-status counters shown above the table.
type Summary struct {
	Total     int `json:"total"`
	Pending   int `json:"pending"`
	Running   int `json:"running"`
	Activated int `json:"activated"`
	Failed    int `json:"failed"`
	Pooled    int `json:"pooled"`
}

type Manager struct {
	mu     sync.RWMutex
	db     *sql.DB
	list   []*Item
	byID   map[string]*Item
	byMail map[string]*Item
	dirty  map[string]bool
	gone   []string
}

const schema = `CREATE TABLE IF NOT EXISTS refill_accounts(id TEXT PRIMARY KEY, data TEXT NOT NULL);`

// Open loads the pool. A sub left "running" by a restart is marked failed.
func Open(db *sql.DB) (*Manager, error) {
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	m := &Manager{db: db, byID: map[string]*Item{}, byMail: map[string]*Item{}, dirty: map[string]bool{}}
	rows, err := db.Query(`SELECT data FROM refill_accounts ORDER BY rowid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var s Item
		if rows.Scan(&raw) != nil || json.Unmarshal([]byte(raw), &s) != nil {
			continue
		}
		if s.Status == StatusRunning {
			s.Status, s.Message = StatusFailed, "注册中断，请重试"
			m.dirty[s.ID] = true
		}
		m.add(&s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	go func() {
		for range time.Tick(2 * time.Second) {
			m.Flush()
		}
	}()
	return m, nil
}

func (m *Manager) add(s *Item) {
	m.list = append(m.list, s)
	m.byID[s.ID] = s
	m.byMail[s.Email] = s
}

func newID() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return "r" + hex.EncodeToString(b)
}

// Import adds / updates refill items from text. An existing email keeps its identity
// (profile, cookie, status); only a non-empty new credential replaces the old.
func (m *Manager) Import(text, country string) (added, updated, invalid int) {
	country = strings.ToUpper(strings.TrimSpace(country))
	now := time.Now().UnixMilli()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		email, secret, ok := ParseLine(line)
		if !ok {
			invalid++
			continue
		}
		if cur := m.byMail[email]; cur != nil {
			if secret != "" && secret != cur.Secret {
				cur.Secret = secret
				cur.UpdatedAt = now
				m.dirty[cur.ID] = true
				updated++
			}
			continue
		}
		id := newID()
		s := &Item{ID: id, Email: email, Secret: secret, Country: country, Status: StatusPending,
			Profile: "refill-" + id, CreatedAt: now, UpdatedAt: now}
		m.add(s)
		m.dirty[id] = true
		added++
	}
	return
}

// List returns one page (newest first) plus the total of the filter.
func (m *Manager) List(f Filter, page, size int) (items []Item, total int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var all []*Item
	for _, s := range m.list {
		if f.match(s) {
			all = append(all, s)
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].CreatedAt > all[j].CreatedAt })
	total = len(all)
	if size < 1 {
		size = 20
	}
	if page < 1 {
		page = 1
	}
	lo := (page - 1) * size
	if lo > total {
		lo = total
	}
	hi := lo + size
	if hi > total {
		hi = total
	}
	for _, s := range all[lo:hi] {
		items = append(items, *s)
	}
	return
}

// IDs returns the ids matching a filter (for "select all").
func (m *Manager) IDs(f Filter) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []string
	for _, s := range m.list {
		if f.match(s) {
			out = append(out, s.ID)
		}
	}
	return out
}

func (m *Manager) Get(id string) (Item, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if s := m.byID[id]; s != nil {
		return *s, true
	}
	return Item{}, false
}

// Update mutates one sub under the lock.
func (m *Manager) Update(id string, fn func(*Item)) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.byID[id]
	if s == nil {
		return false
	}
	fn(s)
	s.HasCookie = s.Cookie != ""
	s.UpdatedAt = time.Now().UnixMilli()
	m.dirty[id] = true
	return true
}

// Delete removes subs.
func (m *Manager) Delete(ids []string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	del := map[string]bool{}
	for _, id := range ids {
		if s := m.byID[id]; s != nil && s.Status != StatusRunning {
			del[id] = true
		}
	}
	if len(del) == 0 {
		return 0
	}
	keep := m.list[:0]
	for _, s := range m.list {
		if del[s.ID] {
			delete(m.byID, s.ID)
			delete(m.byMail, s.Email)
			delete(m.dirty, s.ID)
			m.gone = append(m.gone, s.ID)
			continue
		}
		keep = append(keep, s)
	}
	m.list = keep
	return len(del)
}

// Reset puts non-running subs back to pending (identity is kept).
func (m *Manager) Reset(ids []string) int {
	n := 0
	for _, id := range ids {
		if m.Update(id, func(s *Item) {
			if s.Status == StatusRunning || s.Status == StatusActivated {
				return
			}
			s.Status, s.Message = StatusPending, ""
			n++
		}) {
		}
	}
	return n
}

func (m *Manager) Summary() Summary {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var r Summary
	for _, s := range m.list {
		r.Total++
		switch s.Status {
		case StatusRunning:
			r.Running++
		case StatusActivated:
			r.Activated++
		case StatusFailed:
			r.Failed++
		default:
			r.Pending++
		}
		if s.Pooled {
			r.Pooled++
		}
	}
	return r
}

// Flush persists changed rows.
func (m *Manager) Flush() {
	m.mu.Lock()
	var out []Item
	for id := range m.dirty {
		if s := m.byID[id]; s != nil {
			out = append(out, *s)
		}
	}
	gone := m.gone
	m.dirty, m.gone = map[string]bool{}, nil
	m.mu.Unlock()
	for _, id := range gone {
		_, _ = m.db.Exec(`DELETE FROM refill_accounts WHERE id=?`, id)
	}
	for i := range out {
		raw, _ := json.Marshal(&out[i])
		_, _ = m.db.Exec(`INSERT INTO refill_accounts(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data`, out[i].ID, string(raw))
	}
}
