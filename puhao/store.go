package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Settings struct {
	CaptchaKey  string `json:"captchaKey"`
	Proxies     string `json:"proxies"`
	Country     string `json:"country"`
	Count       int    `json:"count"`
	Concurrency int    `json:"concurrency"`
	IntervalSec int    `json:"intervalSec"`
}

type Account struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Secret    string `json:"secret"`
	Country   string `json:"country"`
	Status    string `json:"status"`
	Message   string `json:"message"`
	Tries     int    `json:"tries"`
	Cookie    string `json:"cookie,omitempty"`
	CreatedAt int64  `json:"createdAt"`
	UpdatedAt int64  `json:"updatedAt"`
}

type Store struct {
	mu       sync.Mutex
	db       *sql.DB
	settings Settings
	accounts []Account
}

func openStore(path string) *Store {
	s := &Store{settings: Settings{Country: "US", Concurrency: 1}}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return s
	}
	db.SetMaxOpenConns(1)
	s.db = db
	_, _ = db.Exec(`
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  captcha_key TEXT NOT NULL DEFAULT '',
  proxies TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT 'US',
  count INTEGER NOT NULL DEFAULT 0,
  concurrency INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  secret TEXT NOT NULL DEFAULT '',
  country TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  message TEXT NOT NULL DEFAULT '',
  tries INTEGER NOT NULL DEFAULT 0,
  cookie TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);`)
	s.load()
	s.ReleaseRunning("软件已关闭，已放开")
	if !s.hasRows() {
		s.importJSON(filepath.Join(filepath.Dir(path), "data", "puhao.json"))
	}
	s.normalizeSettings()
	return s
}

func (s *Store) hasRows() bool {
	if s.db == nil {
		return false
	}
	var n int
	_ = s.db.QueryRow(`SELECT (SELECT COUNT(*) FROM settings) + (SELECT COUNT(*) FROM accounts)`).Scan(&n)
	return n > 0
}

func (s *Store) load() {
	if s.db == nil {
		return
	}
	row := s.db.QueryRow(`SELECT captcha_key, proxies, country, count, concurrency FROM settings WHERE id = 1`)
	var set Settings
	if err := row.Scan(&set.CaptchaKey, &set.Proxies, &set.Country, &set.Count, &set.Concurrency); err == nil {
		s.settings = set
	}
	rows, err := s.db.Query(`SELECT id, email, secret, country, status, message, tries, cookie, created_at, updated_at FROM accounts ORDER BY created_at, email`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var a Account
		if rows.Scan(&a.ID, &a.Email, &a.Secret, &a.Country, &a.Status, &a.Message, &a.Tries, &a.Cookie, &a.CreatedAt, &a.UpdatedAt) == nil {
			s.accounts = append(s.accounts, a)
		}
	}
}

func (s *Store) importJSON(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var old struct {
		Settings Settings  `json:"settings"`
		Accounts []Account `json:"accounts"`
	}
	if json.Unmarshal(b, &old) != nil {
		return
	}
	if old.Settings.Country != "" || old.Settings.CaptchaKey != "" || old.Settings.Proxies != "" {
		s.settings = old.Settings
		s.writeSettings()
	}
	for _, a := range old.Accounts {
		s.accounts = append(s.accounts, a)
		s.writeAccount(a)
	}
}

func (s *Store) normalizeSettings() {
	if s.settings.Country == "" {
		s.settings.Country = "US"
	}
	if s.settings.Concurrency < 1 {
		s.settings.Concurrency = 1
	}
	if s.settings.Concurrency > 20 {
		s.settings.Concurrency = 20
	}
}

func (s *Store) writeSettings() {
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(`INSERT INTO settings (id, captcha_key, proxies, country, count, concurrency)
		VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		  captcha_key = excluded.captcha_key,
		  proxies = excluded.proxies,
		  country = excluded.country,
		  count = excluded.count,
		  concurrency = excluded.concurrency`,
		s.settings.CaptchaKey, s.settings.Proxies, s.settings.Country, s.settings.Count, s.settings.Concurrency)
}

func (s *Store) writeAccount(a Account) {
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(`INSERT INTO accounts (id, email, secret, country, status, message, tries, cookie, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		  email = excluded.email,
		  secret = excluded.secret,
		  country = excluded.country,
		  status = excluded.status,
		  message = excluded.message,
		  tries = excluded.tries,
		  cookie = excluded.cookie,
		  updated_at = excluded.updated_at`,
		a.ID, a.Email, a.Secret, a.Country, a.Status, a.Message, a.Tries, a.Cookie, a.CreatedAt, a.UpdatedAt)
}

func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

func (s *Store) SaveSettings(in Settings) Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	in.CaptchaKey = strings.TrimSpace(in.CaptchaKey)
	in.Country = strings.ToUpper(strings.TrimSpace(in.Country))
	if in.Country == "" {
		in.Country = "US"
	}
	if in.Concurrency < 1 {
		in.Concurrency = 1
	}
	if in.Concurrency > 20 {
		in.Concurrency = 20
	}
	if in.Count < 0 {
		in.Count = 0
	}
	if in.Count > 9999 {
		in.Count = 9999
	}
	in.IntervalSec = 0
	s.settings = in
	s.writeSettings()
	return in
}

func (s *Store) ReleaseRunning(msg string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	now := time.Now().UnixMilli()
	for i := range s.accounts {
		if s.accounts[i].Status != "running" {
			continue
		}
		s.accounts[i].Status = "pending"
		s.accounts[i].Message = msg
		s.accounts[i].UpdatedAt = now
		s.writeAccount(s.accounts[i])
		n++
	}
	return n
}

func (s *Store) List() []Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Account, len(s.accounts))
	copy(out, s.accounts)
	return out
}

func (s *Store) Get(id string) (Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts {
		if a.ID == id {
			return a, true
		}
	}
	return Account{}, false
}

func (s *Store) Update(id string, fn func(*Account)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.accounts {
		if s.accounts[i].ID == id {
			fn(&s.accounts[i])
			s.accounts[i].UpdatedAt = time.Now().UnixMilli()
			s.writeAccount(s.accounts[i])
			return true
		}
	}
	return false
}

func (s *Store) Import(lines []parsedLine, country string) (added, updated int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixMilli()
	index := map[string]int{}
	for i, a := range s.accounts {
		index[a.Email] = i
	}
	for _, ln := range lines {
		if i, ok := index[ln.email]; ok {
			s.accounts[i].Secret = ln.secret
			if s.accounts[i].Country == "" {
				s.accounts[i].Country = country
			}
			s.accounts[i].UpdatedAt = now
			s.writeAccount(s.accounts[i])
			updated++
			continue
		}
		a := Account{
			ID: uuid.NewString(), Email: ln.email, Secret: ln.secret, Country: country,
			Status: "pending", CreatedAt: now, UpdatedAt: now,
		}
		s.accounts = append(s.accounts, a)
		index[ln.email] = len(s.accounts) - 1
		s.writeAccount(a)
		added++
	}
	return added, updated
}

func (s *Store) Delete(ids []string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	kept := s.accounts[:0]
	n := 0
	for _, a := range s.accounts {
		if drop[a.ID] && a.Status != "running" {
			n++
			if s.db != nil {
				_, _ = s.db.Exec(`DELETE FROM accounts WHERE id = ?`, a.ID)
			}
			continue
		}
		kept = append(kept, a)
	}
	s.accounts = kept
	return n
}

func (s *Store) CookiesOf(ids []string) []string {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, a := range s.accounts {
		if strings.TrimSpace(a.Cookie) == "" {
			continue
		}
		if len(want) > 0 && !want[a.ID] {
			continue
		}
		out = append(out, a.Cookie)
	}
	return out
}
