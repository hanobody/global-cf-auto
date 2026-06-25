package reminder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultCachePath = "domain_asset_cache.json"
	cacheVersion     = 1
)

type Cache struct {
	Version   int                `json:"version"`
	UpdatedAt string             `json:"updated_at"`
	Records   map[string]*Record `json:"records"`
}

type Record struct {
	Domain                string              `json:"domain"`
	Source                string              `json:"source,omitempty"`
	IsCF                  bool                `json:"is_cf,omitempty"`
	ZoneID                string              `json:"zone_id,omitempty"`
	Status                string              `json:"status,omitempty"`
	Paused                bool                `json:"paused,omitempty"`
	DomainExpiry          string              `json:"domain_expiry,omitempty"`
	DomainExpiryUpdatedAt string              `json:"domain_expiry_updated_at,omitempty"`
	DomainLastAlertDate   string              `json:"domain_last_alert_date,omitempty"`
	Certificates          []CertificateRecord `json:"certificates,omitempty"`
	Deleted               bool                `json:"deleted,omitempty"`
	PendingRefresh        bool                `json:"pending_refresh,omitempty"`
	LastRefreshAt         string              `json:"last_refresh_at,omitempty"`
	LastRefreshError      string              `json:"last_refresh_error,omitempty"`
	CreatedAt             string              `json:"created_at,omitempty"`
	UpdatedAt             string              `json:"updated_at,omitempty"`
}

type CertificateRecord struct {
	Key           string   `json:"key"`
	Type          string   `json:"type"`
	ID            string   `json:"id,omitempty"`
	Hostnames     []string `json:"hostnames,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	Subject       string   `json:"subject,omitempty"`
	SerialNumber  string   `json:"serial_number,omitempty"`
	NotBefore     string   `json:"not_before,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	LastAlertDate string   `json:"last_alert_date,omitempty"`
	UpdatedAt     string   `json:"updated_at,omitempty"`
}

type DomainChange struct {
	Domain string
	Source string
	IsCF   bool
	ZoneID string
	Status string
	Paused bool
}

type DomainRef struct {
	Domain string
	Source string
}

type Store struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(path string) *Store {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultCachePath
	}
	return &Store{path: path}
}

func (s *Store) Path() string { return s.path }

func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

func NormalizeSource(source string) string {
	return strings.TrimSpace(source)
}

func RecordKey(source, domain string) string {
	domain = NormalizeDomain(domain)
	source = strings.ToLower(NormalizeSource(source))
	if source == "" {
		return domain
	}
	return source + "|" + domain
}

func newCache() Cache {
	return Cache{Version: cacheVersion, Records: map[string]*Record{}}
}

func (s *Store) Load() (Cache, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) Save(c Cache) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(c)
}

func (s *Store) loadLocked() (Cache, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return newCache(), nil
		}
		return Cache{}, fmt.Errorf("读取资产缓存失败: %w", err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return newCache(), nil
	}
	var c Cache
	if err := json.Unmarshal(b, &c); err != nil {
		return Cache{}, fmt.Errorf("解析资产缓存失败: %w", err)
	}
	if c.Records == nil {
		c.Records = map[string]*Record{}
	}
	if c.Version == 0 {
		c.Version = cacheVersion
	}
	return c, nil
}

func (s *Store) saveLocked(c Cache) error {
	if c.Records == nil {
		c.Records = map[string]*Record{}
	}
	c.Version = cacheVersion
	c.UpdatedAt = time.Now().Format(time.RFC3339)
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化资产缓存失败: %w", err)
	}
	if dir := filepath.Dir(s.path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建资产缓存目录失败: %w", err)
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return fmt.Errorf("写入资产缓存临时文件失败: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("替换资产缓存失败: %w", err)
	}
	return nil
}

func (s *Store) UpsertDomain(change DomainChange) (DomainRef, error) {
	change.Domain = NormalizeDomain(change.Domain)
	change.Source = NormalizeSource(change.Source)
	if change.Domain == "" {
		return DomainRef{}, fmt.Errorf("域名为空")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.loadLocked()
	if err != nil {
		return DomainRef{}, err
	}
	key := RecordKey(change.Source, change.Domain)
	now := time.Now().Format(time.RFC3339)
	rec := c.Records[key]
	if rec == nil {
		rec = &Record{CreatedAt: now}
		c.Records[key] = rec
	}
	rec.Domain = change.Domain
	rec.Source = change.Source
	rec.IsCF = change.IsCF
	if strings.TrimSpace(change.ZoneID) != "" {
		rec.ZoneID = strings.TrimSpace(change.ZoneID)
	}
	if strings.TrimSpace(change.Status) != "" {
		rec.Status = strings.TrimSpace(change.Status)
	}
	rec.Paused = change.Paused
	rec.Deleted = false
	rec.PendingRefresh = true
	rec.UpdatedAt = now
	if err := s.saveLocked(c); err != nil {
		return DomainRef{}, err
	}
	return DomainRef{Domain: change.Domain, Source: change.Source}, nil
}

func (s *Store) DeleteDomain(domain string) error {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.loadLocked()
	if err != nil {
		return err
	}
	for key, rec := range c.Records {
		if rec != nil && NormalizeDomain(rec.Domain) == domain {
			delete(c.Records, key)
		}
	}
	return s.saveLocked(c)
}

func (s *Store) UpdateRecord(ref DomainRef, fn func(*Record)) error {
	ref.Domain = NormalizeDomain(ref.Domain)
	ref.Source = NormalizeSource(ref.Source)
	if ref.Domain == "" {
		return fmt.Errorf("域名为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.loadLocked()
	if err != nil {
		return err
	}
	key := RecordKey(ref.Source, ref.Domain)
	now := time.Now().Format(time.RFC3339)
	rec := c.Records[key]
	if rec == nil {
		rec = &Record{Domain: ref.Domain, Source: ref.Source, CreatedAt: now}
		c.Records[key] = rec
	}
	fn(rec)
	rec.Domain = NormalizeDomain(rec.Domain)
	rec.Source = NormalizeSource(rec.Source)
	rec.UpdatedAt = now
	return s.saveLocked(c)
}

func (s *Store) ListActive() ([]Record, error) {
	c, err := s.Load()
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(c.Records))
	for _, rec := range c.Records {
		if rec == nil || rec.Deleted || NormalizeDomain(rec.Domain) == "" {
			continue
		}
		out = append(out, *rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain == out[j].Domain {
			return out[i].Source < out[j].Source
		}
		return out[i].Domain < out[j].Domain
	})
	return out, nil
}

func (s *Store) ListRefreshCandidates(alertDays int, now time.Time) ([]DomainRef, error) {
	records, err := s.ListActive()
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var out []DomainRef
	for _, rec := range records {
		if shouldRefreshRecord(rec, alertDays, now) {
			key := RecordKey(rec.Source, rec.Domain)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, DomainRef{Domain: rec.Domain, Source: rec.Source})
		}
	}
	return out, nil
}

func shouldRefreshRecord(rec Record, alertDays int, now time.Time) bool {
	if rec.PendingRefresh {
		return true
	}
	if strings.TrimSpace(rec.DomainExpiry) == "" {
		return true
	}
	if dateWithin(rec.DomainExpiry, alertDays+1, now) {
		return true
	}
	if len(rec.Certificates) == 0 {
		return true
	}
	for _, cert := range rec.Certificates {
		if strings.TrimSpace(cert.NotAfter) == "" || timeWithin(cert.NotAfter, alertDays+1, now) {
			return true
		}
	}
	return false
}
