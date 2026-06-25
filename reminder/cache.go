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
	DefaultCachePath     = "domain_asset_cache.json"
	cacheVersion         = 2
	StatusUnknownAccount = "未知账户"
)

type Cache struct {
	Version   int                `json:"version"`
	UpdatedAt string             `json:"updated_at"`
	Records   map[string]*Record `json:"records"`
}

type Record struct {
	Domain                string              `json:"domain"`
	Source                string              `json:"source,omitempty"`
	Sources               []string            `json:"sources,omitempty"`
	Accounts              []AccountRecord     `json:"accounts,omitempty"`
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

// AccountRecord 表示一个域名在某个账户平台中的归属信息。
// 同一个域名如果存在于多个 Cloudflare 账户，会在同一条 Record 下保存多条账户归属，
// 避免日报和缓存中重复出现相同域名。
type AccountRecord struct {
	Source     string `json:"source"`
	ZoneID     string `json:"zone_id,omitempty"`
	Status     string `json:"status,omitempty"`
	Paused     bool   `json:"paused,omitempty"`
	Unknown    bool   `json:"unknown,omitempty"`
	LastSeenAt string `json:"last_seen_at,omitempty"`
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
	Domain  string
	Source  string
	Sources []string
}

// CacheReconcileSummary 记录一次启动资产同步对本地缓存的影响。
type CacheReconcileSummary struct {
	Added              int
	Updated            int
	MarkedUnknown      int
	MergedMultiAccount int
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

func DomainCacheKey(domain string) string {
	return NormalizeDomain(domain)
}

// RecordKey 保留 source 参数用于兼容旧调用；资产缓存现在按域名唯一去重，
// 同域名的多账户归属保存在 Record.Sources / Record.Accounts 中。
func RecordKey(source, domain string) string {
	return DomainCacheKey(domain)
}

func legacyRecordKey(source, domain string) string {
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
	c.Records = normalizeCacheRecords(c.Records)
	return c, nil
}

func (s *Store) saveLocked(c Cache) error {
	if c.Records == nil {
		c.Records = map[string]*Record{}
	}
	c.Records = normalizeCacheRecords(c.Records)
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

func normalizeCacheRecords(in map[string]*Record) map[string]*Record {
	out := map[string]*Record{}
	for key, rec := range in {
		if rec == nil {
			continue
		}
		copyRec := *rec
		copyRec.Domain = NormalizeDomain(copyRec.Domain)
		if copyRec.Domain == "" {
			copyRec.Domain = domainFromCacheKey(key)
		}
		if copyRec.Domain == "" {
			continue
		}
		normalizeRecordMembership(&copyRec)
		cacheKey := DomainCacheKey(copyRec.Domain)
		if existing := out[cacheKey]; existing != nil {
			mergeRecord(existing, copyRec)
			continue
		}
		out[cacheKey] = &copyRec
	}
	for _, rec := range out {
		normalizeRecordMembership(rec)
	}
	return out
}

func domainFromCacheKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if parts := strings.Split(key, "|"); len(parts) > 1 {
		return NormalizeDomain(parts[len(parts)-1])
	}
	return NormalizeDomain(key)
}

func mergeRecord(dst *Record, src Record) {
	if dst == nil {
		return
	}
	if dst.Domain == "" {
		dst.Domain = src.Domain
	}
	dst.IsCF = dst.IsCF || src.IsCF
	if dst.ZoneID == "" {
		dst.ZoneID = src.ZoneID
	}
	if dst.Status == "" || dst.Status == StatusUnknownAccount {
		dst.Status = src.Status
	}
	dst.Paused = dst.Paused || src.Paused
	if dst.DomainExpiry == "" || isNewerTime(src.DomainExpiryUpdatedAt, dst.DomainExpiryUpdatedAt) {
		if src.DomainExpiry != "" {
			dst.DomainExpiry = src.DomainExpiry
			dst.DomainExpiryUpdatedAt = src.DomainExpiryUpdatedAt
			dst.DomainLastAlertDate = src.DomainLastAlertDate
		}
	}
	dst.Certificates = mergeCertificates(dst.Certificates, src.Certificates)
	dst.Deleted = dst.Deleted && src.Deleted
	dst.PendingRefresh = dst.PendingRefresh || src.PendingRefresh
	if isNewerTime(src.LastRefreshAt, dst.LastRefreshAt) {
		dst.LastRefreshAt = src.LastRefreshAt
	}
	if dst.LastRefreshError == "" {
		dst.LastRefreshError = src.LastRefreshError
	} else if src.LastRefreshError != "" && !strings.Contains(dst.LastRefreshError, src.LastRefreshError) {
		dst.LastRefreshError += "; " + src.LastRefreshError
	}
	if dst.CreatedAt == "" || (src.CreatedAt != "" && isNewerTime(dst.CreatedAt, src.CreatedAt)) {
		dst.CreatedAt = src.CreatedAt
	}
	if isNewerTime(src.UpdatedAt, dst.UpdatedAt) {
		dst.UpdatedAt = src.UpdatedAt
	}
	for _, source := range src.Sources {
		addSource(dst, source)
	}
	for _, account := range src.Accounts {
		upsertAccount(dst, account)
	}
	normalizeRecordMembership(dst)
}

func isNewerTime(candidate string, current string) bool {
	candidate = strings.TrimSpace(candidate)
	current = strings.TrimSpace(current)
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}
	ct, cerr := time.Parse(time.RFC3339, candidate)
	ot, oerr := time.Parse(time.RFC3339, current)
	if cerr == nil && oerr == nil {
		return ct.After(ot)
	}
	return candidate > current
}

func normalizeRecordMembership(rec *Record) {
	if rec == nil {
		return
	}
	rec.Domain = NormalizeDomain(rec.Domain)
	sources := orderedSourcesFromRecord(*rec)
	if len(rec.Accounts) == 0 {
		for _, source := range sources {
			account := AccountRecord{Source: source}
			if len(sources) == 1 {
				account.ZoneID = rec.ZoneID
				account.Status = rec.Status
				account.Paused = rec.Paused
				account.Unknown = strings.TrimSpace(rec.Status) == StatusUnknownAccount
			}
			rec.Accounts = append(rec.Accounts, account)
		}
	}
	for _, account := range rec.Accounts {
		if account.Source != "" {
			addSourceValue(&sources, account.Source)
		}
	}
	rec.Accounts = normalizeAccounts(rec.Accounts, sources)
	rec.Sources = accountSources(rec.Accounts)
	if len(rec.Sources) == 0 {
		rec.Sources = sources
	}
	sort.Strings(rec.Sources)
	rec.Source = strings.Join(rec.Sources, ", ")
	if len(rec.Accounts) == 1 {
		acc := rec.Accounts[0]
		if rec.ZoneID == "" {
			rec.ZoneID = acc.ZoneID
		}
		if acc.Unknown || strings.TrimSpace(acc.Status) == StatusUnknownAccount {
			rec.Status = StatusUnknownAccount
		} else if strings.TrimSpace(acc.Status) != "" {
			rec.Status = acc.Status
		}
		rec.Paused = acc.Paused
	} else if len(rec.Accounts) > 1 {
		rec.ZoneID = ""
		rec.Paused = anyPaused(rec.Accounts)
		rec.Status = aggregateAccountStatus(rec.Accounts)
	}
}

func orderedSourcesFromRecord(rec Record) []string {
	var sources []string
	for _, source := range rec.Sources {
		addSourceValue(&sources, source)
	}
	if len(sources) == 0 {
		for _, source := range splitSourceDisplay(rec.Source) {
			addSourceValue(&sources, source)
		}
	}
	return sources
}

func splitSourceDisplay(source string) []string {
	if strings.TrimSpace(source) == "" {
		return nil
	}
	parts := strings.FieldsFunc(source, func(r rune) bool {
		return r == ',' || r == '，' || r == ';' || r == '；'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = NormalizeSource(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeAccounts(accounts []AccountRecord, fallbackSources []string) []AccountRecord {
	bySource := map[string]AccountRecord{}
	order := make([]string, 0)
	for _, source := range fallbackSources {
		source = NormalizeSource(source)
		if source == "" {
			continue
		}
		key := normalizedSourceKey(source)
		if _, ok := bySource[key]; !ok {
			bySource[key] = AccountRecord{Source: source}
			order = append(order, key)
		}
	}
	for _, acc := range accounts {
		acc.Source = NormalizeSource(acc.Source)
		if acc.Source == "" {
			continue
		}
		key := normalizedSourceKey(acc.Source)
		old, ok := bySource[key]
		if !ok {
			order = append(order, key)
		}
		bySource[key] = mergeAccountRecord(old, acc)
	}
	sort.Slice(order, func(i, j int) bool { return bySource[order[i]].Source < bySource[order[j]].Source })
	out := make([]AccountRecord, 0, len(order))
	for _, key := range order {
		out = append(out, bySource[key])
	}
	return out
}

func mergeAccountRecord(old AccountRecord, incoming AccountRecord) AccountRecord {
	incoming.Source = NormalizeSource(incoming.Source)
	if old.Source == "" {
		return incoming
	}
	if incoming.ZoneID != "" {
		old.ZoneID = incoming.ZoneID
	}
	if incoming.Status != "" {
		old.Status = incoming.Status
	}
	old.Paused = incoming.Paused
	old.Unknown = incoming.Unknown
	if incoming.LastSeenAt != "" {
		old.LastSeenAt = incoming.LastSeenAt
	}
	return old
}

func accountSources(accounts []AccountRecord) []string {
	var sources []string
	for _, acc := range accounts {
		addSourceValue(&sources, acc.Source)
	}
	sort.Strings(sources)
	return sources
}

func addSource(rec *Record, source string) {
	if rec == nil {
		return
	}
	source = NormalizeSource(source)
	if source == "" {
		return
	}
	addSourceValue(&rec.Sources, source)
}

func addSourceValue(sources *[]string, source string) {
	source = NormalizeSource(source)
	if source == "" {
		return
	}
	key := normalizedSourceKey(source)
	for _, existing := range *sources {
		if normalizedSourceKey(existing) == key {
			return
		}
	}
	*sources = append(*sources, source)
}

func upsertAccount(rec *Record, account AccountRecord) bool {
	if rec == nil {
		return false
	}
	account.Source = NormalizeSource(account.Source)
	if account.Source == "" {
		return false
	}
	changed := false
	key := normalizedSourceKey(account.Source)
	for i := range rec.Accounts {
		if normalizedSourceKey(rec.Accounts[i].Source) == key {
			merged := mergeAccountRecord(rec.Accounts[i], account)
			changed = rec.Accounts[i] != merged
			rec.Accounts[i] = merged
			addSource(rec, account.Source)
			return changed
		}
	}
	rec.Accounts = append(rec.Accounts, account)
	addSource(rec, account.Source)
	return true
}

func anyPaused(accounts []AccountRecord) bool {
	for _, acc := range accounts {
		if acc.Paused {
			return true
		}
	}
	return false
}

func aggregateAccountStatus(accounts []AccountRecord) string {
	if len(accounts) == 0 {
		return ""
	}
	unknown := 0
	statuses := map[string]struct{}{}
	for _, acc := range accounts {
		status := strings.TrimSpace(acc.Status)
		if acc.Unknown || status == StatusUnknownAccount {
			unknown++
			continue
		}
		if status != "" {
			statuses[status] = struct{}{}
		}
	}
	if unknown == len(accounts) {
		return StatusUnknownAccount
	}
	var parts []string
	if len(accounts) > 1 {
		parts = append(parts, "多账户")
	}
	if unknown > 0 {
		parts = append(parts, fmt.Sprintf("部分未知账户%d个", unknown))
	}
	for status := range statuses {
		parts = append(parts, status)
	}
	sort.Strings(parts)
	return strings.Join(parts, "/")
}

func RecordSources(rec Record) []string {
	normalizeRecordMembership(&rec)
	return append([]string(nil), rec.Sources...)
}

func RecordAccounts(rec Record) []AccountRecord {
	normalizeRecordMembership(&rec)
	return append([]AccountRecord(nil), rec.Accounts...)
}

func RecordSourceDisplay(rec Record) string {
	normalizeRecordMembership(&rec)
	if len(rec.Accounts) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rec.Accounts))
	for _, acc := range rec.Accounts {
		name := NormalizeSource(acc.Source)
		if name == "" {
			continue
		}
		if acc.Unknown || strings.TrimSpace(acc.Status) == StatusUnknownAccount {
			name += "(未知账户)"
		}
		parts = append(parts, name)
	}
	return strings.Join(parts, ", ")
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
	key := DomainCacheKey(change.Domain)
	now := time.Now().Format(time.RFC3339)
	rec := c.Records[key]
	if rec == nil {
		rec = &Record{Domain: change.Domain, CreatedAt: now}
		c.Records[key] = rec
	}
	oldSourceCount := len(RecordSources(*rec))
	applyDomainChange(rec, change, now)
	rec.Deleted = false
	rec.PendingRefresh = true
	rec.UpdatedAt = now
	if oldSourceCount > 0 && len(RecordSources(*rec)) > oldSourceCount {
		rec.LastRefreshError = strings.TrimSpace(rec.LastRefreshError)
	}
	if err := s.saveLocked(c); err != nil {
		return DomainRef{}, err
	}
	return DomainRef{Domain: change.Domain, Source: change.Source, Sources: RecordSources(*rec)}, nil
}

func applyDomainChange(rec *Record, change DomainChange, now string) bool {
	if rec == nil {
		return false
	}
	normalizeRecordMembership(rec)
	before, _ := json.Marshal(rec)
	rec.Domain = NormalizeDomain(change.Domain)
	if change.IsCF {
		rec.IsCF = true
	}
	if change.Source != "" {
		acc := AccountRecord{
			Source:     change.Source,
			ZoneID:     strings.TrimSpace(change.ZoneID),
			Status:     strings.TrimSpace(change.Status),
			Paused:     change.Paused,
			Unknown:    false,
			LastSeenAt: now,
		}
		upsertAccount(rec, acc)
	}
	if strings.TrimSpace(change.ZoneID) != "" && (rec.ZoneID == "" || len(rec.Accounts) <= 1) {
		rec.ZoneID = strings.TrimSpace(change.ZoneID)
	}
	if strings.TrimSpace(change.Status) != "" && len(rec.Accounts) <= 1 {
		rec.Status = strings.TrimSpace(change.Status)
	}
	rec.Paused = change.Paused
	if strings.Contains(rec.LastRefreshError, "启动同步未在当前有权限") {
		rec.LastRefreshError = ""
	}
	normalizeRecordMembership(rec)
	after, _ := json.Marshal(rec)
	return string(before) != string(after)
}

func (s *Store) DeleteDomain(domain string, sources ...string) error {
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
	key := DomainCacheKey(domain)
	if len(sources) == 0 {
		delete(c.Records, key)
		return s.saveLocked(c)
	}
	rec := c.Records[key]
	if rec == nil {
		return s.saveLocked(c)
	}
	removeSet := normalizedSourceSet(sources)
	kept := rec.Accounts[:0]
	for _, acc := range rec.Accounts {
		if _, remove := removeSet[normalizedSourceKey(acc.Source)]; remove {
			continue
		}
		kept = append(kept, acc)
	}
	if len(kept) == 0 {
		delete(c.Records, key)
		return s.saveLocked(c)
	}
	rec.Accounts = kept
	rec.Sources = nil
	rec.PendingRefresh = true
	rec.UpdatedAt = time.Now().Format(time.RFC3339)
	normalizeRecordMembership(rec)
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
	key := DomainCacheKey(ref.Domain)
	now := time.Now().Format(time.RFC3339)
	rec := c.Records[key]
	if rec == nil {
		rec = &Record{Domain: ref.Domain, CreatedAt: now}
		c.Records[key] = rec
	}
	if ref.Source != "" {
		upsertAccount(rec, AccountRecord{Source: ref.Source})
	}
	for _, source := range ref.Sources {
		if strings.TrimSpace(source) != "" {
			upsertAccount(rec, AccountRecord{Source: NormalizeSource(source)})
		}
	}
	fn(rec)
	rec.Domain = NormalizeDomain(rec.Domain)
	rec.UpdatedAt = now
	normalizeRecordMembership(rec)
	return s.saveLocked(c)
}

func (s *Store) GetRecord(domain string) (Record, bool, error) {
	domain = NormalizeDomain(domain)
	if domain == "" {
		return Record{}, false, nil
	}
	c, err := s.Load()
	if err != nil {
		return Record{}, false, err
	}
	rec := c.Records[DomainCacheKey(domain)]
	if rec == nil || rec.Deleted {
		return Record{}, false, nil
	}
	return *rec, true, nil
}

// ReconcileCloudflareDomains 使用启动时从 Cloudflare 读取到的域名清单增量校准本地资产缓存。
//
// 设计目标：
//   - 按域名唯一去重；同一个域名出现在多个账户时合并为一条记录并保留多个账户归属；
//   - 只合并差异，不清空或重建已有缓存，保留已经查询到的域名续费时间和证书信息；
//   - 当前有权限账号里新发现的域名会写入缓存并标记待补全；
//   - 之前缓存的账户归属如果在已成功扫描的账号中消失，或所属账号已不在当前配置里，
//     不直接删除，而是在该账户归属上标记为“未知账户”，便于在日报 CSV 中发现并人工确认。
func (s *Store) ReconcileCloudflareDomains(changes []DomainChange, successfulSources []string, configuredSources []string) ([]DomainRef, CacheReconcileSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, err := s.loadLocked()
	if err != nil {
		return nil, CacheReconcileSummary{}, err
	}

	now := time.Now().Format(time.RFC3339)
	successful := normalizedSourceSet(successfulSources)
	configured := normalizedSourceSet(configuredSources)
	seenByDomain := map[string]map[string]struct{}{}
	refreshSeen := map[string]struct{}{}
	refs := make([]DomainRef, 0)
	summary := CacheReconcileSummary{}

	addRefresh := func(rec *Record) {
		if rec == nil || NormalizeDomain(rec.Domain) == "" {
			return
		}
		key := DomainCacheKey(rec.Domain)
		if _, ok := refreshSeen[key]; ok {
			return
		}
		refreshSeen[key] = struct{}{}
		refs = append(refs, DomainRef{Domain: rec.Domain, Source: firstSource(*rec), Sources: RecordSources(*rec)})
	}

	for _, change := range changes {
		change.Domain = NormalizeDomain(change.Domain)
		change.Source = NormalizeSource(change.Source)
		if change.Domain == "" {
			continue
		}
		key := DomainCacheKey(change.Domain)
		if _, ok := seenByDomain[key]; !ok {
			seenByDomain[key] = map[string]struct{}{}
		}
		if change.Source != "" {
			seenByDomain[key][normalizedSourceKey(change.Source)] = struct{}{}
		}

		rec := c.Records[key]
		created := false
		if rec == nil {
			rec = &Record{Domain: change.Domain, CreatedAt: now}
			c.Records[key] = rec
			created = true
			summary.Added++
		}

		beforeSources := len(RecordSources(*rec))
		needsRefresh := created || rec.PendingRefresh || strings.TrimSpace(rec.DomainExpiry) == "" || len(rec.Certificates) == 0 || strings.TrimSpace(rec.LastRefreshError) != ""
		changed := applyDomainChange(rec, change, now)
		rec.Deleted = false
		if needsRefresh {
			rec.PendingRefresh = true
			addRefresh(rec)
		}
		rec.UpdatedAt = now
		if !created && changed {
			summary.Updated++
		}
		if beforeSources <= 1 && len(RecordSources(*rec)) > 1 {
			summary.MergedMultiAccount++
		}
	}

	for _, rec := range c.Records {
		if rec == nil || rec.Deleted || !rec.IsCF || NormalizeDomain(rec.Domain) == "" {
			continue
		}
		normalizeRecordMembership(rec)
		seenSources := seenByDomain[DomainCacheKey(rec.Domain)]
		changedUnknown := false
		for i := range rec.Accounts {
			acc := &rec.Accounts[i]
			sourceKey := normalizedSourceKey(acc.Source)
			if sourceKey == "" {
				continue
			}
			_, sourceScannedSuccessfully := successful[sourceKey]
			_, sourceConfigured := configured[sourceKey]
			_, seenInScan := seenSources[sourceKey]

			missingFromSuccessfulAccount := sourceScannedSuccessfully && !seenInScan
			accountNoLongerConfigured := !sourceConfigured
			if !missingFromSuccessfulAccount && !accountNoLongerConfigured {
				continue
			}

			if !acc.Unknown || acc.Status != StatusUnknownAccount {
				summary.MarkedUnknown++
				changedUnknown = true
			}
			acc.Unknown = true
			acc.Status = StatusUnknownAccount
		}
		if changedUnknown {
			rec.PendingRefresh = true
			rec.LastRefreshError = "启动同步未在当前有权限的 Cloudflare 账户中找到部分或全部账户归属，已标记为未知账户"
			rec.UpdatedAt = now
			addRefresh(rec)
		}
		normalizeRecordMembership(rec)
	}

	if err := s.saveLocked(c); err != nil {
		return nil, CacheReconcileSummary{}, err
	}
	return refs, summary, nil
}

func firstSource(rec Record) string {
	sources := RecordSources(rec)
	if len(sources) == 0 {
		return ""
	}
	return sources[0]
}

func normalizedSourceSet(sources []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, source := range sources {
		key := normalizedSourceKey(source)
		if key != "" {
			out[key] = struct{}{}
		}
	}
	return out
}

func normalizedSourceKey(source string) string {
	return strings.ToLower(NormalizeSource(source))
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
		copyRec := *rec
		normalizeRecordMembership(&copyRec)
		out = append(out, copyRec)
	}
	sort.Slice(out, func(i, j int) bool {
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
			key := DomainCacheKey(rec.Domain)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, DomainRef{Domain: rec.Domain, Source: firstSource(rec), Sources: RecordSources(rec)})
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
