package reminder

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"DomainC/cfclient"
	"DomainC/config"
	"DomainC/tools"
)

type RegistrarExpiry interface {
	GetExpireAtForDomain(ctx context.Context, domain string) (config.Registrar, time.Time, error)
}

type WhoisClient interface {
	Query(ctx context.Context, domain string) (string, error)
}

type RuntimeOptions struct {
	Store        *Store
	CFClient     cfclient.Client
	Accounts     []config.CF
	Registrar    RegistrarExpiry
	Whois        WhoisClient
	RefreshDelay time.Duration
	QueryTimeout time.Duration
	TLS          time.Duration
}

type Runtime struct {
	store        *Store
	cfClient     cfclient.Client
	accounts     []config.CF
	registrar    RegistrarExpiry
	whois        WhoisClient
	refreshDelay time.Duration
	queryTimeout time.Duration
	tlsTimeout   time.Duration
	jobs         chan DomainRef
	startupOnce  sync.Once

	originMu    sync.Mutex
	originCache map[string]originCertCacheItem
}

// StartupSyncSummary 表示一次启动资产同步的结果。
type StartupSyncSummary struct {
	ConfiguredAccounts int
	ScannedAccounts    int
	DomainsSeen        int
	Added              int
	Updated            int
	MarkedUnknown      int
	QueuedRefresh      int
	Errors             []string
}

type originCertCacheItem struct {
	loadedAt time.Time
	certs    []cfclient.OriginCACertInfo
	err      error
}

var defaultRuntime atomic.Value

func SetDefaultRuntime(rt *Runtime) {
	defaultRuntime.Store(rt)
}

func DefaultRuntime() *Runtime {
	v := defaultRuntime.Load()
	if v == nil {
		return nil
	}
	rt, _ := v.(*Runtime)
	return rt
}

func NewRuntime(opts RuntimeOptions) *Runtime {
	store := opts.Store
	if store == nil {
		store = NewFileStore(DefaultCachePath)
	}
	cf := opts.CFClient
	if cf == nil {
		cf = cfclient.NewClient()
	}
	refreshDelay := opts.RefreshDelay
	if refreshDelay <= 0 {
		refreshDelay = 2 * time.Second
	}
	queryTimeout := opts.QueryTimeout
	if queryTimeout <= 0 {
		queryTimeout = 15 * time.Second
	}
	tlsTimeout := opts.TLS
	if tlsTimeout <= 0 {
		tlsTimeout = 10 * time.Second
	}
	return &Runtime{
		store:        store,
		cfClient:     cf,
		accounts:     append([]config.CF(nil), opts.Accounts...),
		registrar:    opts.Registrar,
		whois:        opts.Whois,
		refreshDelay: refreshDelay,
		queryTimeout: queryTimeout,
		tlsTimeout:   tlsTimeout,
		jobs:         make(chan DomainRef, 1024),
		originCache:  map[string]originCertCacheItem{},
	}
}

func (r *Runtime) Store() *Store { return r.store }

// SyncCloudflareDomainsOnce 在进程启动后执行一次 Cloudflare 域名基线同步。
//
// 该方法只读取各账号的 Zone 清单并与本地缓存做增量合并，不会清空重建缓存；
// 新增或缺失基础数据的域名会进入后台补全队列，由 Run 的工作循环按 refreshDelay 慢速查询
// 域名续费时间、Cloudflare Origin CA 源站证书和当前访问证书。
func (r *Runtime) SyncCloudflareDomainsOnce(ctx context.Context) StartupSyncSummary {
	summary := StartupSyncSummary{}
	if r == nil || r.store == nil || r.cfClient == nil {
		return summary
	}
	r.startupOnce.Do(func() {
		summary = r.syncCloudflareDomains(ctx)
	})
	return summary
}

func (r *Runtime) syncCloudflareDomains(ctx context.Context) StartupSyncSummary {
	summary := StartupSyncSummary{ConfiguredAccounts: len(r.accounts)}
	if len(r.accounts) == 0 {
		log.Printf("[reminder] startup_sync_skip reason=no_cloudflare_accounts")
		return summary
	}

	configuredSources := make([]string, 0, len(r.accounts))
	for _, acc := range r.accounts {
		configuredSources = append(configuredSources, accountCacheLabel(acc))
	}

	changes := make([]DomainChange, 0)
	successfulSources := make([]string, 0, len(r.accounts))
	for i, acc := range r.accounts {
		label := accountCacheLabel(acc)
		if strings.TrimSpace(acc.APIToken) == "" {
			errText := fmt.Sprintf("Cloudflare 账号 %s 缺少 apiToken，跳过启动同步", label)
			summary.Errors = append(summary.Errors, errText)
			log.Printf("[reminder] startup_sync_account_skip source=%s err=%s", label, errText)
			continue
		}

		lookupTimeout := r.queryTimeout
		if lookupTimeout < 60*time.Second {
			lookupTimeout = 60 * time.Second
		}
		lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
		domains, err := r.cfClient.FetchAllDomains(lookupCtx, acc)
		cancel()
		if err != nil {
			errText := fmt.Sprintf("Cloudflare 账号 %s 启动同步失败: %v", label, err)
			summary.Errors = append(summary.Errors, errText)
			log.Printf("[reminder] startup_sync_account_failed source=%s err=%v", label, err)
			continue
		}

		successfulSources = append(successfulSources, label)
		summary.ScannedAccounts++
		for _, item := range domains {
			domain := NormalizeDomain(item.Domain)
			if domain == "" {
				continue
			}
			source := NormalizeSource(item.Source)
			if source == "" {
				source = label
			}
			changes = append(changes, DomainChange{
				Domain: domain,
				Source: source,
				IsCF:   true,
				ZoneID: item.ZoneID,
				Status: item.Status,
				Paused: item.Paused,
			})
			summary.DomainsSeen++
		}
		log.Printf("[reminder] startup_sync_account_done source=%s domains=%d", label, len(domains))

		if r.refreshDelay > 0 && i < len(r.accounts)-1 {
			select {
			case <-ctx.Done():
				summary.Errors = append(summary.Errors, ctx.Err().Error())
				return summary
			case <-time.After(r.refreshDelay):
			}
		}
	}

	refs, cacheSummary, err := r.store.ReconcileCloudflareDomains(changes, successfulSources, configuredSources)
	if err != nil {
		errText := fmt.Sprintf("写入启动同步缓存失败: %v", err)
		summary.Errors = append(summary.Errors, errText)
		log.Printf("[reminder] startup_sync_cache_failed err=%v", err)
		return summary
	}

	summary.Added = cacheSummary.Added
	summary.Updated = cacheSummary.Updated
	summary.MarkedUnknown = cacheSummary.MarkedUnknown
	summary.QueuedRefresh = len(refs)

	go r.enqueueRefreshesSequentially(ctx, refs)
	log.Printf("[reminder] startup_sync_done accounts=%d/%d domains=%d added=%d updated=%d unknown=%d merged_multi_account=%d queued_refresh=%d errors=%d",
		summary.ScannedAccounts, summary.ConfiguredAccounts, summary.DomainsSeen, summary.Added, summary.Updated, summary.MarkedUnknown, cacheSummary.MergedMultiAccount, summary.QueuedRefresh, len(summary.Errors))
	return summary
}

func (r *Runtime) enqueueRefreshesSequentially(ctx context.Context, refs []DomainRef) {
	for _, ref := range refs {
		if !r.enqueueWait(ctx, ref) {
			return
		}
	}
}

func (r *Runtime) enqueueWait(ctx context.Context, ref DomainRef) bool {
	ref.Domain = NormalizeDomain(ref.Domain)
	ref.Source = NormalizeSource(ref.Source)
	if ref.Domain == "" {
		return true
	}
	select {
	case r.jobs <- ref:
		return true
	case <-ctx.Done():
		return false
	}
}

func accountCacheLabel(account config.CF) string {
	if label := strings.TrimSpace(account.Label); label != "" {
		return label
	}
	if accountID := strings.TrimSpace(account.AccountID); accountID != "" {
		return accountID
	}
	if email := strings.TrimSpace(account.Email); email != "" {
		return email
	}
	return "Cloudflare"
}

func (r *Runtime) Run(ctx context.Context) {
	if r == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ref := <-r.jobs:
			if r.refreshDelay > 0 {
				timer := time.NewTimer(r.refreshDelay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
			if err := r.RefreshDomain(ctx, ref); err != nil {
				log.Printf("[reminder] refresh_failed domain=%s source=%s err=%v", ref.Domain, ref.Source, err)
			}
		}
	}
}

func (r *Runtime) RecordDomainChange(ctx context.Context, change DomainChange) {
	if r == nil || r.store == nil {
		return
	}
	ref, err := r.store.UpsertDomain(change)
	if err != nil {
		log.Printf("[reminder] cache_upsert_failed domain=%s source=%s err=%v", change.Domain, change.Source, err)
		return
	}
	r.enqueue(ctx, ref)
}

func (r *Runtime) RecordDomainDeletion(ctx context.Context, domain string, sources ...string) {
	if r == nil || r.store == nil {
		return
	}
	if err := r.store.DeleteDomain(domain, sources...); err != nil {
		log.Printf("[reminder] cache_delete_failed domain=%s sources=%v err=%v", domain, sources, err)
	}
}

func (r *Runtime) RecordOriginCert(ctx context.Context, domain string, source string, cert cfclient.OriginCert) {
	if r == nil || r.store == nil {
		return
	}
	domain = NormalizeDomain(domain)
	source = NormalizeSource(source)
	if domain == "" || cert.ExpiresOn.IsZero() {
		return
	}
	_, _ = r.store.UpsertDomain(DomainChange{Domain: domain, Source: source, IsCF: true})
	rec := CertificateRecord{
		Type:      CertTypeCFOrigin,
		ID:        cert.ID,
		Hostnames: append([]string(nil), cert.Hostnames...),
		Issuer:    "Cloudflare Origin CA",
		Subject:   strings.Join(cert.Hostnames, ","),
		NotAfter:  timeString(cert.ExpiresOn),
		UpdatedAt: time.Now().Format(time.RFC3339),
	}
	rec.Key = certificateKey(rec)
	if err := r.store.UpdateRecord(DomainRef{Domain: domain, Source: source}, func(record *Record) {
		record.IsCF = true
		record.Deleted = false
		record.PendingRefresh = true
		record.Certificates = mergeCertificates(record.Certificates, []CertificateRecord{rec})
	}); err != nil {
		log.Printf("[reminder] record_origin_cert_failed domain=%s source=%s err=%v", domain, source, err)
		return
	}
	r.enqueue(ctx, DomainRef{Domain: domain, Source: source})
}

func (r *Runtime) enqueue(ctx context.Context, ref DomainRef) {
	ref.Domain = NormalizeDomain(ref.Domain)
	ref.Source = NormalizeSource(ref.Source)
	if ref.Domain == "" {
		return
	}
	select {
	case r.jobs <- ref:
	case <-ctx.Done():
	default:
		go func() {
			select {
			case r.jobs <- ref:
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
				log.Printf("[reminder] refresh_queue_full domain=%s source=%s", ref.Domain, ref.Source)
			}
		}()
	}
}

func (r *Runtime) RefreshCandidates(ctx context.Context, alertDays int, now time.Time) error {
	if r == nil || r.store == nil {
		return nil
	}
	refs, err := r.store.ListRefreshCandidates(alertDays, now)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		if err := r.RefreshDomain(ctx, ref); err != nil {
			log.Printf("[reminder] daily_refresh_failed domain=%s source=%s err=%v", ref.Domain, ref.Source, err)
		}
		if r.refreshDelay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(r.refreshDelay):
			}
		}
	}
	return nil
}

func (r *Runtime) RefreshDomain(ctx context.Context, ref DomainRef) error {
	if r == nil || r.store == nil {
		return nil
	}
	ref.Domain = NormalizeDomain(ref.Domain)
	ref.Source = NormalizeSource(ref.Source)
	if ref.Domain == "" {
		return fmt.Errorf("域名为空")
	}

	var errorsList []string
	var domainExpiry string
	if t, ok, err := r.lookupDomainExpiry(ctx, ref.Domain); err == nil && ok {
		domainExpiry = dateString(t)
	} else if err != nil {
		errorsList = append(errorsList, err.Error())
	}

	certs := make([]CertificateRecord, 0, 4)
	if origin, err := r.lookupOriginCertificates(ctx, ref); err == nil {
		certs = append(certs, origin...)
	} else if err != nil {
		errorsList = append(errorsList, err.Error())
	}
	if served, err := r.lookupServedCertificate(ctx, ref.Domain); err == nil {
		certs = append(certs, served)
	} else if err != nil {
		errorsList = append(errorsList, err.Error())
	}

	now := time.Now().Format(time.RFC3339)
	return r.store.UpdateRecord(ref, func(rec *Record) {
		if domainExpiry != "" {
			if rec.DomainExpiry != domainExpiry {
				rec.DomainLastAlertDate = ""
			}
			rec.DomainExpiry = domainExpiry
			rec.DomainExpiryUpdatedAt = now
		}
		if len(certs) > 0 {
			rec.Certificates = mergeCertificates(rec.Certificates, certs)
		}
		rec.PendingRefresh = false
		rec.LastRefreshAt = now
		if len(errorsList) > 0 {
			rec.LastRefreshError = strings.Join(errorsList, "; ")
		} else {
			rec.LastRefreshError = ""
		}
	})
}

func (r *Runtime) lookupDomainExpiry(ctx context.Context, domain string) (time.Time, bool, error) {
	if r.registrar != nil {
		lookupCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
		_, t, err := r.registrar.GetExpireAtForDomain(lookupCtx, domain)
		cancel()
		if err == nil && !t.IsZero() {
			return t, true, nil
		}
	}
	if r.whois == nil {
		return time.Time{}, false, nil
	}
	lookupCtx, cancel := context.WithTimeout(ctx, r.queryTimeout)
	result, err := r.whois.Query(lookupCtx, domain)
	cancel()
	if err != nil {
		return time.Time{}, false, fmt.Errorf("域名到期查询失败: %w", err)
	}
	result = strings.TrimSpace(result)
	if t, err := time.Parse("2006-01-02", result); err == nil {
		return t, true, nil
	}
	expiry, ok := tools.ExtractExpiry(result)
	if !ok {
		return time.Time{}, false, fmt.Errorf("域名到期解析失败")
	}
	t, err := time.Parse("2006-01-02", strings.TrimSpace(expiry))
	if err != nil {
		return time.Time{}, false, fmt.Errorf("域名到期日期解析失败: %w", err)
	}
	return t, true, nil
}

func (r *Runtime) lookupServedCertificate(ctx context.Context, domain string) (CertificateRecord, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, r.tlsTimeout)
	defer cancel()
	return servedCertificate(lookupCtx, domain, r.tlsTimeout)
}

func (r *Runtime) lookupOriginCertificates(ctx context.Context, ref DomainRef) ([]CertificateRecord, error) {
	if r.cfClient == nil {
		return nil, nil
	}
	sources := r.refreshSources(ref)
	if len(sources) == 0 {
		return nil, nil
	}

	out := make([]CertificateRecord, 0)
	var errorsList []string
	for _, source := range sources {
		acc, ok := r.accountByLabel(source)
		if !ok {
			continue
		}
		certs, err := r.listOriginCerts(ctx, acc)
		if err != nil {
			errorsList = append(errorsList, fmt.Sprintf("%s: %v", source, err))
			continue
		}
		for _, cert := range certs {
			if cert.RevokedAt != nil || cert.ExpiresOn.IsZero() {
				continue
			}
			matched := false
			for _, host := range cert.Hostnames {
				if hostnameMatchesDomain(host, ref.Domain) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			rec := CertificateRecord{
				Type:      CertTypeCFOrigin,
				ID:        cert.ID,
				Hostnames: append([]string(nil), cert.Hostnames...),
				Issuer:    "Cloudflare Origin CA",
				Subject:   strings.Join(cert.Hostnames, ","),
				NotAfter:  timeString(cert.ExpiresOn),
				UpdatedAt: time.Now().Format(time.RFC3339),
			}
			rec.Key = certificateKey(rec)
			out = append(out, rec)
		}
	}
	if len(errorsList) > 0 && len(out) == 0 {
		return nil, fmt.Errorf("Cloudflare Origin CA 查询失败: %s", strings.Join(errorsList, "; "))
	}
	return out, nil
}

func (r *Runtime) refreshSources(ref DomainRef) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(source string) {
		source = NormalizeSource(source)
		if source == "" {
			return
		}
		key := normalizedSourceKey(source)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, source)
	}
	for _, source := range ref.Sources {
		add(source)
	}
	for _, source := range splitSourceDisplay(ref.Source) {
		add(source)
	}
	if len(out) == 0 && r.store != nil {
		if rec, ok, err := r.store.GetRecord(ref.Domain); err == nil && ok {
			for _, acc := range RecordAccounts(rec) {
				if acc.Unknown || strings.TrimSpace(acc.Status) == StatusUnknownAccount {
					continue
				}
				add(acc.Source)
			}
		}
	}
	return out
}

func (r *Runtime) listOriginCerts(ctx context.Context, account config.CF) ([]cfclient.OriginCACertInfo, error) {
	label := accountCacheLabel(account)
	r.originMu.Lock()
	cached, ok := r.originCache[label]
	if ok && time.Since(cached.loadedAt) < time.Hour {
		r.originMu.Unlock()
		return append([]cfclient.OriginCACertInfo(nil), cached.certs...), cached.err
	}
	r.originMu.Unlock()

	certs, err := r.cfClient.ListOriginCACertificates(ctx, account)
	r.originMu.Lock()
	r.originCache[label] = originCertCacheItem{loadedAt: time.Now(), certs: append([]cfclient.OriginCACertInfo(nil), certs...), err: err}
	r.originMu.Unlock()
	return certs, err
}

func (r *Runtime) accountByLabel(label string) (config.CF, bool) {
	label = strings.TrimSpace(label)
	for _, acc := range r.accounts {
		if strings.EqualFold(accountCacheLabel(acc), label) ||
			strings.EqualFold(strings.TrimSpace(acc.Label), label) ||
			strings.EqualFold(strings.TrimSpace(acc.AccountID), label) ||
			strings.EqualFold(strings.TrimSpace(acc.Email), label) {
			return acc, true
		}
	}
	return config.CF{}, false
}
