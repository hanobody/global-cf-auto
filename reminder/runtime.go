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

	originMu    sync.Mutex
	originCache map[string]originCertCacheItem
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

func (r *Runtime) RecordDomainDeletion(ctx context.Context, domain string) {
	if r == nil || r.store == nil {
		return
	}
	if err := r.store.DeleteDomain(domain); err != nil {
		log.Printf("[reminder] cache_delete_failed domain=%s err=%v", domain, err)
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
	if r.cfClient == nil || strings.TrimSpace(ref.Source) == "" {
		return nil, nil
	}
	acc, ok := r.accountByLabel(ref.Source)
	if !ok {
		return nil, nil
	}
	certs, err := r.listOriginCerts(ctx, acc)
	if err != nil {
		return nil, fmt.Errorf("Cloudflare Origin CA 查询失败: %w", err)
	}
	out := make([]CertificateRecord, 0)
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
	return out, nil
}

func (r *Runtime) listOriginCerts(ctx context.Context, account config.CF) ([]cfclient.OriginCACertInfo, error) {
	label := strings.TrimSpace(account.Label)
	if label == "" {
		label = account.AccountID
	}
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
		if strings.EqualFold(strings.TrimSpace(acc.Label), label) {
			return acc, true
		}
	}
	return config.CF{}, false
}
