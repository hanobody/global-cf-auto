package registrarclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"DomainC/config"
)

const (
	registrarRateLimitCooldown = 15 * time.Minute
	registrarRequestInterval   = 3 * time.Second
)

// Manager 提供基于配置的注册商查询/修改能力。
type Manager struct {
	client          Client
	registrars      []config.Registrar
	limitMu         sync.Mutex
	limitedUntil    map[string]time.Time
	paceMu          sync.Mutex
	nextAllowed     map[string]time.Time
	domainMu        sync.RWMutex
	domainRegistrar map[string]string
}

type SyncError struct {
	Domain      string
	NotFound    []string
	RateLimited []string
	Failed      []string
}

func (e *SyncError) Error() string {
	if e == nil {
		return ""
	}
	var parts []string
	if len(e.NotFound) > 0 {
		parts = append(parts, "可访问账号未找到域名: "+strings.Join(e.NotFound, ", "))
	}
	if len(e.RateLimited) > 0 {
		parts = append(parts, "限流账号已跳过: "+strings.Join(e.RateLimited, ", "))
	}
	if len(e.Failed) > 0 {
		parts = append(parts, "异常账号: "+strings.Join(e.Failed, "; "))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%s: 注册商同步失败", e.Domain)
	}
	return fmt.Sprintf("%s: 注册商同步未完成（%s）", e.Domain, strings.Join(parts, "；"))
}

func (e *SyncError) Is(target error) bool {
	if target == ErrDomainNotFound {
		return len(e.NotFound) > 0 && len(e.RateLimited) == 0 && len(e.Failed) == 0
	}
	if target == ErrRegistrarRateLimited {
		return len(e.RateLimited) > 0
	}
	return false
}

func NewManager(client Client, registrars []config.Registrar) *Manager {
	if client == nil {
		client = NewClient()
	}
	return &Manager{
		client:          client,
		registrars:      registrars,
		limitedUntil:    make(map[string]time.Time),
		nextAllowed:     make(map[string]time.Time),
		domainRegistrar: make(map[string]string),
	}
}

func (m *Manager) Registrars() []config.Registrar {
	out := make([]config.Registrar, 0, len(m.registrars))
	for _, r := range m.registrars {
		if strings.TrimSpace(r.Label) == "" || strings.TrimSpace(r.Type) == "" {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (m *Manager) RegistrarByLabel(label string) (config.Registrar, bool) {
	if strings.TrimSpace(label) == "" {
		return config.Registrar{}, false
	}
	for _, r := range m.registrars {
		if strings.EqualFold(strings.TrimSpace(r.Label), strings.TrimSpace(label)) {
			return r, true
		}
	}
	return config.Registrar{}, false
}

func (m *Manager) registrarsForDomain(domain string) []config.Registrar {
	if strings.TrimSpace(domain) == "" {
		return nil
	}
	all := make([]config.Registrar, 0, len(m.registrars))
	for _, r := range m.registrars {
		if strings.TrimSpace(r.Label) == "" || strings.TrimSpace(r.Type) == "" {
			continue
		}
		all = append(all, r)
	}
	cachedLabel := m.cachedRegistrarLabel(domain)
	if cachedLabel == "" {
		return all
	}
	results := make([]config.Registrar, 0, len(all))
	for _, r := range all {
		if strings.EqualFold(strings.TrimSpace(r.Label), cachedLabel) {
			results = append(results, r)
			break
		}
	}
	for _, r := range all {
		if strings.EqualFold(strings.TrimSpace(r.Label), cachedLabel) {
			continue
		}
		results = append(results, r)
	}
	return results
}

// SetNameServersForDomain 尝试将 NS 写入到对应注册商。
func (m *Manager) SetNameServersForDomain(ctx context.Context, domain string, nameServers []string) (config.Registrar, error) {
	if len(m.registrars) == 0 {
		return config.Registrar{}, fmt.Errorf("未配置注册商")
	}

	syncErr := &SyncError{Domain: strings.TrimSpace(domain)}
	for _, r := range m.registrarsForDomain(domain) {
		isCached := m.isCachedRegistrar(domain, r)
		if m.isRegistrarRateLimited(r) {
			syncErr.RateLimited = append(syncErr.RateLimited, strings.TrimSpace(r.Label)+"(cooldown)")
			if isCached {
				return config.Registrar{}, syncErr
			}
			continue
		}
		if err := m.waitRegistrarPace(ctx, r); err != nil {
			syncErr.Failed = append(syncErr.Failed, fmt.Sprintf("[%s] 等待限速失败: %v", r.Label, err))
			continue
		}
		err := m.client.SetNameServers(ctx, r, domain, nameServers)
		if err != nil {
			if errors.Is(err, ErrDomainNotFound) {
				syncErr.NotFound = append(syncErr.NotFound, strings.TrimSpace(r.Label))
				if isCached {
					m.clearDomainRegistrar(domain)
				}
				continue
			}
			if errors.Is(err, ErrRegistrarRateLimited) {
				m.markRegistrarRateLimited(r)
				syncErr.RateLimited = append(syncErr.RateLimited, strings.TrimSpace(r.Label))
				if isCached {
					return config.Registrar{}, syncErr
				}
				continue
			}
			syncErr.Failed = append(syncErr.Failed, fmt.Sprintf("[%s] %v", r.Label, err))
			continue
		}
		m.rememberDomainRegistrar(domain, r)
		return r, nil
	}

	if len(syncErr.NotFound) == 0 && len(syncErr.RateLimited) == 0 && len(syncErr.Failed) == 0 {
		return config.Registrar{}, fmt.Errorf("%w: 未在任何注册商账号下找到该域名", ErrDomainNotFound)
	}
	return config.Registrar{}, syncErr
}

func (m *Manager) waitRegistrarPace(ctx context.Context, registrar config.Registrar) error {
	label := strings.TrimSpace(registrar.Label)
	if label == "" || registrarRequestInterval <= 0 {
		return nil
	}
	for {
		m.paceMu.Lock()
		if m.nextAllowed == nil {
			m.nextAllowed = make(map[string]time.Time)
		}
		now := time.Now()
		next := m.nextAllowed[label]
		if next.IsZero() || !now.Before(next) {
			m.nextAllowed[label] = now.Add(registrarRequestInterval)
			m.paceMu.Unlock()
			return nil
		}
		wait := next.Sub(now)
		m.paceMu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (m *Manager) isRegistrarRateLimited(registrar config.Registrar) bool {
	label := strings.TrimSpace(registrar.Label)
	if label == "" {
		return false
	}
	m.limitMu.Lock()
	defer m.limitMu.Unlock()
	if m.limitedUntil == nil {
		m.limitedUntil = make(map[string]time.Time)
		return false
	}
	until, ok := m.limitedUntil[label]
	if !ok {
		return false
	}
	if time.Now().Before(until) {
		return true
	}
	delete(m.limitedUntil, label)
	return false
}

func (m *Manager) markRegistrarRateLimited(registrar config.Registrar) {
	label := strings.TrimSpace(registrar.Label)
	if label == "" {
		return
	}
	m.limitMu.Lock()
	defer m.limitMu.Unlock()
	if m.limitedUntil == nil {
		m.limitedUntil = make(map[string]time.Time)
	}
	m.limitedUntil[label] = time.Now().Add(registrarRateLimitCooldown)
}

func (m *Manager) cachedRegistrarLabel(domain string) string {
	key := normalizeRegistrarDomainKey(domain)
	if key == "" {
		return ""
	}
	m.domainMu.RLock()
	defer m.domainMu.RUnlock()
	return m.domainRegistrar[key]
}

func (m *Manager) isCachedRegistrar(domain string, registrar config.Registrar) bool {
	cached := m.cachedRegistrarLabel(domain)
	return cached != "" && strings.EqualFold(cached, strings.TrimSpace(registrar.Label))
}

func (m *Manager) rememberDomainRegistrar(domain string, registrar config.Registrar) {
	key := normalizeRegistrarDomainKey(domain)
	label := strings.TrimSpace(registrar.Label)
	if key == "" || label == "" {
		return
	}
	m.domainMu.Lock()
	defer m.domainMu.Unlock()
	if m.domainRegistrar == nil {
		m.domainRegistrar = make(map[string]string)
	}
	m.domainRegistrar[key] = label
}

func (m *Manager) clearDomainRegistrar(domain string) {
	key := normalizeRegistrarDomainKey(domain)
	if key == "" {
		return
	}
	m.domainMu.Lock()
	defer m.domainMu.Unlock()
	delete(m.domainRegistrar, key)
}

func normalizeRegistrarDomainKey(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func (m *Manager) GetExpireAtForDomain(ctx context.Context, domain string) (config.Registrar, time.Time, error) {
	if len(m.registrars) == 0 {
		return config.Registrar{}, time.Time{}, fmt.Errorf("未配置注册商")
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return config.Registrar{}, time.Time{}, fmt.Errorf("域名不能为空")
	}

	// 通过 type assertion 使用底层实现，避免改动 Client 接口
	type namecheapExpireGetter interface {
		namecheapGetExpireAt(ctx context.Context, cfg config.NamecheapConfig, domain string) (time.Time, error)
	}

	getter, ok := m.client.(namecheapExpireGetter)
	if !ok {
		return config.Registrar{}, time.Time{}, fmt.Errorf("当前 client 不支持获取到期时间")
	}

	var lastErr error
	for _, r := range m.registrarsForDomain(domain) {
		if strings.ToLower(strings.TrimSpace(r.Type)) != "namecheap" || r.Namecheap == nil {
			continue
		}

		expAt, err := getter.namecheapGetExpireAt(ctx, *r.Namecheap, domain)
		if err != nil {
			// 该账号下没有这个域名：继续尝试下一个账号
			if errors.Is(err, ErrDomainNotFound) {
				continue
			}
			lastErr = fmt.Errorf("[%s] %w", r.Label, err)
			continue
		}

		return r, expAt, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("未在任何 namecheap 账号下找到该域名")
	}
	return config.Registrar{}, time.Time{}, lastErr
}

// GetNameServersForDomain 尝试从注册商读取 NS。
func (m *Manager) GetNameServersForDomain(ctx context.Context, domain string) (config.Registrar, []string, error) {
	if len(m.registrars) == 0 {
		return config.Registrar{}, nil, fmt.Errorf("未配置注册商")
	}
	syncErr := &SyncError{Domain: strings.TrimSpace(domain)}
	for _, r := range m.registrarsForDomain(domain) {
		isCached := m.isCachedRegistrar(domain, r)
		if m.isRegistrarRateLimited(r) {
			syncErr.RateLimited = append(syncErr.RateLimited, strings.TrimSpace(r.Label)+"(cooldown)")
			if isCached {
				return config.Registrar{}, nil, syncErr
			}
			continue
		}
		if err := m.waitRegistrarPace(ctx, r); err != nil {
			syncErr.Failed = append(syncErr.Failed, fmt.Sprintf("[%s] 等待限速失败: %v", r.Label, err))
			continue
		}
		ns, err := m.client.GetNameServers(ctx, r, domain)
		if err != nil {
			if errors.Is(err, ErrDomainNotFound) {
				syncErr.NotFound = append(syncErr.NotFound, strings.TrimSpace(r.Label))
				if isCached {
					m.clearDomainRegistrar(domain)
				}
				continue
			}
			if errors.Is(err, ErrRegistrarRateLimited) {
				m.markRegistrarRateLimited(r)
				syncErr.RateLimited = append(syncErr.RateLimited, strings.TrimSpace(r.Label))
				if isCached {
					return config.Registrar{}, nil, syncErr
				}
				continue
			}
			syncErr.Failed = append(syncErr.Failed, fmt.Sprintf("[%s] %v", r.Label, err))
			continue
		}
		m.rememberDomainRegistrar(domain, r)
		return r, ns, nil
	}
	if len(syncErr.NotFound) == 0 && len(syncErr.RateLimited) == 0 && len(syncErr.Failed) == 0 {
		return config.Registrar{}, nil, fmt.Errorf("没有可用的注册商")
	}
	return config.Registrar{}, nil, syncErr
}

// ListDomainsForRegistrar 查询指定注册商的域名列表。
func (m *Manager) ListDomainsForRegistrar(ctx context.Context, registrar config.Registrar) ([]string, error) {
	return m.client.ListDomains(ctx, registrar)
}
