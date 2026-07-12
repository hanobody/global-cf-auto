package cfclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"DomainC/config"
)

const (
	cfAPIBaseURL              = "https://api.cloudflare.com/client/v4"
	countryBlockRuleDesc      = "telegram-auto-block-countries"
	countryBlockRulesetName   = "telegram-auto-waf"
	firewallCustomPhase       = "http_request_firewall_custom"
	statusCreated             = "created"
	statusUpdated             = "updated"
	statusAlreadyExists       = "already_exists"
	statusAlreadyEnabled      = "already_enabled"
	statusEnabled             = "enabled"
	statusSkipped             = "skipped"
	statusFailedPrefix         = "failed: "
	maxCloudflareHTTPRetries   = 2
	countryBlockVerifyAttempts = 5
	countryBlockVerifyDelay    = 250 * time.Millisecond
	defaultHTTPRetryBaseDelay  = 500 * time.Millisecond
)

// Provisioner is implemented by the default Cloudflare client. It is kept
// separate from Client so older tests and fakes do not need to implement the
// provisioning surface unless they use it directly.
type Provisioner interface {
	ProvisionCloudflareZone(ctx context.Context, account config.CF, domain string, opts ProvisionOptions) (*ProvisionResult, error)
}

type ProvisionOptions struct {
	AccountID           string
	BlockCountries      []string
	EnableSpeed         bool
	EnableRUM           bool
	ExtraZoneSettings   map[string]any
	CreateZoneIfMissing bool
}

type ProvisionResult struct {
	Domain                string
	ZoneID                string
	ZoneStatus            string
	ZoneCreated           bool
	NameServers           []string
	CountryBlockStatus    string
	CountryBlockCountries []string
	SpeedStatus           map[string]string
	CacheRuleStatus       string
	RUMStatus             string
	Warnings              []string
}

type CloudflareAPIError struct {
	StatusCode int
	Method     string
	Path       string
	Messages   []string
}

func (e *CloudflareAPIError) Error() string {
	msg := strings.TrimSpace(strings.Join(e.Messages, "; "))
	if msg == "" {
		msg = "unknown Cloudflare API error"
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("Cloudflare API %s %s failed: HTTP %d: %s", e.Method, e.Path, e.StatusCode, msg)
	}
	return fmt.Sprintf("Cloudflare API %s %s failed: %s", e.Method, e.Path, msg)
}

func (e *CloudflareAPIError) IsStatus(code int) bool {
	return e != nil && e.StatusCode == code
}

type cfAPIMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfAPIEnvelope struct {
	Success  bool            `json:"success"`
	Errors   []cfAPIMessage  `json:"errors"`
	Messages []cfAPIMessage  `json:"messages"`
	Result   json.RawMessage `json:"result"`
}

func (c *apiClient) cloudflareBaseURL() string {
	if strings.TrimSpace(c.baseURL) != "" {
		return strings.TrimRight(c.baseURL, "/")
	}
	return cfAPIBaseURL
}

func (c *apiClient) cloudflareHTTPClient() *http.Client {
	if c.httpClient != nil {
		return c.httpClient
	}
	return http.DefaultClient
}

func (c *apiClient) Do(ctx context.Context, account config.CF, method, path string, body any, out any) error {
	ctx, cancel := ensureTimeout(ctx)
	defer cancel()

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal Cloudflare request body failed: %w", err)
		}
	}

	endpoint := path
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = c.cloudflareBaseURL() + "/" + strings.TrimLeft(path, "/")
	}

	var lastErr error
	for attempt := 0; attempt <= maxCloudflareHTTPRetries; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(1<<uint(attempt-1)) * defaultHTTPRetryBaseDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}

		var reader io.Reader
		if bodyBytes != nil {
			reader = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+account.APIToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.cloudflareHTTPClient().Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		respBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}

		var envelope cfAPIEnvelope
		if len(respBody) > 0 {
			if err := json.Unmarshal(respBody, &envelope); err != nil {
				lastErr = fmt.Errorf("decode Cloudflare response failed: %w", err)
				if shouldRetryHTTPStatus(resp.StatusCode) {
					continue
				}
				return lastErr
			}
		}

		if resp.StatusCode >= http.StatusBadRequest || !envelope.Success {
			apiErr := &CloudflareAPIError{
				StatusCode: resp.StatusCode,
				Method:     method,
				Path:       path,
				Messages:   cloudflareMessages(envelope.Errors, envelope.Messages),
			}
			lastErr = apiErr
			if shouldRetryHTTPStatus(resp.StatusCode) && attempt < maxCloudflareHTTPRetries {
				continue
			}
			return apiErr
		}

		if out == nil || len(envelope.Result) == 0 || string(envelope.Result) == "null" {
			return nil
		}
		if raw, ok := out.(*json.RawMessage); ok {
			*raw = append((*raw)[:0], envelope.Result...)
			return nil
		}
		if err := json.Unmarshal(envelope.Result, out); err != nil {
			return fmt.Errorf("decode Cloudflare result failed: %w", err)
		}
		return nil
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("Cloudflare request failed")
}

func shouldRetryHTTPStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

func cloudflareMessages(errors []cfAPIMessage, messages []cfAPIMessage) []string {
	out := make([]string, 0, len(errors)+len(messages))
	for _, item := range errors {
		if msg := strings.TrimSpace(item.Message); msg != "" {
			out = append(out, msg)
		}
	}
	if len(out) == 0 {
		for _, item := range messages {
			if msg := strings.TrimSpace(item.Message); msg != "" {
				out = append(out, msg)
			}
		}
	}
	if len(out) == 0 {
		out = append(out, "unknown Cloudflare API error")
	}
	return out
}

type provisionZoneResult struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	Paused      bool     `json:"paused"`
	NameServers []string `json:"name_servers"`
}

func (c *apiClient) ProvisionCloudflareZone(ctx context.Context, account config.CF, domain string, opts ProvisionOptions) (*ProvisionResult, error) {
	domain = normalizeProvisionDomain(domain)
	if domain == "" {
		return nil, errors.New("domain is empty")
	}

	accountID := strings.TrimSpace(opts.AccountID)
	if accountID == "" {
		accountID = strings.TrimSpace(account.AccountID)
	}
	if accountID == "" {
		var err error
		accountID, err = c.GetAccountID(ctx, account)
		if err != nil {
			return nil, err
		}
	}

	zone, created, err := c.findOrCreateZoneForProvision(ctx, account, accountID, domain, opts.CreateZoneIfMissing)
	if err != nil {
		return nil, err
	}

	result := &ProvisionResult{
		Domain:              zone.Name,
		ZoneID:              zone.ID,
		ZoneStatus:          zone.Status,
		ZoneCreated:         created,
		NameServers:         append([]string(nil), zone.NameServers...),
		CountryBlockStatus:  statusSkipped,
		SpeedStatus:         map[string]string{},
		CacheRuleStatus:     statusSkipped,
		RUMStatus:           statusSkipped,
		CountryBlockCountries: nil,
	}
	if result.Domain == "" {
		result.Domain = domain
	}
	return result, nil
}

func normalizeProvisionDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	if idx := strings.IndexByte(domain, '/'); idx >= 0 {
		domain = domain[:idx]
	}
	return strings.TrimSuffix(domain, ".")
}

func (c *apiClient) findOrCreateZoneForProvision(ctx context.Context, account config.CF, accountID string, domain string, createIfMissing bool) (provisionZoneResult, bool, error) {
	q := url.Values{}
	q.Set("name", domain)
	if accountID != "" {
		q.Set("account.id", accountID)
	}

	var list []provisionZoneResult
	if err := c.Do(ctx, account, http.MethodGet, "/zones?"+q.Encode(), nil, &list); err != nil {
		return provisionZoneResult{}, false, err
	}
	for _, zone := range list {
		if strings.EqualFold(strings.TrimSpace(zone.Name), domain) {
			return zone, false, nil
		}
	}

	if !createIfMissing {
		return provisionZoneResult{}, false, fmt.Errorf("%w: %s", ErrZoneNotFound, domain)
	}

	req := map[string]any{
		"name":       domain,
		"jump_start": false,
		"type":       "full",
		"account": map[string]string{
			"id": accountID,
		},
	}
	var created provisionZoneResult
	if err := c.Do(ctx, account, http.MethodPost, "/zones", req, &created); err != nil {
		return provisionZoneResult{}, false, err
	}
	return created, true, nil
}

func NormalizeCountryCodes(countries []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(countries))
	for _, raw := range countries {
		fields := strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' || r == '\r'
		})
		for _, field := range fields {
			code := strings.ToUpper(strings.TrimSpace(field))
			if code == "" {
				continue
			}
			if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
				return nil, fmt.Errorf("invalid country/region code %q: must be a 2-letter ISO 3166-1 alpha-2 code", field)
			}
			if _, ok := seen[code]; ok {
				continue
			}
			seen[code] = struct{}{}
			out = append(out, code)
		}
	}
	return out, nil
}

func buildCountryBlockExpression(countries []string) string {
	quoted := make([]string, 0, len(countries))
	for _, code := range countries {
		quoted = append(quoted, fmt.Sprintf("%q", code))
	}
	return fmt.Sprintf("ip.src.country in {%s}", strings.Join(quoted, " "))
}

type rulesetRule struct {
	ID               string `json:"id,omitempty"`
	Description      string `json:"description"`
	Expression       string `json:"expression"`
	Action           string `json:"action"`
	Enabled          bool   `json:"enabled"`
	ActionParameters any    `json:"action_parameters,omitempty"`
}

type rulesetEntryPoint struct {
	ID    string        `json:"id"`
	Rules []rulesetRule `json:"rules"`
}

func (c *apiClient) EnsureCountryBlockRule(ctx context.Context, account config.CF, zoneID string, countries []string) (string, error) {
	normalized, err := NormalizeCountryCodes(countries)
	if err != nil {
		return "", err
	}
	if len(normalized) == 0 {
		return statusSkipped, nil
	}

	expression := buildCountryBlockExpression(normalized)
	rule := rulesetRule{
		Description: countryBlockRuleDesc,
		Expression:  expression,
		Action:      "block",
		Enabled:     true,
	}

	var entry rulesetEntryPoint
	path := fmt.Sprintf("/zones/%s/rulesets/phases/%s/entrypoint", zoneID, firewallCustomPhase)
	err = c.Do(ctx, account, http.MethodGet, path, nil, &entry)
	if err != nil {
		var apiErr *CloudflareAPIError
		if errors.As(err, &apiErr) && apiErr.IsStatus(http.StatusNotFound) {
			req := map[string]any{
				"name":  countryBlockRulesetName,
				"kind":  "zone",
				"phase": firewallCustomPhase,
				"rules": []rulesetRule{rule},
			}
			if err := c.Do(ctx, account, http.MethodPost, fmt.Sprintf("/zones/%s/rulesets", zoneID), req, nil); err != nil {
				return "", err
			}
			if err := c.verifyCountryBlockRule(ctx, account, zoneID, expression); err != nil {
				return "", err
			}
			return statusCreated, nil
		}
		return "", err
	}
	if strings.TrimSpace(entry.ID) == "" {
		return "", errors.New("Cloudflare firewall entrypoint ruleset id is empty")
	}

	var target rulesetRule
	var duplicates []rulesetRule
	for _, existing := range entry.Rules {
		if existing.Description != countryBlockRuleDesc {
			continue
		}
		if strings.TrimSpace(target.Description) == "" {
			target = existing
			continue
		}
		duplicates = append(duplicates, existing)
	}
	if strings.TrimSpace(target.Description) != "" {
		if strings.TrimSpace(target.ID) == "" {
			return "", errors.New("Cloudflare firewall rule id is empty")
		}
		status := statusAlreadyExists
		if !countryBlockRuleMatches(target, expression) {
			rule.ID = target.ID
			updatePath := fmt.Sprintf("/zones/%s/rulesets/%s/rules/%s", zoneID, entry.ID, target.ID)
			if err := c.Do(ctx, account, http.MethodPatch, updatePath, rule, nil); err != nil {
				return "", err
			}
			status = statusUpdated
		}
		for _, duplicate := range duplicates {
			if strings.TrimSpace(duplicate.ID) == "" {
				return "", errors.New("Cloudflare duplicate firewall rule id is empty")
			}
			deletePath := fmt.Sprintf("/zones/%s/rulesets/%s/rules/%s", zoneID, entry.ID, duplicate.ID)
			if err := c.Do(ctx, account, http.MethodDelete, deletePath, nil, nil); err != nil {
				return "", err
			}
			status = statusUpdated
		}
		if status == statusUpdated {
			if err := c.verifyCountryBlockRule(ctx, account, zoneID, expression); err != nil {
				return "", err
			}
		}
		return status, nil
	}

	if err := c.Do(ctx, account, http.MethodPost, fmt.Sprintf("/zones/%s/rulesets/%s/rules", zoneID, entry.ID), rule, nil); err != nil {
		return "", err
	}
	if err := c.verifyCountryBlockRule(ctx, account, zoneID, expression); err != nil {
		return "", err
	}
	return statusCreated, nil
}

func (c *apiClient) verifyCountryBlockRule(ctx context.Context, account config.CF, zoneID string, expression string) error {
	path := fmt.Sprintf("/zones/%s/rulesets/phases/%s/entrypoint", zoneID, firewallCustomPhase)
	var lastErr error
	for attempt := 0; attempt < countryBlockVerifyAttempts; attempt++ {
		if err := waitCountryBlockVerifyRetry(ctx, attempt); err != nil {
			return err
		}
		var entry rulesetEntryPoint
		if err := c.Do(ctx, account, http.MethodGet, path, nil, &entry); err != nil {
			lastErr = err
			continue
		}
		if strings.TrimSpace(entry.ID) == "" {
			lastErr = errors.New("Cloudflare firewall entrypoint ruleset id is empty after write")
			continue
		}
		for _, existing := range entry.Rules {
			if countryBlockRuleMatches(existing, expression) {
				return nil
			}
		}
		lastErr = fmt.Errorf("Cloudflare firewall rule %q is not visible after write", countryBlockRuleDesc)
	}
	if lastErr != nil {
		return fmt.Errorf("verify Cloudflare country block rule failed: %w", lastErr)
	}
	return errors.New("verify Cloudflare country block rule failed")
}

func waitCountryBlockVerifyRetry(ctx context.Context, attempt int) error {
	if attempt <= 0 {
		return nil
	}
	timer := time.NewTimer(time.Duration(attempt) * countryBlockVerifyDelay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func countryBlockRuleMatches(existing rulesetRule, expression string) bool {
	return existing.Description == countryBlockRuleDesc &&
		normalizeRulesetExpression(existing.Expression) == normalizeRulesetExpression(expression) &&
		strings.EqualFold(existing.Action, "block") &&
		existing.Enabled
}

func normalizeRulesetExpression(value string) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	for strings.HasPrefix(value, "(") && strings.HasSuffix(value, ")") && len(value) > 1 {
		value = strings.TrimSpace(value[1 : len(value)-1])
		value = strings.Join(strings.Fields(value), " ")
	}
	return value
}

func (c *apiClient) EnableSpeedRecommendations(ctx context.Context, account config.CF, zoneID string, extraSettings map[string]any) map[string]string {
	status := c.EnableCloudflareStandardSpeedRecommendations(ctx, account, zoneID)
	for _, key := range sortedMapKeys(extraSettings) {
		extra := c.applyZoneSettings(ctx, account, zoneID, map[string]any{key: extraSettings[key]})
		for settingID, settingStatus := range extra {
			status[settingID] = settingStatus
		}
	}
	return status
}

func sortedMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		key = strings.TrimSpace(key)
		if key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

type rumRule struct {
	Host string `json:"host"`
}

type rumRuleset struct {
	ZoneTag string `json:"zone_tag"`
}

type rumSite struct {
	ID              string     `json:"id"`
	SiteID          string     `json:"site_id"`
	SiteTag         string     `json:"site_tag"`
	Host            string     `json:"host"`
	ZoneTag         string     `json:"zone_tag"`
	AutoInstall     bool       `json:"auto_install"`
	Rules           []rumRule  `json:"rules"`
	Ruleset         rumRuleset `json:"ruleset"`
	AutoInstallBool *bool      `json:"-"`
}

func (s rumSite) siteID() string {
	if strings.TrimSpace(s.ID) != "" {
		return strings.TrimSpace(s.ID)
	}
	if strings.TrimSpace(s.SiteID) != "" {
		return strings.TrimSpace(s.SiteID)
	}
	return strings.TrimSpace(s.SiteTag)
}

func (s rumSite) matches(domain string, zoneID string) bool {
	domain = strings.TrimSpace(strings.ToLower(domain))
	zoneID = strings.TrimSpace(zoneID)
	if strings.EqualFold(strings.TrimSpace(s.Host), domain) {
		return true
	}
	if zoneID != "" && strings.EqualFold(strings.TrimSpace(s.ZoneTag), zoneID) {
		return true
	}
	if zoneID != "" && strings.EqualFold(strings.TrimSpace(s.Ruleset.ZoneTag), zoneID) {
		return true
	}
	for _, rule := range s.Rules {
		if strings.EqualFold(strings.TrimSpace(rule.Host), domain) {
			return true
		}
	}
	return false
}

func (c *apiClient) EnsureRUMAutoInstall(ctx context.Context, account config.CF, accountID, zoneID, domain string) (string, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		return "", errors.New("Cloudflare account id is empty")
	}
	domain = normalizeProvisionDomain(domain)
	var raw json.RawMessage
	if err := c.Do(ctx, account, http.MethodGet, fmt.Sprintf("/accounts/%s/rum/site_info/list", accountID), nil, &raw); err != nil {
		return "", classifyRUMError(err)
	}

	for _, site := range decodeRUMSites(raw) {
		if !site.matches(domain, zoneID) {
			continue
		}
		if site.AutoInstall {
			return statusAlreadyEnabled, nil
		}
		siteID := site.siteID()
		if siteID == "" {
			return "", errors.New("Cloudflare RUM site id is empty")
		}
		req := map[string]any{
			"auto_install": true,
			"host":         domain,
			"zone_tag":     zoneID,
		}
		if err := c.Do(ctx, account, http.MethodPut, fmt.Sprintf("/accounts/%s/rum/site_info/%s", accountID, siteID), req, nil); err != nil {
			return "", classifyRUMError(err)
		}
		return statusUpdated, nil
	}

	req := map[string]any{
		"auto_install": true,
		"host":         domain,
		"zone_tag":     zoneID,
	}
	if err := c.Do(ctx, account, http.MethodPost, fmt.Sprintf("/accounts/%s/rum/site_info", accountID), req, nil); err != nil {
		return "", classifyRUMError(err)
	}
	return statusCreated, nil
}

func classifyRUMError(err error) error {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "permission") || strings.Contains(msg, "not authorized") || strings.Contains(msg, "authentication") {
		return fmt.Errorf("missing_permission: API Token 缺少 Web Analytics/RUM 读取或编辑权限: %w", err)
	}
	return err
}

func decodeRUMSites(raw json.RawMessage) []rumSite {
	var direct []rumSite
	if err := json.Unmarshal(raw, &direct); err == nil {
		return direct
	}

	var wrapped struct {
		Sites    []rumSite `json:"sites"`
		SiteInfo []rumSite `json:"site_info"`
		Items    []rumSite `json:"items"`
		Result   []rumSite `json:"result"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil
	}
	switch {
	case len(wrapped.Sites) > 0:
		return wrapped.Sites
	case len(wrapped.SiteInfo) > 0:
		return wrapped.SiteInfo
	case len(wrapped.Items) > 0:
		return wrapped.Items
	default:
		return wrapped.Result
	}
}

func FormatProvisionResult(result ProvisionResult) string {
	var sb strings.Builder
	sb.WriteString("✅ Cloudflare 初始化完成\n\n")
	sb.WriteString("域名：" + normalizeDisplay(result.Domain) + "\n")
	sb.WriteString("Zone ID：" + normalizeDisplay(result.ZoneID) + "\n")
	if result.ZoneCreated {
		sb.WriteString("Zone 状态：新建成功\n")
	} else {
		sb.WriteString("Zone 状态：已存在，已执行初始化\n")
	}

	sb.WriteString("\n安全规则：\n")
	sb.WriteString("- 国家/地区拦截：" + formatCountryBlockStatus(result.CountryBlockStatus, result.CountryBlockCountries) + "\n")

	sb.WriteString("\n速度设置：\n")
	if len(result.SpeedStatus) == 0 {
		sb.WriteString("- speed_brain：已跳过\n")
	} else {
		for _, key := range sortedSpeedStatusKeys(result.SpeedStatus) {
			sb.WriteString(fmt.Sprintf("- %s：%s\n", key, formatSettingStatus(result.SpeedStatus[key])))
		}
	}

	sb.WriteString("\nRUM：\n")
	sb.WriteString("- Web Analytics 自动注入：" + formatRUMStatus(result.RUMStatus) + "\n")

	if len(result.NameServers) > 0 {
		sb.WriteString("\nNameservers：\n")
		for _, ns := range result.NameServers {
			sb.WriteString("- " + ns + "\n")
		}
	}

	if len(result.Warnings) > 0 {
		sb.WriteString("\n警告：\n")
		for _, warning := range result.Warnings {
			sb.WriteString("- " + warning + "\n")
		}
	}

	sb.WriteString("\n注意：\n")
	sb.WriteString("- 若 DNS 记录不是 Proxied/橙云，WAF、RUM 自动注入和加速不会对该记录生效。")
	return sb.String()
}

func normalizeDisplay(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return s
}

func formatCountryBlockStatus(status string, countries []string) string {
	countryText := strings.Join(countries, ",")
	switch {
	case status == statusCreated:
		return "已启用 " + countryText
	case status == statusUpdated:
		return "已更新为 " + countryText
	case status == statusAlreadyExists:
		return "已存在 " + countryText
	case status == statusSkipped || strings.TrimSpace(status) == "":
		return "已跳过"
	case strings.HasPrefix(status, statusFailedPrefix):
		return "失败：" + strings.TrimPrefix(status, statusFailedPrefix)
	default:
		return status
	}
}

func formatSettingStatus(status string) string {
	switch {
	case status == statusEnabled:
		return "已开启"
	case status == statusSkipped || strings.TrimSpace(status) == "":
		return "已跳过"
	case strings.HasPrefix(status, statusFailedPrefix):
		return "失败：" + strings.TrimPrefix(status, statusFailedPrefix)
	default:
		return status
	}
}

func formatRUMStatus(status string) string {
	switch {
	case status == statusCreated:
		return "已创建并开启"
	case status == statusUpdated:
		return "已存在并更新为开启"
	case status == statusAlreadyEnabled:
		return "已开启"
	case status == statusSkipped || strings.TrimSpace(status) == "":
		return "已跳过"
	case strings.HasPrefix(status, statusFailedPrefix):
		return "失败：" + strings.TrimPrefix(status, statusFailedPrefix)
	default:
		return status
	}
}

func sortedSpeedStatusKeys(status map[string]string) []string {
	keys := make([]string, 0, len(status))
	for key := range status {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i] == "speed_brain" {
			return true
		}
		if keys[j] == "speed_brain" {
			return false
		}
		return keys[i] < keys[j]
	})
	return keys
}
