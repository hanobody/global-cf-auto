package cfclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"time"

	"DomainC/config"
)

const (
	cacheSettingsPhase     = "http_request_cache_settings"
	cacheRulesetName       = "telegram-auto-cache-rules"
	staticCacheRuleDesc    = "缓存默认文件扩展名 [模板]"
	staticCacheRuleExpr    = `(http.request.uri.path.extension in {"7z" "avi" "avif" "apk" "bin" "bmp" "bz2" "class" "css" "csv" "doc" "docx" "dmg" "ejs" "eot" "eps" "exe" "flac" "gif" "gz" "ico" "iso" "jar" "jpg" "jpeg" "js" "mid" "midi" "mkv" "mp3" "mp4" "ogg" "otf" "pdf" "pict" "pls" "png" "ppt" "pptx" "ps" "rar" "svg" "svgz" "swf" "tar" "tif" "tiff" "ttf" "webm" "webp" "woff" "woff2" "xls" "xlsx" "zip" "zst"})`
	statusMissing          = "missing"
	statusDeleted          = "deleted"
	statusNotFound         = "not_found"
	defaultPostInitTimeout = 6 * time.Hour
	defaultSSLPollInterval = 2 * time.Minute
)

type PostInitOptions struct {
	AccountID           string
	BlockCountries      []string
	EnableSecurityRules bool
	EnableSpeedSettings bool
	EnableCacheRule     bool
	EnableRUM           bool
	ZoneActiveTimeout   time.Duration
	SSLActiveTimeout    time.Duration
	PollInterval        time.Duration
}

type PostInitResult struct {
	Domain             string
	ZoneID             string
	ZoneStatus         string
	SSLStatus          string
	SecurityRuleStatus string
	SpeedStatus        map[string]string
	CacheRuleStatus    string
	RUMStatus           string
	Warnings           []string
	Errors             []string
}

type FeatureManageOptions struct {
	AccountID      string
	BlockCountries []string
	Action         string
	Security       bool
	Speed          bool
	Cache          bool
}

type FeatureManageResult struct {
	Domain             string
	ZoneID             string
	SecurityRuleStatus string
	SpeedStatus        map[string]string
	CacheRuleStatus    string
	Warnings           []string
	Errors             []string
}

type zoneStatusResult struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	NameServers []string `json:"name_servers"`
}

type universalSSLSettings struct {
	Enabled bool `json:"enabled"`
}

func (c *apiClient) RunPostSSLInit(ctx context.Context, account config.CF, domain string, zoneID string, opts PostInitOptions) (*PostInitResult, error) {
	domain = normalizeProvisionDomain(domain)
	zoneID = strings.TrimSpace(zoneID)
	if zoneID == "" {
		return nil, errors.New("zone id is empty")
	}
	opts = normalizePostInitOptions(opts)

	result := &PostInitResult{
		Domain:             domain,
		ZoneID:             zoneID,
		SecurityRuleStatus: statusSkipped,
		SpeedStatus:        map[string]string{},
		CacheRuleStatus:    statusSkipped,
		RUMStatus:          statusSkipped,
	}

	zoneStatus, err := c.WaitZoneActive(ctx, account, zoneID, opts.ZoneActiveTimeout, opts.PollInterval)
	result.ZoneStatus = zoneStatus
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}

	if err := c.EnsureUniversalSSL(ctx, account, zoneID); err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}

	sslStatus, err := c.WaitEdgeSSLActive(ctx, account, zoneID, opts.SSLActiveTimeout, opts.PollInterval)
	result.SSLStatus = sslStatus
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}

	if opts.EnableSecurityRules {
		countries, countryErr := NormalizeCountryCodes(opts.BlockCountries)
		if countryErr != nil {
			result.SecurityRuleStatus = statusFailedPrefix + countryErr.Error()
			result.Errors = append(result.Errors, countryErr.Error())
		} else if len(countries) == 0 {
			result.SecurityRuleStatus = statusSkipped
		} else if status, err := c.EnsureCountryBlockRule(ctx, account, zoneID, countries); err != nil {
			result.SecurityRuleStatus = statusFailedPrefix + err.Error()
			result.Errors = append(result.Errors, err.Error())
		} else {
			result.SecurityRuleStatus = status + " " + strings.Join(countries, ",")
		}
	}

	if opts.EnableSpeedSettings {
		result.SpeedStatus = c.EnableCloudflareStandardSpeedRecommendations(ctx, account, zoneID)
	}

	if opts.EnableRUM {
		accountID := strings.TrimSpace(opts.AccountID)
		if accountID == "" {
			accountID = strings.TrimSpace(account.AccountID)
		}
		if accountID == "" {
			var idErr error
			accountID, idErr = c.GetAccountID(ctx, account)
			if idErr != nil {
				result.RUMStatus = statusFailedPrefix + idErr.Error()
				result.Errors = append(result.Errors, idErr.Error())
			}
		}
		if accountID != "" {
			if status, err := c.EnsureRUMAutoInstall(ctx, account, accountID, zoneID, domain); err != nil {
				result.RUMStatus = statusFailedPrefix + err.Error()
				result.Errors = append(result.Errors, err.Error())
			} else {
				result.RUMStatus = status
			}
		}
	}

	if opts.EnableCacheRule {
		if status, err := c.EnsureDefaultStaticFileCacheRule(ctx, account, zoneID); err != nil {
			result.CacheRuleStatus = statusFailedPrefix + err.Error()
			result.Errors = append(result.Errors, err.Error())
		} else {
			result.CacheRuleStatus = status
		}
	}

	return result, nil
}

func normalizePostInitOptions(opts PostInitOptions) PostInitOptions {
	if opts.ZoneActiveTimeout <= 0 {
		opts.ZoneActiveTimeout = defaultPostInitTimeout
	}
	if opts.SSLActiveTimeout <= 0 {
		opts.SSLActiveTimeout = defaultPostInitTimeout
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = defaultSSLPollInterval
	}
	return opts
}

func (c *apiClient) WaitZoneActive(ctx context.Context, account config.CF, zoneID string, timeout time.Duration, pollInterval time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = defaultPostInitTimeout
	}
	if pollInterval <= 0 {
		pollInterval = defaultSSLPollInterval
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	lastStatus := "unknown"
	attempt := 0
	for {
		var zone zoneStatusResult
		if err := c.Do(waitCtx, account, http.MethodGet, fmt.Sprintf("/zones/%s", zoneID), nil, &zone); err != nil {
			return lastStatus, err
		}
		lastStatus = strings.ToLower(strings.TrimSpace(zone.Status))
		if lastStatus == "active" {
			return lastStatus, nil
		}

		if attempt%5 == 4 {
			_ = c.Do(waitCtx, account, http.MethodPut, fmt.Sprintf("/zones/%s/activation_check", zoneID), nil, nil)
		}
		attempt++

		timer := time.NewTimer(pollInterval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return lastStatus, fmt.Errorf("waiting for zone active timed out, current status=%s", lastStatus)
		case <-timer.C:
		}
	}
}

func (c *apiClient) EnsureUniversalSSL(ctx context.Context, account config.CF, zoneID string) error {
	var settings universalSSLSettings
	path := fmt.Sprintf("/zones/%s/ssl/universal/settings", zoneID)
	if err := c.Do(ctx, account, http.MethodGet, path, nil, &settings); err != nil {
		return err
	}
	if settings.Enabled {
		return nil
	}
	return c.Do(ctx, account, http.MethodPatch, path, map[string]any{"enabled": true}, nil)
}

func (c *apiClient) WaitEdgeSSLActive(ctx context.Context, account config.CF, zoneID string, timeout time.Duration, pollInterval time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = defaultPostInitTimeout
	}
	if pollInterval <= 0 {
		pollInterval = defaultSSLPollInterval
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	lastStatus := "unknown"
	for {
		var raw json.RawMessage
		if err := c.Do(waitCtx, account, http.MethodGet, fmt.Sprintf("/zones/%s/ssl/verification", zoneID), nil, &raw); err != nil {
			return lastStatus, err
		}
		lastStatus = edgeSSLStatus(raw)
		switch lastStatus {
		case "active":
			return lastStatus, nil
		case "timing_out", "expired", "failed":
			return lastStatus, fmt.Errorf("edge ssl certificate status=%s", lastStatus)
		}

		timer := time.NewTimer(pollInterval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return lastStatus, fmt.Errorf("waiting for edge ssl active timed out, current status=%s", lastStatus)
		case <-timer.C:
		}
	}
}

func edgeSSLStatus(raw json.RawMessage) string {
	type verificationItem struct {
		CertificateStatus string `json:"certificate_status"`
		Status            string `json:"status"`
	}
	var items []verificationItem
	if err := json.Unmarshal(raw, &items); err == nil {
		if len(items) == 0 {
			return "initializing"
		}
		allActive := true
		last := "initializing"
		for _, item := range items {
			status := strings.ToLower(strings.TrimSpace(item.CertificateStatus))
			if status == "" {
				status = strings.ToLower(strings.TrimSpace(item.Status))
			}
			if status == "" {
				status = "initializing"
			}
			if status == "failed" || status == "timing_out" || status == "expired" {
				return status
			}
			if status != "active" {
				allActive = false
				last = status
			}
		}
		if allActive {
			return "active"
		}
		return last
	}

	var item verificationItem
	if err := json.Unmarshal(raw, &item); err == nil {
		status := strings.ToLower(strings.TrimSpace(item.CertificateStatus))
		if status == "" {
			status = strings.ToLower(strings.TrimSpace(item.Status))
		}
		if status != "" {
			return status
		}
	}
	return "initializing"
}

func (c *apiClient) EnableCloudflareStandardSpeedRecommendations(ctx context.Context, account config.CF, zoneID string) map[string]string {
	settings := map[string]any{
		"speed_brain":             "on",
		"http2":                   "on",
		"http3":                   "on",
		"origin_max_http_version": "2",
		"0rtt":                    "on",
		"always_use_https":        "on",
		"tls_1_3":                 "zrt",
		"early_hints":             "on",
	}
	return c.applyZoneSettings(ctx, account, zoneID, settings)
}

func (c *apiClient) DisableCloudflareStandardSpeedRecommendations(ctx context.Context, account config.CF, zoneID string) map[string]string {
	settings := map[string]any{
		"speed_brain":             "off",
		"http2":                   "off",
		"http3":                   "off",
		"origin_max_http_version": "1",
		"0rtt":                    "off",
		"always_use_https":        "off",
		"tls_1_3":                 "off",
		"early_hints":             "off",
	}
	return c.applyZoneSettings(ctx, account, zoneID, settings)
}

func (c *apiClient) applyZoneSettings(ctx context.Context, account config.CF, zoneID string, settings map[string]any) map[string]string {
	status := make(map[string]string, len(settings))
	for _, settingID := range sortedMapKeys(settings) {
		value := settings[settingID]
		current, ok := c.currentZoneSettingValue(ctx, account, zoneID, settingID)
		if ok && reflect.DeepEqual(current, value) {
			status[settingID] = statusAlreadyEnabled
			continue
		}
		path := fmt.Sprintf("/zones/%s/settings/%s", zoneID, settingID)
		if err := c.Do(ctx, account, http.MethodPatch, path, map[string]any{"value": value}, nil); err != nil {
			status[settingID] = classifySettingError(err)
			continue
		}
		status[settingID] = statusEnabled
	}
	return status
}

func (c *apiClient) currentZoneSettingValue(ctx context.Context, account config.CF, zoneID string, settingID string) (any, bool) {
	var raw map[string]any
	if err := c.Do(ctx, account, http.MethodGet, fmt.Sprintf("/zones/%s/settings/%s", zoneID, settingID), nil, &raw); err != nil {
		return nil, false
	}
	value, ok := raw["value"]
	return value, ok
}

func classifySettingError(err error) string {
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "editable") || strings.Contains(msg, "upgrade") || strings.Contains(msg, "plan") || strings.Contains(msg, "not entitled") {
		return "skipped: plan_not_supported"
	}
	return statusFailedPrefix + err.Error()
}

type cacheRuleActionParameters struct {
	Cache   bool `json:"cache"`
	EdgeTTL struct {
		Mode string `json:"mode"`
	} `json:"edge_ttl"`
}

func defaultStaticCacheActionParameters() cacheRuleActionParameters {
	var params cacheRuleActionParameters
	params.Cache = true
	params.EdgeTTL.Mode = "respect_origin"
	return params
}

func defaultStaticCacheRule() rulesetRule {
	return rulesetRule{
		Description:      staticCacheRuleDesc,
		Expression:       staticCacheRuleExpr,
		Action:           "set_cache_settings",
		Enabled:          true,
		ActionParameters: defaultStaticCacheActionParameters(),
	}
}

func (c *apiClient) EnsureDefaultStaticFileCacheRule(ctx context.Context, account config.CF, zoneID string) (string, error) {
	rule := defaultStaticCacheRule()
	var entry rulesetEntryPoint
	path := fmt.Sprintf("/zones/%s/rulesets/phases/%s/entrypoint", zoneID, cacheSettingsPhase)
	err := c.Do(ctx, account, http.MethodGet, path, nil, &entry)
	if err != nil {
		var apiErr *CloudflareAPIError
		if errors.As(err, &apiErr) && apiErr.IsStatus(http.StatusNotFound) {
			req := map[string]any{
				"name":  cacheRulesetName,
				"kind":  "zone",
				"phase": cacheSettingsPhase,
				"rules": []rulesetRule{rule},
			}
			if err := c.Do(ctx, account, http.MethodPost, fmt.Sprintf("/zones/%s/rulesets", zoneID), req, nil); err != nil {
				return classifyCacheRuleError(err)
			}
			return statusCreated, nil
		}
		return classifyCacheRuleError(err)
	}
	if strings.TrimSpace(entry.ID) == "" {
		return "", errors.New("Cloudflare cache entrypoint ruleset id is empty")
	}

	var target rulesetRule
	var duplicates []rulesetRule
	for _, existing := range entry.Rules {
		if existing.Description != staticCacheRuleDesc {
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
			return "", errors.New("Cloudflare cache rule id is empty")
		}
		status := statusAlreadyExists
		if !cacheRuleMatches(target, rule) {
			rule.ID = target.ID
			updatePath := fmt.Sprintf("/zones/%s/rulesets/%s/rules/%s", zoneID, entry.ID, target.ID)
			if err := c.Do(ctx, account, http.MethodPatch, updatePath, rule, nil); err != nil {
				return classifyCacheRuleError(err)
			}
			status = statusUpdated
		}
		for _, duplicate := range duplicates {
			if strings.TrimSpace(duplicate.ID) == "" {
				return "", errors.New("Cloudflare duplicate cache rule id is empty")
			}
			deletePath := fmt.Sprintf("/zones/%s/rulesets/%s/rules/%s", zoneID, entry.ID, duplicate.ID)
			if err := c.Do(ctx, account, http.MethodDelete, deletePath, nil, nil); err != nil {
				return classifyCacheRuleError(err)
			}
			status = statusUpdated
		}
		return status, nil
	}

	if err := c.Do(ctx, account, http.MethodPost, fmt.Sprintf("/zones/%s/rulesets/%s/rules", zoneID, entry.ID), rule, nil); err != nil {
		return classifyCacheRuleError(err)
	}
	return statusCreated, nil
}

func cacheRuleMatches(existing rulesetRule, want rulesetRule) bool {
	return strings.TrimSpace(existing.Expression) == want.Expression &&
		strings.EqualFold(existing.Action, want.Action) &&
		existing.Enabled == want.Enabled &&
		jsonEqual(existing.ActionParameters, want.ActionParameters)
}

func jsonEqual(a any, b any) bool {
	ab, aerr := json.Marshal(a)
	bb, berr := json.Marshal(b)
	if aerr != nil || berr != nil {
		return false
	}
	var av any
	var bv any
	if json.Unmarshal(ab, &av) != nil || json.Unmarshal(bb, &bv) != nil {
		return false
	}
	return reflect.DeepEqual(av, bv)
}

func classifyCacheRuleError(err error) (string, error) {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "exceeded") || strings.Contains(msg, "limit"):
		return "skipped: rule_limit_reached", nil
	case strings.Contains(msg, "permission") || strings.Contains(msg, "not authorized") || strings.Contains(msg, "authentication"):
		return "", fmt.Errorf("missing_permission: API Token 缺少 Cache Rules/Rulesets 读取或编辑权限: %w", err)
	case strings.Contains(msg, "expression"):
		return "", fmt.Errorf("invalid_expression: %w", err)
	default:
		return "", err
	}
}

func (c *apiClient) DeleteCountryBlockRule(ctx context.Context, account config.CF, zoneID string) (string, error) {
	return c.deleteRulesetRuleByDescription(ctx, account, zoneID, firewallCustomPhase, countryBlockRuleDesc)
}

func (c *apiClient) DeleteDefaultStaticFileCacheRule(ctx context.Context, account config.CF, zoneID string) (string, error) {
	return c.deleteRulesetRuleByDescription(ctx, account, zoneID, cacheSettingsPhase, staticCacheRuleDesc)
}

func (c *apiClient) deleteRulesetRuleByDescription(ctx context.Context, account config.CF, zoneID string, phase string, description string) (string, error) {
	var entry rulesetEntryPoint
	path := fmt.Sprintf("/zones/%s/rulesets/phases/%s/entrypoint", zoneID, phase)
	err := c.Do(ctx, account, http.MethodGet, path, nil, &entry)
	if err != nil {
		var apiErr *CloudflareAPIError
		if errors.As(err, &apiErr) && apiErr.IsStatus(http.StatusNotFound) {
			return statusNotFound, nil
		}
		return "", err
	}
	deleted := false
	for _, rule := range entry.Rules {
		if rule.Description != description {
			continue
		}
		if strings.TrimSpace(rule.ID) == "" {
			return "", errors.New("Cloudflare ruleset rule id is empty")
		}
		deletePath := fmt.Sprintf("/zones/%s/rulesets/%s/rules/%s", zoneID, entry.ID, rule.ID)
		if err := c.Do(ctx, account, http.MethodDelete, deletePath, nil, nil); err != nil {
			return "", err
		}
		deleted = true
	}
	if deleted {
		return statusDeleted, nil
	}
	return statusNotFound, nil
}

func (c *apiClient) ManageZoneFeatures(ctx context.Context, account config.CF, domain string, zoneID string, opts FeatureManageOptions) FeatureManageResult {
	result := FeatureManageResult{
		Domain:             domain,
		ZoneID:             zoneID,
		SecurityRuleStatus: statusSkipped,
		SpeedStatus:        map[string]string{},
		CacheRuleStatus:    statusSkipped,
	}
	action := strings.ToLower(strings.TrimSpace(opts.Action))
	if action == "" {
		action = "enable"
	}

	if opts.Security {
		switch action {
		case "disable", "delete", "off":
			status, err := c.DeleteCountryBlockRule(ctx, account, zoneID)
			result.SecurityRuleStatus = statusOrFailed(status, err)
			if err != nil {
				result.Errors = append(result.Errors, err.Error())
			}
		default:
			countries, err := NormalizeCountryCodes(opts.BlockCountries)
			if err != nil {
				result.SecurityRuleStatus = statusFailedPrefix + err.Error()
				result.Errors = append(result.Errors, err.Error())
			} else if len(countries) == 0 {
				result.SecurityRuleStatus = statusSkipped
			} else {
				status, err := c.EnsureCountryBlockRule(ctx, account, zoneID, countries)
				result.SecurityRuleStatus = statusOrFailed(status+" "+strings.Join(countries, ","), err)
				if err != nil {
					result.Errors = append(result.Errors, err.Error())
				}
			}
		}
	}

	if opts.Speed {
		if action == "disable" || action == "delete" || action == "off" {
			result.SpeedStatus = c.DisableCloudflareStandardSpeedRecommendations(ctx, account, zoneID)
		} else {
			result.SpeedStatus = c.EnableCloudflareStandardSpeedRecommendations(ctx, account, zoneID)
		}
	}

	if opts.Cache {
		if action == "disable" || action == "delete" || action == "off" {
			status, err := c.DeleteDefaultStaticFileCacheRule(ctx, account, zoneID)
			result.CacheRuleStatus = statusOrFailed(status, err)
			if err != nil {
				result.Errors = append(result.Errors, err.Error())
			}
		} else {
			status, err := c.EnsureDefaultStaticFileCacheRule(ctx, account, zoneID)
			result.CacheRuleStatus = statusOrFailed(status, err)
			if err != nil {
				result.Errors = append(result.Errors, err.Error())
			}
		}
	}

	return result
}

func statusOrFailed(status string, err error) string {
	if err != nil {
		return statusFailedPrefix + err.Error()
	}
	status = strings.TrimSpace(status)
	if status == "" {
		return statusSkipped
	}
	return status
}

func sortedFeatureResults(results []FeatureManageResult) {
	sort.Slice(results, func(i, j int) bool {
		return results[i].Domain < results[j].Domain
	})
}
