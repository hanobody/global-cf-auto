package cfclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"DomainC/config"
)

const (
	ipBlockRuleDesc    = "telegram-auto-block-ips"
	ipBlockRulesetName = "telegram-auto-ip-waf"

	AccountIPAccessRuleNote = "telegram-auto-ip-blacklist"
)

type AccountIPAccessRuleDeleteResult struct {
	Matched  int
	Deleted  int
	NotFound int
	Failed   []string
}

type accountIPAccessRule struct {
	ID            string `json:"id"`
	Mode          string `json:"mode"`
	Notes         string `json:"notes"`
	Configuration struct {
		Target string `json:"target"`
		Value  string `json:"value"`
	} `json:"configuration"`
}

func NormalizeIPAccessRuleValues(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		_, value, err := normalizeIPAccessRuleValue(raw)
		if err != nil {
			return nil, err
		}
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out, nil
}

func normalizeIPAccessRuleValue(raw string) (string, string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", "", nil
	}
	if strings.Contains(value, "/") {
		ip, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return "", "", fmt.Errorf("invalid IP range %q", raw)
		}
		ones, bits := ipNet.Mask.Size()
		if ip.To4() != nil {
			if bits != 32 || (ones != 16 && ones != 24) {
				return "", "", fmt.Errorf("invalid IPv4 range %q: Cloudflare account IP access rules only support /16 or /24", raw)
			}
		} else {
			if bits != 128 || (ones != 32 && ones != 48 && ones != 64) {
				return "", "", fmt.Errorf("invalid IPv6 range %q: Cloudflare account IP access rules only support /32, /48, or /64", raw)
			}
		}
		return "ip_range", ipNet.String(), nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return "", "", fmt.Errorf("invalid IP address %q", raw)
	}
	return "ip", ip.String(), nil
}

func buildIPBlockExpression(values []string) string {
	return fmt.Sprintf("ip.src in {%s}", strings.Join(values, " "))
}

func (c *apiClient) EnsureIPBlockRule(ctx context.Context, account config.CF, zoneID string, values []string) (string, error) {
	normalized, err := NormalizeIPAccessRuleValues(values)
	if err != nil {
		return "", err
	}
	if len(normalized) == 0 {
		return statusSkipped, nil
	}
	existing, err := c.currentIPBlockValues(ctx, account, zoneID)
	if err != nil {
		return "", err
	}
	normalized = mergeIPAccessRuleValues(existing, normalized)
	expression := buildIPBlockExpression(normalized)
	rule := rulesetRule{
		Description: ipBlockRuleDesc,
		Expression:  expression,
		Action:      "block",
		Enabled:     true,
	}
	status, err := c.ensureFirewallCustomRuleByDescription(ctx, account, zoneID, ipBlockRulesetName, ipBlockRuleDesc, rule)
	if err != nil {
		return "", err
	}
	if err := c.verifyFirewallCustomRule(ctx, account, zoneID, ipBlockRuleDesc, expression); err != nil {
		return "", err
	}
	return status, nil
}

func (c *apiClient) DeleteIPBlockRule(ctx context.Context, account config.CF, zoneID string, values []string) (string, error) {
	remove, err := NormalizeIPAccessRuleValues(values)
	if err != nil {
		return "", err
	}
	if len(remove) == 0 {
		return statusSkipped, nil
	}
	existing, err := c.currentIPBlockValues(ctx, account, zoneID)
	if err != nil {
		return "", err
	}
	if len(existing) == 0 {
		return statusNotFound, nil
	}
	remaining := removeIPAccessRuleValues(existing, remove)
	if len(remaining) == len(existing) {
		return statusNotFound, nil
	}
	if len(remaining) == 0 {
		return c.deleteRulesetRuleByDescription(ctx, account, zoneID, firewallCustomPhase, ipBlockRuleDesc)
	}
	expression := buildIPBlockExpression(remaining)
	rule := rulesetRule{
		Description: ipBlockRuleDesc,
		Expression:  expression,
		Action:      "block",
		Enabled:     true,
	}
	status, err := c.ensureFirewallCustomRuleByDescription(ctx, account, zoneID, ipBlockRulesetName, ipBlockRuleDesc, rule)
	if err != nil {
		return "", err
	}
	if err := c.verifyFirewallCustomRule(ctx, account, zoneID, ipBlockRuleDesc, expression); err != nil {
		return "", err
	}
	return status, nil
}

func (c *apiClient) ClearIPBlockRule(ctx context.Context, account config.CF, zoneID string) (string, error) {
	return c.deleteRulesetRuleByDescription(ctx, account, zoneID, firewallCustomPhase, ipBlockRuleDesc)
}

func (c *apiClient) DeleteAccountIPAccessRules(ctx context.Context, account config.CF, values []string) (AccountIPAccessRuleDeleteResult, error) {
	var result AccountIPAccessRuleDeleteResult
	normalized, err := NormalizeIPAccessRuleValues(values)
	if err != nil {
		return result, err
	}
	if len(normalized) == 0 {
		return result, nil
	}
	accountID, err := c.GetAccountID(ctx, account)
	if err != nil {
		return result, err
	}
	for _, value := range normalized {
		target, normalizedValue, err := normalizeIPAccessRuleValue(value)
		if err != nil {
			return result, err
		}
		q := url.Values{}
		q.Set("configuration.target", target)
		q.Set("configuration.value", normalizedValue)
		rules, err := c.listAccountIPAccessRules(ctx, account, accountID, q)
		if err != nil {
			return result, err
		}
		matched := filterBotAccountIPAccessRules(rules, AccountIPAccessRuleNote)
		if len(matched) == 0 {
			result.NotFound++
			continue
		}
		result.Matched += len(matched)
		for _, rule := range matched {
			if strings.TrimSpace(rule.ID) == "" {
				result.Failed = append(result.Failed, normalizedValue+": Cloudflare account IP access rule id is empty")
				continue
			}
			if err := c.deleteAccountIPAccessRule(ctx, account, accountID, rule.ID); err != nil {
				result.Failed = append(result.Failed, normalizedValue+": "+err.Error())
				continue
			}
			result.Deleted++
		}
	}
	return result, nil
}

func (c *apiClient) ClearAccountIPAccessRulesByNote(ctx context.Context, account config.CF, note string) (AccountIPAccessRuleDeleteResult, error) {
	var result AccountIPAccessRuleDeleteResult
	note = strings.TrimSpace(note)
	if note == "" {
		note = AccountIPAccessRuleNote
	}
	accountID, err := c.GetAccountID(ctx, account)
	if err != nil {
		return result, err
	}
	q := url.Values{}
	q.Set("mode", "block")
	rules, err := c.listAccountIPAccessRules(ctx, account, accountID, q)
	if err != nil {
		return result, err
	}
	matched := filterBotAccountIPAccessRules(rules, note)
	if len(matched) == 0 {
		result.NotFound = 1
		return result, nil
	}
	result.Matched = len(matched)
	for _, rule := range matched {
		if strings.TrimSpace(rule.ID) == "" {
			result.Failed = append(result.Failed, rule.Configuration.Value+": Cloudflare account IP access rule id is empty")
			continue
		}
		if err := c.deleteAccountIPAccessRule(ctx, account, accountID, rule.ID); err != nil {
			result.Failed = append(result.Failed, rule.Configuration.Value+": "+err.Error())
			continue
		}
		result.Deleted++
	}
	return result, nil
}

func (c *apiClient) listAccountIPAccessRules(ctx context.Context, account config.CF, accountID string, query url.Values) ([]accountIPAccessRule, error) {
	const perPage = 100
	var out []accountIPAccessRule
	for page := 1; ; page++ {
		q := url.Values{}
		for key, values := range query {
			for _, value := range values {
				q.Add(key, value)
			}
		}
		q.Set("page", strconv.Itoa(page))
		q.Set("per_page", strconv.Itoa(perPage))
		var rules []accountIPAccessRule
		path := fmt.Sprintf("/accounts/%s/firewall/access_rules/rules?%s", accountID, q.Encode())
		if err := c.Do(ctx, account, "GET", path, nil, &rules); err != nil {
			return nil, err
		}
		out = append(out, rules...)
		if len(rules) < perPage {
			break
		}
	}
	return out, nil
}

func (c *apiClient) deleteAccountIPAccessRule(ctx context.Context, account config.CF, accountID string, ruleID string) error {
	path := fmt.Sprintf("/accounts/%s/firewall/access_rules/rules/%s", accountID, ruleID)
	return c.Do(ctx, account, "DELETE", path, nil, nil)
}

func filterBotAccountIPAccessRules(rules []accountIPAccessRule, note string) []accountIPAccessRule {
	note = strings.TrimSpace(note)
	out := make([]accountIPAccessRule, 0, len(rules))
	for _, rule := range rules {
		target := strings.ToLower(strings.TrimSpace(rule.Configuration.Target))
		if target != "ip" && target != "ip_range" {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rule.Mode), "block") {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(rule.Notes), note) {
			continue
		}
		out = append(out, rule)
	}
	return out
}

func (c *apiClient) currentIPBlockValues(ctx context.Context, account config.CF, zoneID string) ([]string, error) {
	var entry rulesetEntryPoint
	path := fmt.Sprintf("/zones/%s/rulesets/phases/%s/entrypoint", zoneID, firewallCustomPhase)
	err := c.Do(ctx, account, "GET", path, nil, &entry)
	if err != nil {
		var apiErr *CloudflareAPIError
		if errors.As(err, &apiErr) && apiErr.IsStatus(404) {
			return nil, nil
		}
		return nil, err
	}
	for _, rule := range entry.Rules {
		if rule.Description != ipBlockRuleDesc {
			continue
		}
		return parseIPBlockExpression(rule.Expression), nil
	}
	return nil, nil
}

func parseIPBlockExpression(expression string) []string {
	start := strings.Index(expression, "{")
	end := strings.LastIndex(expression, "}")
	if start < 0 || end <= start {
		return nil
	}
	fields := strings.Fields(expression[start+1 : end])
	values, err := NormalizeIPAccessRuleValues(fields)
	if err != nil {
		return nil
	}
	return values
}

func mergeIPAccessRuleValues(existing []string, add []string) []string {
	seen := make(map[string]struct{}, len(existing)+len(add))
	out := make([]string, 0, len(existing)+len(add))
	for _, value := range append(append([]string(nil), existing...), add...) {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func removeIPAccessRuleValues(existing []string, remove []string) []string {
	removeSet := make(map[string]struct{}, len(remove))
	for _, value := range remove {
		removeSet[value] = struct{}{}
	}
	out := make([]string, 0, len(existing))
	for _, value := range existing {
		if _, ok := removeSet[value]; ok {
			continue
		}
		out = append(out, value)
	}
	return out
}

func (c *apiClient) ensureFirewallCustomRuleByDescription(ctx context.Context, account config.CF, zoneID string, rulesetName string, description string, rule rulesetRule) (string, error) {
	var entry rulesetEntryPoint
	path := fmt.Sprintf("/zones/%s/rulesets/phases/%s/entrypoint", zoneID, firewallCustomPhase)
	err := c.Do(ctx, account, "GET", path, nil, &entry)
	if err != nil {
		var apiErr *CloudflareAPIError
		if errors.As(err, &apiErr) && apiErr.IsStatus(404) {
			req := map[string]any{
				"name":  rulesetName,
				"kind":  "zone",
				"phase": firewallCustomPhase,
				"rules": []rulesetRule{rule},
			}
			if err := c.Do(ctx, account, "POST", fmt.Sprintf("/zones/%s/rulesets", zoneID), req, nil); err != nil {
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
		if existing.Description != description {
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
		if !firewallRuleMatches(target, rule.Expression, rule.Action, rule.Enabled) {
			rule.ID = target.ID
			updatePath := fmt.Sprintf("/zones/%s/rulesets/%s/rules/%s", zoneID, entry.ID, target.ID)
			if err := c.Do(ctx, account, "PATCH", updatePath, rule, nil); err != nil {
				return "", err
			}
			status = statusUpdated
		}
		for _, duplicate := range duplicates {
			if strings.TrimSpace(duplicate.ID) == "" {
				return "", errors.New("Cloudflare duplicate firewall rule id is empty")
			}
			deletePath := fmt.Sprintf("/zones/%s/rulesets/%s/rules/%s", zoneID, entry.ID, duplicate.ID)
			if err := c.Do(ctx, account, "DELETE", deletePath, nil, nil); err != nil {
				return "", err
			}
			status = statusUpdated
		}
		return status, nil
	}
	if err := c.Do(ctx, account, "POST", fmt.Sprintf("/zones/%s/rulesets/%s/rules", zoneID, entry.ID), rule, nil); err != nil {
		return "", err
	}
	return statusCreated, nil
}

func (c *apiClient) verifyFirewallCustomRule(ctx context.Context, account config.CF, zoneID string, description string, expression string) error {
	path := fmt.Sprintf("/zones/%s/rulesets/phases/%s/entrypoint", zoneID, firewallCustomPhase)
	var lastErr error
	for attempt := 0; attempt < countryBlockVerifyAttempts; attempt++ {
		if err := waitCountryBlockVerifyRetry(ctx, attempt); err != nil {
			return err
		}
		var entry rulesetEntryPoint
		if err := c.Do(ctx, account, "GET", path, nil, &entry); err != nil {
			lastErr = err
			continue
		}
		for _, existing := range entry.Rules {
			if existing.Description == description && firewallRuleMatches(existing, expression, "block", true) {
				return nil
			}
		}
		lastErr = fmt.Errorf("Cloudflare firewall rule %q is not visible after write", description)
	}
	if lastErr != nil {
		return fmt.Errorf("verify Cloudflare firewall rule failed: %w", lastErr)
	}
	return errors.New("verify Cloudflare firewall rule failed")
}

func firewallRuleMatches(rule rulesetRule, expression string, action string, enabled bool) bool {
	return strings.TrimSpace(rule.Expression) == strings.TrimSpace(expression) &&
		strings.EqualFold(rule.Action, action) &&
		rule.Enabled == enabled
}
