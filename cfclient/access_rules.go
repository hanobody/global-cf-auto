package cfclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"DomainC/config"
)

const (
	ipBlockRuleDesc    = "telegram-auto-block-ips"
	ipBlockRulesetName = "telegram-auto-ip-waf"
)

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
