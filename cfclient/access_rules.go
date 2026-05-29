package cfclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"DomainC/config"
)

const accountIPBlacklistNote = "telegram-auto-ip-blacklist"

type AccountIPAccessRule struct {
	ID            string                    `json:"id"`
	Mode          string                    `json:"mode"`
	Configuration accessRuleConfiguration   `json:"configuration"`
	Notes         string                    `json:"notes"`
}

type accessRuleConfiguration struct {
	Target string `json:"target"`
	Value  string `json:"value"`
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

func (c *apiClient) EnsureAccountIPAccessBlockRule(ctx context.Context, account config.CF, value string) (string, error) {
	target, normalized, err := normalizeIPAccessRuleValue(value)
	if err != nil {
		return "", err
	}
	if normalized == "" {
		return statusSkipped, nil
	}
	accountID, err := c.GetAccountID(ctx, account)
	if err != nil {
		return "", err
	}
	rules, err := c.listAccountIPAccessRules(ctx, account, accountID, "", target, normalized)
	if err != nil {
		return "", err
	}
	for _, rule := range rules {
		if !accessRuleMatches(rule, target, normalized) {
			continue
		}
		if strings.EqualFold(rule.Mode, "block") {
			return statusAlreadyExists, nil
		}
		if strings.TrimSpace(rule.ID) == "" {
			return "", errors.New("Cloudflare account IP access rule id is empty")
		}
		req := map[string]any{
			"mode":  "block",
			"notes": accountIPBlacklistNote,
		}
		path := fmt.Sprintf("/accounts/%s/firewall/access_rules/rules/%s", accountID, rule.ID)
		if err := c.Do(ctx, account, "PATCH", path, req, nil); err != nil {
			return "", err
		}
		return statusUpdated, nil
	}

	req := map[string]any{
		"mode": "block",
		"configuration": map[string]string{
			"target": target,
			"value":  normalized,
		},
		"notes": accountIPBlacklistNote,
	}
	if err := c.Do(ctx, account, "POST", fmt.Sprintf("/accounts/%s/firewall/access_rules/rules", accountID), req, nil); err != nil {
		return "", err
	}
	return statusCreated, nil
}

func (c *apiClient) DeleteAccountIPAccessBlockRule(ctx context.Context, account config.CF, value string) (string, error) {
	target, normalized, err := normalizeIPAccessRuleValue(value)
	if err != nil {
		return "", err
	}
	if normalized == "" {
		return statusSkipped, nil
	}
	accountID, err := c.GetAccountID(ctx, account)
	if err != nil {
		return "", err
	}
	rules, err := c.listAccountIPAccessRules(ctx, account, accountID, "block", target, normalized)
	if err != nil {
		return "", err
	}
	deleted := false
	for _, rule := range rules {
		if !accessRuleMatches(rule, target, normalized) || !strings.EqualFold(rule.Mode, "block") {
			continue
		}
		if strings.TrimSpace(rule.ID) == "" {
			return "", errors.New("Cloudflare account IP access rule id is empty")
		}
		path := fmt.Sprintf("/accounts/%s/firewall/access_rules/rules/%s", accountID, rule.ID)
		if err := c.Do(ctx, account, "DELETE", path, nil, nil); err != nil {
			return "", err
		}
		deleted = true
	}
	if deleted {
		return statusDeleted, nil
	}
	return statusNotFound, nil
}

func (c *apiClient) listAccountIPAccessRules(ctx context.Context, account config.CF, accountID string, mode string, target string, value string) ([]AccountIPAccessRule, error) {
	const perPage = 100
	var out []AccountIPAccessRule
	for page := 1; ; page++ {
		q := url.Values{}
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("per_page", fmt.Sprintf("%d", perPage))
		if strings.TrimSpace(mode) != "" {
			q.Set("mode", strings.TrimSpace(mode))
		}
		if strings.TrimSpace(target) != "" {
			q.Set("configuration.target", strings.TrimSpace(target))
		}
		if strings.TrimSpace(value) != "" {
			q.Set("configuration.value", strings.TrimSpace(value))
		}
		var pageItems []AccountIPAccessRule
		path := fmt.Sprintf("/accounts/%s/firewall/access_rules/rules?%s", accountID, q.Encode())
		if err := c.Do(ctx, account, "GET", path, nil, &pageItems); err != nil {
			return nil, err
		}
		out = append(out, pageItems...)
		if len(pageItems) < perPage {
			break
		}
	}
	return out, nil
}

func accessRuleMatches(rule AccountIPAccessRule, target string, value string) bool {
	return strings.EqualFold(strings.TrimSpace(rule.Configuration.Target), strings.TrimSpace(target)) &&
		strings.EqualFold(strings.TrimSpace(rule.Configuration.Value), strings.TrimSpace(value))
}
