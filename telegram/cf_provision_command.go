package telegram

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"DomainC/cfclient"
	"DomainC/config"
	"DomainC/reminder"
)

type cfProvisionCommandOptions struct {
	Domain          string
	AccountLabel    string
	BlockCountries  []string
	BlockSpecified  bool
	EnableSpeed     bool
	EnableCache     bool
	EnableRUM       bool
	CreateIfMissing bool
}

type cloudflarePostInitializer interface {
	RunPostSSLInit(ctx context.Context, account config.CF, domain string, zoneID string, opts cfclient.PostInitOptions) (*cfclient.PostInitResult, error)
}

func (h *CommandHandler) handleCFProvisionCommand(command string, args []string) {
	if len(h.Accounts) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法执行初始化。")
		return
	}

	opts, err := parseCFProvisionCommandOptions(command, args)
	if err != nil {
		h.sendText(err.Error())
		return
	}
	if opts.Domain == "" {
		h.sendText(cfProvisionUsage(command))
		return
	}

	provisioner, ok := h.CFClient.(cfclient.Provisioner)
	if !ok {
		h.sendText("当前 Cloudflare 客户端不支持 Zone 初始化。")
		return
	}

	account, err := h.resolveProvisionAccount(opts)
	if err != nil {
		h.sendText(err.Error())
		return
	}

	provisionOpts := cfclient.ProvisionOptions{
		AccountID:           account.AccountID,
		BlockCountries:      opts.BlockCountries,
		EnableSpeed:         opts.EnableSpeed,
		EnableRUM:           opts.EnableRUM,
		ExtraZoneSettings:   config.ExtraZoneSettings(),
		CreateZoneIfMissing: opts.CreateIfMissing,
	}

	result, err := provisioner.ProvisionCloudflareZone(context.Background(), *account, opts.Domain, provisionOpts)
	if err != nil {
		h.sendText(fmt.Sprintf("Cloudflare 初始化失败：%v", err))
		return
	}
	if rt := reminder.DefaultRuntime(); rt != nil {
		rt.RecordDomainChange(context.Background(), reminder.DomainChange{Domain: result.Domain, Source: account.Label, IsCF: true, ZoneID: result.ZoneID, Status: result.ZoneStatus})
	}
	if opts.CreateIfMissing {
		h.sendText(formatCFAddSubmitted(*result))
	} else {
		h.sendText(fmt.Sprintf("Cloudflare 初始化任务已提交。\n域名：%s\nZone ID：%s\n当前状态：%s", result.Domain, result.ZoneID, normalizeDisplayValue(result.ZoneStatus)))
	}
	h.startCloudflarePostInitTask(*account, result.Domain, result.ZoneID, opts)
}

func parseCFProvisionCommandOptions(command string, args []string) (cfProvisionCommandOptions, error) {
	opts := cfProvisionCommandOptions{
		EnableSpeed:     config.EnableSpeedRecommendations(),
		EnableCache:     config.EnableCacheRule(),
		EnableRUM:       config.EnableRUMAutoInstall(),
		CreateIfMissing: strings.EqualFold(command, "cf_add"),
	}

	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		if key, value, ok := strings.Cut(arg, "="); ok {
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			switch key {
			case "block", "blocks", "country", "countries":
				opts.BlockSpecified = true
				if isNoneValue(value) {
					opts.BlockCountries = nil
					continue
				}
				countries, err := cfclient.NormalizeCountryCodes([]string{value})
				if err != nil {
					return opts, err
				}
				opts.BlockCountries = countries
			case "speed":
				enabled, err := parseOnOff(value)
				if err != nil {
					return opts, fmt.Errorf("speed 参数错误：%v", err)
				}
				opts.EnableSpeed = enabled
			case "cache":
				enabled, err := parseOnOff(value)
				if err != nil {
					return opts, fmt.Errorf("cache 参数错误：%v", err)
				}
				opts.EnableCache = enabled
			case "rum":
				enabled, err := parseOnOff(value)
				if err != nil {
					return opts, fmt.Errorf("rum 参数错误：%v", err)
				}
				opts.EnableRUM = enabled
			case "account", "acc", "cf":
				opts.AccountLabel = value
			default:
				return opts, fmt.Errorf("未知参数 %s", key)
			}
			continue
		}

		if opts.Domain == "" {
			domain, err := extractDomainOrHost(arg)
			if err != nil {
				return opts, fmt.Errorf("%s: %v", arg, err)
			}
			opts.Domain = domain
			continue
		}
		if opts.AccountLabel == "" {
			opts.AccountLabel = arg
			continue
		}
		return opts, fmt.Errorf("无法识别参数：%s", arg)
	}

	if !opts.BlockSpecified {
		countries, err := cfclient.NormalizeCountryCodes(config.DefaultBlockCountries())
		if err != nil {
			return opts, err
		}
		opts.BlockCountries = countries
	}
	return opts, nil
}

func (h *CommandHandler) resolveProvisionAccount(opts cfProvisionCommandOptions) (*config.CF, error) {
	if opts.AccountLabel != "" {
		account := h.getAccountByLabel(opts.AccountLabel)
		if account == nil {
			return nil, fmt.Errorf("未找到 Cloudflare 账号：%s", opts.AccountLabel)
		}
		return account, nil
	}

	if !opts.CreateIfMissing {
		account, _, err := h.findZone(opts.Domain)
		if err != nil {
			return nil, fmt.Errorf("域名 %s 不属于任何 Cloudflare 账号：%v", opts.Domain, err)
		}
		return account, nil
	}

	if account, _, err := h.findZone(opts.Domain); err == nil {
		return account, nil
	} else if !errors.Is(err, cfclient.ErrZoneNotFound) && !strings.Contains(strings.ToLower(err.Error()), "zone not found") {
		return nil, err
	}

	if len(h.Accounts) == 0 {
		return nil, fmt.Errorf("未配置可用的 Cloudflare 账号")
	}
	return &h.Accounts[0], nil
}

func cfProvisionUsage(command string) string {
	if command == "cf_init" {
		return "用法：/cf_init example.com block=CN speed=on cache=on rum=on"
	}
	return "用法：/cf_add example.com block=CN,RU speed=on cache=on rum=on\n也可使用 block=none speed=off cache=off rum=off"
}

func (h *CommandHandler) startCloudflarePostInitTask(account config.CF, domain string, zoneID string, opts cfProvisionCommandOptions) {
	initializer, ok := h.CFClient.(cloudflarePostInitializer)
	if !ok {
		h.sendText("当前 Cloudflare 客户端不支持 SSL 后初始化任务。")
		return
	}
	go func() {
		result, err := initializer.RunPostSSLInit(context.Background(), account, domain, zoneID, cfclient.PostInitOptions{
			AccountID:           account.AccountID,
			BlockCountries:      opts.BlockCountries,
			EnableSecurityRules: len(opts.BlockCountries) > 0,
			EnableSpeedSettings: opts.EnableSpeed,
			EnableCacheRule:     opts.EnableCache,
			EnableRUM:           opts.EnableRUM,
			ZoneActiveTimeout:   6 * time.Hour,
			SSLActiveTimeout:    6 * time.Hour,
			PollInterval:        2 * time.Minute,
		})
		if err != nil && result == nil {
			h.sendText(fmt.Sprintf("Cloudflare 初始化失败：%v", err))
			return
		}
		h.sendText(formatPostInitResult(result))
	}()
}

func formatCFAddSubmitted(result cfclient.ProvisionResult) string {
	var sb strings.Builder
	sb.WriteString("✅ Cloudflare 域名已添加\n\n")
	sb.WriteString("域名：" + normalizeDisplayValue(result.Domain) + "\n")
	sb.WriteString("Zone ID：" + normalizeDisplayValue(result.ZoneID) + "\n")
	sb.WriteString("当前状态：" + normalizeDisplayValue(result.ZoneStatus) + "\n")
	sb.WriteString("初始化：等待 Zone active 和 SSL 证书 active 后自动执行\n")
	if len(result.NameServers) > 0 {
		sb.WriteString("\nNameservers：\n")
		for _, ns := range result.NameServers {
			sb.WriteString("- " + ns + "\n")
		}
	}
	sb.WriteString("\n提示：\n请先把域名注册商处的 NS 修改为以上 Cloudflare NS。\nZone active 且 SSL active 后，程序会自动开启安全规则、速度推荐设置和默认缓存规则。")
	return sb.String()
}

func formatPostInitResult(result *cfclient.PostInitResult) string {
	if result == nil {
		return "Cloudflare 初始化失败：结果为空"
	}
	var sb strings.Builder
	if len(result.Errors) > 0 {
		sb.WriteString("⚠️ Cloudflare 初始化完成但有异常\n\n")
	} else {
		sb.WriteString("✅ Cloudflare 初始化完成\n\n")
	}
	sb.WriteString("域名：" + normalizeDisplayValue(result.Domain) + "\n")
	sb.WriteString("Zone ID：" + normalizeDisplayValue(result.ZoneID) + "\n")
	sb.WriteString("Zone 状态：" + normalizeDisplayValue(result.ZoneStatus) + "\n")
	sb.WriteString("SSL 证书：" + normalizeDisplayValue(result.SSLStatus) + "\n")
	sb.WriteString("\n安全规则：\n- 国家/地区拦截：" + normalizeDisplayValue(result.SecurityRuleStatus) + "\n")
	sb.WriteString("\n速度推荐设置：\n")
	if len(result.SpeedStatus) == 0 {
		sb.WriteString("- 已跳过\n")
	} else {
		for _, key := range sortedStringMapKeys(result.SpeedStatus) {
			sb.WriteString(fmt.Sprintf("- %s：%s\n", speedSettingDisplayName(key), normalizeDisplayValue(result.SpeedStatus[key])))
		}
	}
	sb.WriteString("\nRUM：\n- Web Analytics 自动注入：" + normalizeDisplayValue(result.RUMStatus) + "\n")
	sb.WriteString("\n缓存规则：\n- 缓存默认文件扩展名 [模板]：" + normalizeDisplayValue(result.CacheRuleStatus) + "\n")
	sb.WriteString("- 缓存资格：符合缓存条件\n- 边缘 TTL：尊重源站缓存控制头；无缓存控制头时使用 Cloudflare 默认缓存行为\n")
	if len(result.Errors) > 0 {
		sb.WriteString("\n错误：\n")
		for _, item := range result.Errors {
			sb.WriteString("- " + item + "\n")
		}
	}
	sb.WriteString("\n注意：\n只有 Proxied / 橙云 DNS 记录才会生效 WAF、RUM 自动注入、速度设置和缓存规则。")
	return sb.String()
}

func sortedStringMapKeys(items map[string]string) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func speedSettingDisplayName(settingID string) string {
	switch settingID {
	case "speed_brain":
		return "Speed Brain"
	case "http2":
		return "HTTP/2"
	case "http3":
		return "HTTP/3"
	case "origin_max_http_version":
		return "HTTP/2 到源服务器"
	case "0rtt":
		return "0-RTT 连接恢复"
	case "always_use_https":
		return "始终使用 HTTPS"
	case "tls_1_3":
		return "TLS 1.3"
	case "early_hints":
		return "Early Hints"
	default:
		return settingID
	}
}

func parseOnOff(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on", "enable", "enabled":
		return true, nil
	case "0", "false", "no", "n", "off", "disable", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("必须是 on/off")
	}
}

func isNoneValue(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "none", "no", "off", "skip", "disabled", "-":
		return true
	default:
		return false
	}
}
