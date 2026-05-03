package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"DomainC/cfclient"
	"DomainC/config"
)

type cfProvisionCommandOptions struct {
	Domain          string
	AccountLabel    string
	BlockCountries  []string
	BlockSpecified  bool
	EnableSpeed     bool
	EnableRUM       bool
	CreateIfMissing bool
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
	h.sendText(cfclient.FormatProvisionResult(*result))
}

func parseCFProvisionCommandOptions(command string, args []string) (cfProvisionCommandOptions, error) {
	opts := cfProvisionCommandOptions{
		EnableSpeed:     config.EnableSpeedRecommendations(),
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
		return "用法：/cf_init example.com block=CN speed=on rum=on"
	}
	return "用法：/cf_add example.com block=CN,RU speed=on rum=on\n也可使用 block=none speed=off rum=off"
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
