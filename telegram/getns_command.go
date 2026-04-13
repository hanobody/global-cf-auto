package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"DomainC/cfclient"
	"DomainC/config"
)

type getNSDomainResult struct {
	Domain       string
	AccountLabel string
}

type getNSBatchResult struct {
	TargetAccount   string
	Created         []getNSDomainResult
	Existing        []getNSDomainResult
	ParseErrors     []string
	Failed          []string
	ManualNS        []string
	RegistrarSynced int
}

func (r getNSBatchResult) HasInputErrors() bool {
	return len(r.ParseErrors) > 0 || len(r.Failed) > 0
}

func (r getNSBatchResult) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("✅ /getns 处理完成\n目标账号: %s\n新增: %d\n已存在: %d", r.TargetAccount, len(r.Created), len(r.Existing)))
	if r.RegistrarSynced > 0 {
		sb.WriteString(fmt.Sprintf("\n注册商已自动同步: %d", r.RegistrarSynced))
	}

	if len(r.Existing) > 0 {
		sb.WriteString("\n\n已存在:")
		for _, item := range r.Existing {
			sb.WriteString(fmt.Sprintf("\n- %s -> %s", item.Domain, item.AccountLabel))
		}
	}

	if len(r.ManualNS) > 0 {
		sb.WriteString("\n\n需手动设置 NS:")
		for _, item := range r.ManualNS {
			sb.WriteString("\n" + item)
		}
	}

	if len(r.ParseErrors) > 0 {
		sb.WriteString("\n\n格式错误:")
		for _, item := range r.ParseErrors {
			sb.WriteString("\n- " + item)
		}
	}

	if len(r.Failed) > 0 {
		sb.WriteString("\n\n处理失败:")
		for _, item := range r.Failed {
			sb.WriteString("\n- " + item)
		}
	}

	if r.HasInputErrors() {
		sb.WriteString("\n\n可继续直接发送失败域名重试。")
	}

	return sb.String()
}

func (h *CommandHandler) handleGetNSCommand(args []string) {
	if len(h.Accounts) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法添加域名。")
		return
	}

	if len(args) == 0 {
		h.sendGetNSAccountSelector()
		return
	}

	domains, selected, selectorErr := h.parseGetNSDomainsAndAccount(args)
	if selectorErr != nil {
		h.sendText(selectorErr.Error())
		return
	}

	if selected == nil {
		h.sendGetNSAccountSelector()
		return
	}

	if len(domains) == 0 {
		if h.operator != nil {
			SetPendingGetNSInput(h.operator.ID, GetNSInputRequest{AccountLabel: selected.Label})
		}
		h.sendText(h.getNSInputPrompt(selected.Label))
		return
	}

	result := h.processGetNSBatch(*selected, domains)
	if h.operator != nil && !result.HasInputErrors() {
		ClearPendingGetNSInput(h.operator.ID)
	}
	h.sendText(result.Summary())
}

func (h *CommandHandler) sendGetNSAccountSelector() {
	var buttons [][]Button
	for _, acc := range h.Accounts {
		label := strings.TrimSpace(acc.Label)
		if label == "" {
			continue
		}
		token := SetGetNSCallbackPayload(GetNSCallbackPayload{AccountLabel: label})
		buttons = append(buttons, []Button{{
			Text:         label,
			CallbackData: fmt.Sprintf("getns_select|%s", token),
		}})
	}

	if len(buttons) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法添加域名。")
		return
	}

	if err := h.Sender.SendWithButtons(context.Background(), h.getNSPromptText(), buttons); err != nil {
		h.sendText(fmt.Sprintf("发送账号选择失败: %v", err))
	}
}

func (h *CommandHandler) handlePendingGetNSInput(msgText string, userID int64) bool {
	req, ok := GetPendingGetNSInput(userID)
	if !ok {
		return false
	}

	domains, parseErrors := parseGetNSDomainsInput(msgText)
	if len(domains) == 0 {
		h.sendText(h.getNSRetryPrompt(req.AccountLabel, parseErrors))
		return true
	}

	acc := h.getAccountByLabel(req.AccountLabel)
	if acc == nil {
		ClearPendingGetNSInput(userID)
		h.sendText(fmt.Sprintf("未找到账号 %s，已取消本次 /getns 操作。", req.AccountLabel))
		return true
	}

	result := h.processGetNSBatch(*acc, domains)
	result.ParseErrors = append(result.ParseErrors, parseErrors...)
	if !result.HasInputErrors() {
		ClearPendingGetNSInput(userID)
	}

	h.sendText(result.Summary())
	return true
}

func (h *CommandHandler) processGetNSBatch(selected config.CF, rawDomains []string) getNSBatchResult {
	domains, parseErrors := parseGetNSDomainsInput(strings.Join(rawDomains, "\n"))
	result := getNSBatchResult{
		TargetAccount: selected.Label,
		ParseErrors:   parseErrors,
	}

	for _, domain := range domains {
		if acc, zone, err := h.findZone(domain); err == nil {
			item := getNSDomainResult{
				Domain:       zone.Name,
				AccountLabel: acc.Label,
			}
			_ = h.appendGetNSManualOrSynced(domain, zone.NameServers, &result)
			result.Existing = append(result.Existing, item)
			continue
		} else if !errors.Is(err, cfclient.ErrZoneNotFound) {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", domain, err))
			continue
		}

		zone, err := h.CFClient.CreateZone(context.Background(), selected, domain)
		if err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", domain, err))
			continue
		}

		item := getNSDomainResult{
			Domain:       zone.Name,
			AccountLabel: selected.Label,
		}
		_ = h.appendGetNSManualOrSynced(domain, zone.NameServers, &result)
		result.Created = append(result.Created, item)
	}

	return result
}

func (h *CommandHandler) appendGetNSManualOrSynced(domain string, nameServers []string, result *getNSBatchResult) error {
	if len(nameServers) == 0 {
		result.ManualNS = append(result.ManualNS, fmt.Sprintf("- %s\n  未获取到 NS", domain))
		return fmt.Errorf("未获取到 NS")
	}

	if _, err := h.syncRegistrarNameServers(domain, nameServers); err != nil {
		manual := fmt.Sprintf("- %s\n  %s", domain, strings.Join(nameServers, "\n  "))
		if h.RegistrarManager != nil {
			manual += fmt.Sprintf("\n  同步失败: %v", err)
		}
		result.ManualNS = append(result.ManualNS, manual)
		return err
	}

	result.RegistrarSynced++
	return nil
}

func (h *CommandHandler) parseGetNSDomainsAndAccount(args []string) ([]string, *config.CF, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}

	last := strings.TrimSpace(args[len(args)-1])
	if acc := h.getAccountByLabel(last); acc != nil {
		return args[:len(args)-1], acc, nil
	}

	return args, nil, nil
}

func (h *CommandHandler) getNSPromptText() string {
	if len(h.Accounts) == 0 {
		return "未配置可用的 Cloudflare 账号，无法添加域名。"
	}

	var sb strings.Builder
	sb.WriteString("请选择要添加域名的 Cloudflare 账号：\n")
	for _, a := range h.Accounts {
		if strings.TrimSpace(a.Label) == "" {
			continue
		}
		sb.WriteString("- " + a.Label + "\n")
	}
	sb.WriteString("\n选择后直接发送一个或多个域名即可。")
	return sb.String()
}

func (h *CommandHandler) getNSInputPrompt(accountLabel string) string {
	return fmt.Sprintf("已选择账号 %s。\n请直接发送要添加的域名，支持多行、空格、逗号或分号分隔。\n示例：\nexample.com\nexample.net", accountLabel)
}

func (h *CommandHandler) getNSRetryPrompt(accountLabel string, errs []string) string {
	var sb strings.Builder
	if len(errs) > 0 {
		sb.WriteString("以下域名未识别：\n")
		for _, item := range errs {
			sb.WriteString("- " + item + "\n")
		}
		sb.WriteString("\n")
	}
	sb.WriteString(h.getNSInputPrompt(accountLabel))
	return strings.TrimSpace(sb.String())
}

func parseGetNSDomainsInput(input string) ([]string, []string) {
	fields := strings.FieldsFunc(input, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';'
	})

	seen := make(map[string]struct{})
	domains := make([]string, 0, len(fields))
	var errs []string

	for _, raw := range fields {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}

		domain, err := extractDomainOrHost(token)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", token, err))
			continue
		}

		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}

	if len(domains) == 0 && len(errs) == 0 {
		errs = append(errs, "输入为空")
	}

	return domains, errs
}

func (h *CommandHandler) syncRegistrarNameServers(domain string, nameServers []string) (config.Registrar, error) {
	if h.RegistrarManager == nil {
		return config.Registrar{}, fmt.Errorf("未配置注册商")
	}
	if len(nameServers) == 0 {
		return config.Registrar{}, fmt.Errorf("未获取到 NS")
	}
	return h.RegistrarManager.SetNameServersForDomain(context.Background(), domain, nameServers)
}

func (h *CommandHandler) setRegistrarNameServers(domain string, nameServers []string) {
	registrar, err := h.syncRegistrarNameServers(domain, nameServers)
	if err != nil {
		h.sendText(fmt.Sprintf("同步注册商 NS 失败: %v", err))
		return
	}
	h.sendText(fmt.Sprintf("已同步 NS 到注册商账号 %s (%s)。", registrar.Label, registrar.Type))
}
