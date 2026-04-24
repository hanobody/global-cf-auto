package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"DomainC/cfclient"
	"DomainC/config"
)

type DeleteBatchResult struct {
	TargetAccount string
	Deleted       []string
	ParseErrors   []string
	Missing       []string
	Failed        []string
}

func (r DeleteBatchResult) HasErrors() bool {
	return len(r.ParseErrors) > 0 || len(r.Missing) > 0 || len(r.Failed) > 0
}

func (r DeleteBatchResult) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("✅ /delete 处理完成\n目标账号: %s\n成功: %d", r.TargetAccount, len(r.Deleted)))

	if len(r.ParseErrors) > 0 {
		sb.WriteString("\n\n格式错误:")
		for _, item := range r.ParseErrors {
			sb.WriteString("\n- " + item)
		}
	}

	if len(r.Missing) > 0 {
		sb.WriteString("\n\n未找到的域名:")
		for _, item := range r.Missing {
			sb.WriteString("\n- " + item)
		}
	}

	if len(r.Failed) > 0 {
		sb.WriteString("\n\n处理失败:")
		for _, item := range r.Failed {
			sb.WriteString("\n- " + item)
		}
	}

	if r.HasErrors() {
		sb.WriteString("\n\n可继续直接发送失败域名重试。")
	}

	return sb.String()
}

func ProcessDeleteBatch(client cfclient.Client, account config.CF, domains []string) DeleteBatchResult {
	if client == nil {
		client = cfclient.NewClient()
	}

	result := DeleteBatchResult{
		TargetAccount: account.Label,
	}

	ctx := context.Background()
	pacer := newBatchAPIPacer()
	for _, domain := range domains {
		if err := pacer.Wait(ctx); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: 删除前等待失败: %v", domain, err))
			continue
		}

		if err := client.DeleteDomain(ctx, account, domain); err != nil {
			if errors.Is(err, cfclient.ErrZoneNotFound) || strings.Contains(strings.ToLower(err.Error()), "zone not found") {
				result.Missing = append(result.Missing, domain)
				continue
			}
			result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", domain, err))
			continue
		}

		result.Deleted = append(result.Deleted, domain)
	}

	return result
}

func (h *CommandHandler) handleDeleteCommand(args []string) {
	if len(h.Accounts) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法删除域名。")
		return
	}

	if len(args) == 0 {
		h.sendDeleteAccountSelector()
		return
	}

	domains, selected, _ := h.parseDeleteDomainsAndAccount(args)
	if selected == nil {
		if len(args) == 1 {
			h.handleSingleDeleteConfirm(args[0])
			return
		}
		h.sendDeleteAccountSelector()
		return
	}

	if len(domains) == 0 {
		if h.operator != nil {
			SetPendingDeleteInput(h.operator.ID, DeleteInputRequest{AccountLabel: selected.Label})
		}
		h.sendText(BuildDeleteInputPrompt(selected.Label))
		return
	}

	parsedDomains, parseErrors := parseGetNSDomainsInput(strings.Join(domains, "\n"))
	if len(parsedDomains) == 0 {
		h.sendText(h.deleteRetryPrompt(selected.Label, parseErrors))
		return
	}

	h.sendDeleteBatchConfirm(*selected, parsedDomains, parseErrors)
}

func (h *CommandHandler) handlePendingDeleteInput(msgText string, userID int64) bool {
	req, ok := GetPendingDeleteInput(userID)
	if !ok {
		return false
	}

	domains, parseErrors := parseGetNSDomainsInput(msgText)
	if len(domains) == 0 {
		h.sendText(h.deleteRetryPrompt(req.AccountLabel, parseErrors))
		return true
	}

	acc := h.getAccountByLabel(req.AccountLabel)
	if acc == nil {
		ClearPendingDeleteInput(userID)
		h.sendText(fmt.Sprintf("未找到账号 %s，已取消本次 /delete 操作。", req.AccountLabel))
		return true
	}

	ClearPendingDeleteInput(userID)
	h.sendDeleteBatchConfirm(*acc, domains, parseErrors)
	return true
}

func (h *CommandHandler) sendDeleteAccountSelector() {
	var buttons [][]Button
	for _, acc := range h.Accounts {
		label := strings.TrimSpace(acc.Label)
		if label == "" {
			continue
		}
		token := SetDeleteCallbackPayload(DeleteCallbackPayload{AccountLabel: label})
		buttons = append(buttons, []Button{{
			Text:         label,
			CallbackData: fmt.Sprintf("deletecmd_select|%s", token),
		}})
	}

	if len(buttons) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法删除域名。")
		return
	}

	if err := h.Sender.SendWithButtons(context.Background(), h.deletePromptText(), buttons); err != nil {
		h.sendText(fmt.Sprintf("发送删除账号选择失败: %v", err))
	}
}

func (h *CommandHandler) deletePromptText() string {
	if len(h.Accounts) == 0 {
		return "未配置可用的 Cloudflare 账号，无法删除域名。"
	}

	var sb strings.Builder
	sb.WriteString("请选择要删除域名的 Cloudflare 账号：\n")
	for _, a := range h.Accounts {
		if strings.TrimSpace(a.Label) == "" {
			continue
		}
		sb.WriteString("- " + a.Label + "\n")
	}
	sb.WriteString("\n选择后可直接发送一个或多个域名。")
	sb.WriteString("\n也支持：/delete 账号标签")
	sb.WriteString("\n兼容旧用法：/delete example.com")
	return sb.String()
}

func BuildDeleteInputPrompt(accountLabel string) string {
	return fmt.Sprintf("已选择账号 %s。\n请直接发送要删除的域名，支持多行、空格、逗号或分号分隔。\n示例：\nexample.com\nexample.net", accountLabel)
}

func (h *CommandHandler) deleteRetryPrompt(accountLabel string, errs []string) string {
	var sb strings.Builder
	if len(errs) > 0 {
		sb.WriteString("以下域名未识别：\n")
		for _, item := range errs {
			sb.WriteString("- " + item + "\n")
		}
		sb.WriteString("\n")
	}
	sb.WriteString(BuildDeleteInputPrompt(accountLabel))
	return strings.TrimSpace(sb.String())
}

func (h *CommandHandler) sendDeleteBatchConfirm(account config.CF, domains []string, parseErrors []string) {
	token := SetDeleteCallbackPayload(DeleteCallbackPayload{
		AccountLabel: account.Label,
		Domains:      domains,
		ParseErrors:  parseErrors,
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("⚠️【批量删除确认】\n操作人: %s\n账号: %s\n待删域名: %d", formatOperator(h.operator), account.Label, len(domains)))
	for _, line := range previewDeleteDomains(domains, 20) {
		sb.WriteString("\n- " + line)
	}
	if len(domains) > 20 {
		sb.WriteString(fmt.Sprintf("\n- ... 其余 %d 个域名", len(domains)-20))
	}
	if len(parseErrors) > 0 {
		sb.WriteString("\n\n以下内容不会执行:")
		for _, item := range parseErrors {
			sb.WriteString("\n- " + item)
		}
	}
	sb.WriteString("\n\n此操作不可逆，确认要删除以上 Cloudflare Zone 吗？")

	buttons := [][]Button{{
		{Text: "✅ 确认批量删除", CallbackData: fmt.Sprintf("deletecmd_confirm|%s", token)},
		{Text: "❌ 取消", CallbackData: fmt.Sprintf("deletecmd_cancel|%s", token)},
	}}
	if err := h.Sender.SendWithButtons(context.Background(), sb.String(), buttons); err != nil {
		h.sendText(fmt.Sprintf("发送批量删除确认失败: %v", err))
	}
}

func previewDeleteDomains(domains []string, limit int) []string {
	if limit <= 0 || len(domains) <= limit {
		return append([]string(nil), domains...)
	}
	return append([]string(nil), domains[:limit]...)
}

func (h *CommandHandler) parseDeleteDomainsAndAccount(args []string) ([]string, *config.CF, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}

	first := strings.TrimSpace(args[0])
	if acc := h.getAccountByLabel(first); acc != nil {
		return args[1:], acc, nil
	}

	if len(args) > 1 {
		last := strings.TrimSpace(args[len(args)-1])
		if acc := h.getAccountByLabel(last); acc != nil {
			return args[:len(args)-1], acc, nil
		}
	}

	return args, nil, nil
}

func (h *CommandHandler) handleSingleDeleteConfirm(raw string) {
	domain, err := extractDomainOrHost(raw)
	if err != nil {
		h.sendText(fmt.Sprintf("参数不合法：%v\n用法: /delete <domain.com>", err))
		return
	}

	op := formatOperator(h.operator)
	account, _, err := h.findZone(domain)
	if err != nil {
		if errors.Is(err, cfclient.ErrZoneNotFound) {
			h.sendText(fmt.Sprintf("域名 %s 不存在于 Cloudflare。", domain))
			return
		}
		h.sendText(fmt.Sprintf("查询域名失败: %v", err))
		return
	}

	confirmMsg := fmt.Sprintf(
		"⚠️【删除二次确认】\n操作人: %s\n域名: %s\n账号: %s\n\n此操作不可逆，确认要删除该域名（Cloudflare Zone）吗？",
		op, domain, account.Label,
	)
	buttons := [][]Button{{
		{Text: "✅ 确认删除", CallbackData: fmt.Sprintf("delete_confirm|%s|%s", account.Label, domain)},
		{Text: "❌ 取消", CallbackData: fmt.Sprintf("delete_cancel|%s|%s", account.Label, domain)},
	}}
	SendTelegramAlertWithButtons(confirmMsg, buttons)
}
