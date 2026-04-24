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
	sb.WriteString(fmt.Sprintf("✅ /delete 处理完成\n搜索范围: %s\n成功: %d", r.TargetAccount, len(r.Deleted)))

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

func ProcessDeleteBatch(client cfclient.Client, accounts []config.CF, domains []string) DeleteBatchResult {
	if client == nil {
		client = cfclient.NewClient()
	}

	result := DeleteBatchResult{
		TargetAccount: "自动搜索所有账号",
	}
	if len(accounts) == 0 {
		result.Failed = append(result.Failed, "未配置可用的 Cloudflare 账号")
		return result
	}

	ctx := context.Background()
	pacer := newBatchAPIPacer()
	for _, domain := range domains {
		if err := pacer.Wait(ctx); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: 删除前等待失败: %v", domain, err))
			continue
		}

		if _, err := deleteDomainAcrossAccounts(ctx, client, accounts, domain); err != nil {
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
		if h.operator != nil {
			SetPendingDeleteInput(h.operator.ID, DeleteInputRequest{})
		}
		h.sendText(h.deletePromptText())
		return
	}

	domains, parseErrors := parseGetNSDomainsInput(strings.Join(args, "\n"))
	if len(domains) == 0 {
		h.sendText(h.deleteRetryPrompt("", parseErrors))
		return
	}

	h.sendDeleteBatchConfirm(domains, parseErrors)
}

func (h *CommandHandler) handlePendingDeleteInput(msgText string, userID int64) bool {
	_, ok := GetPendingDeleteInput(userID)
	if !ok {
		return false
	}

	domains, parseErrors := parseGetNSDomainsInput(msgText)
	if len(domains) == 0 {
		h.sendText(h.deleteRetryPrompt("", parseErrors))
		return true
	}

	ClearPendingDeleteInput(userID)
	h.sendDeleteBatchConfirm(domains, parseErrors)
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
	sb.WriteString("请直接发送要删除的域名，系统会自动在所有 Cloudflare 账号中搜索并删除。\n")
	sb.WriteString("支持多行、空格、逗号或分号分隔。\n")
	sb.WriteString("\n示例：\n/delete example.com example.net")
	sb.WriteString("\n或者下一条直接发送：\nexample.com\nexample.net")
	return sb.String()
}

func BuildDeleteInputPrompt(accountLabel string) string {
	if strings.TrimSpace(accountLabel) != "" {
		return fmt.Sprintf("已选择账号 %s。\n请直接发送要删除的域名，支持多行、空格、逗号或分号分隔。\n示例：\nexample.com\nexample.net", accountLabel)
	}
	return "请直接发送要删除的域名，系统会自动在所有 Cloudflare 账号中搜索并删除。\n支持多行、空格、逗号或分号分隔。\n示例：\nexample.com\nexample.net"
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

func (h *CommandHandler) sendDeleteBatchConfirm(domains []string, parseErrors []string) {
	token := SetDeleteCallbackPayload(DeleteCallbackPayload{
		Domains:     domains,
		ParseErrors: parseErrors,
	})

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("⚠️【批量删除确认】\n操作人: %s\n搜索范围: 自动搜索所有账号\n待删域名: %d", formatOperator(h.operator), len(domains)))
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

func deleteDomainAcrossAccounts(ctx context.Context, client cfclient.Client, accounts []config.CF, domain string) (*config.CF, error) {
	var lastErr error
	for i := range accounts {
		acc := accounts[i]
		err := client.DeleteDomain(ctx, acc, domain)
		if err != nil {
			if errors.Is(err, cfclient.ErrZoneNotFound) {
				lastErr = err
				continue
			}
			return nil, err
		}
		return &acc, nil
	}
	if lastErr == nil {
		lastErr = cfclient.ErrZoneNotFound
	}
	return nil, lastErr
}
