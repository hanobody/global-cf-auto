package telegram

import (
	"context"
	"fmt"
	"net"
	"strings"

	"DomainC/config"

	cloudflare "github.com/cloudflare/cloudflare-go"
)

type ipListBatchEntry struct {
	IP      string
	Comment string
}

type ipListBatchResult struct {
	Request     IPListInputRequest
	Success     int
	ParseErrors []string
	Missing     []string
	Failed      []string
}

func (r ipListBatchResult) HasErrors() bool {
	return len(r.ParseErrors) > 0 || len(r.Missing) > 0 || len(r.Failed) > 0
}

func (r ipListBatchResult) Summary() string {
	actionText := "添加"
	if r.Request.Action == IPListActionDelete {
		actionText = "删除"
	}

	listName := r.Request.ListName
	if strings.TrimSpace(listName) == "" {
		listName = r.Request.ListID
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("✅ 白名单%s处理完成\n账号: %s\n名单: %s\n成功: %d", actionText, r.Request.AccountLabel, listName, r.Success))

	if len(r.ParseErrors) > 0 {
		sb.WriteString("\n\n格式错误:")
		for _, item := range r.ParseErrors {
			sb.WriteString("\n- " + item)
		}
	}

	if len(r.Missing) > 0 {
		sb.WriteString("\n\n未找到的地址:")
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
		sb.WriteString("\n\n可继续直接发送失败条目重试。")
	}

	return sb.String()
}

func (h *CommandHandler) handleIPListCommand(args []string) {
	if len(h.Accounts) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法操作白名单。")
		return
	}

	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		h.sendIPListAccountSelector()
		return
	}

	selector := strings.TrimSpace(args[0])
	if strings.EqualFold(selector, "all") {
		for _, acc := range h.Accounts {
			h.sendIPListListSelector(acc)
		}
		return
	}

	acc := h.getAccountByLabel(selector)
	if acc == nil {
		h.sendText(fmt.Sprintf("未找到账号 %s。\n\n%s", selector, h.ipListPromptText()))
		return
	}

	h.sendIPListListSelector(*acc)
}

func (h *CommandHandler) sendIPListAccountSelector() {
	var buttons [][]Button
	for _, acc := range h.Accounts {
		label := strings.TrimSpace(acc.Label)
		if label == "" {
			continue
		}
		token := SetIPListCallbackPayload(IPListCallbackPayload{AccountLabel: label})
		buttons = append(buttons, []Button{{
			Text:         label,
			CallbackData: fmt.Sprintf("iplist_account|%s", token),
		}})
	}

	if len(buttons) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法操作白名单。")
		return
	}

	if err := h.Sender.SendWithButtons(context.Background(), h.ipListPromptText(), buttons); err != nil {
		h.sendText(fmt.Sprintf("发送白名单账号选择失败: %v", err))
	}
}

func (h *CommandHandler) sendIPListListSelector(account config.CF) {
	lists, err := h.CFClient.ListCustomLists(context.Background(), account)
	if err != nil {
		h.sendText(fmt.Sprintf("查询账号 %s 白名单失败: %v", account.Label, err))
		return
	}
	if len(lists) == 0 {
		h.sendText(fmt.Sprintf("账号 %s 暂无 IP 白名单。", account.Label))
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("【IP 白名单】\n账号: %s\n请选择要操作的名单：\n", account.Label))
	for i, list := range lists {
		sb.WriteString(fmt.Sprintf("%d. %s (%d)\n", i+1, list.Name, list.NumItems))
	}

	if err := h.Sender.SendWithButtons(context.Background(), sb.String(), buildIPListListButtons(account.Label, lists)); err != nil {
		h.sendText(fmt.Sprintf("发送账号 %s 白名单列表失败: %v", account.Label, err))
	}
}

func buildIPListListButtons(accountLabel string, lists []cloudflare.List) [][]Button {
	buttons := make([][]Button, 0, len(lists))
	for _, list := range lists {
		token := SetIPListCallbackPayload(IPListCallbackPayload{
			AccountLabel: accountLabel,
			ListID:       list.ID,
			ListName:     list.Name,
		})
		buttons = append(buttons, []Button{
			{Text: "添加 " + list.Name, CallbackData: fmt.Sprintf("iplist_add|%s", token)},
			{Text: "删除 " + list.Name, CallbackData: fmt.Sprintf("iplist_delete|%s", token)},
		})
	}
	return buttons
}

func (h *CommandHandler) ipListPromptText() string {
	if len(h.Accounts) == 0 {
		return "未配置可用的 Cloudflare 账号，无法操作白名单。"
	}

	var sb strings.Builder
	sb.WriteString("请选择要操作白名单的 Cloudflare 账号：\n")
	for _, a := range h.Accounts {
		if strings.TrimSpace(a.Label) == "" {
			continue
		}
		sb.WriteString("- " + a.Label + "\n")
	}
	sb.WriteString("\n也可以直接输入：/iplist 账号标签")
	return sb.String()
}

func (h *CommandHandler) ipListInputPrompt(req IPListInputRequest) string {
	listName := req.ListName
	if strings.TrimSpace(listName) == "" {
		listName = req.ListID
	}

	switch req.Action {
	case IPListActionDelete:
		return fmt.Sprintf("已选择白名单 %s（账号: %s）。\n请直接发送要删除的地址，每行一条，只需填写 IP 或 CIDR。\n示例：\n1.2.3.4\n2407:cdc0:b010::/112", listName, req.AccountLabel)
	default:
		return fmt.Sprintf("已选择白名单 %s（账号: %s）。\n请直接发送要添加的地址，每行一条，格式：IP 或 CIDR，备注可选。\n示例：\n1.2.3.4 办公网\n2407:cdc0:b010::/112 香港", listName, req.AccountLabel)
	}
}

func (h *CommandHandler) ipListRetryPrompt(req IPListInputRequest, errs []string) string {
	var sb strings.Builder
	if len(errs) > 0 {
		sb.WriteString("以下内容未识别：\n")
		for _, item := range errs {
			sb.WriteString("- " + item + "\n")
		}
		sb.WriteString("\n")
	}
	sb.WriteString(h.ipListInputPrompt(req))
	return strings.TrimSpace(sb.String())
}

func (h *CommandHandler) handlePendingIPListInput(msgText string, userID int64) bool {
	req, ok := GetPendingIPListInput(userID)
	if !ok {
		return false
	}

	entries, parseErrors := parseIPListBatchEntries(msgText)
	if len(entries) == 0 {
		h.sendText(h.ipListRetryPrompt(req, parseErrors))
		return true
	}

	acc := h.getAccountByLabel(req.AccountLabel)
	if acc == nil {
		ClearPendingIPListInput(userID)
		h.sendText(fmt.Sprintf("未找到账号 %s，已取消本次白名单操作。", req.AccountLabel))
		return true
	}

	var result ipListBatchResult
	switch req.Action {
	case IPListActionAdd:
		result = h.processIPListAddBatch(*acc, req, entries)
	case IPListActionDelete:
		result = h.processIPListDeleteBatch(*acc, req, entries)
	default:
		ClearPendingIPListInput(userID)
		h.sendText("未知的白名单操作，已取消。")
		return true
	}
	result.ParseErrors = append(result.ParseErrors, parseErrors...)

	if !result.HasErrors() {
		ClearPendingIPListInput(userID)
	}

	h.sendText(result.Summary())
	return true
}

func (h *CommandHandler) processIPListAddBatch(acc config.CF, req IPListInputRequest, entries []ipListBatchEntry) ipListBatchResult {
	result := ipListBatchResult{Request: req}
	for _, entry := range entries {
		if _, err := h.CFClient.CreateCustomListItem(context.Background(), acc, req.ListID, entry.IP, entry.Comment); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", entry.IP, err))
			continue
		}
		result.Success++
	}
	return result
}

func (h *CommandHandler) processIPListDeleteBatch(acc config.CF, req IPListInputRequest, entries []ipListBatchEntry) ipListBatchResult {
	result := ipListBatchResult{Request: req}

	items, err := h.CFClient.ListCustomListItems(context.Background(), acc, req.ListID)
	if err != nil {
		result.Failed = append(result.Failed, fmt.Sprintf("读取白名单失败: %v", err))
		return result
	}

	index := make(map[string][]string)
	for _, item := range items {
		if item.ID == "" || item.IP == nil {
			continue
		}
		ip, err := normalizeIPListValue(*item.IP)
		if err != nil || ip == "" {
			continue
		}
		index[ip] = append(index[ip], item.ID)
	}

	for _, entry := range entries {
		itemIDs := index[entry.IP]
		if len(itemIDs) == 0 {
			result.Missing = append(result.Missing, entry.IP)
			continue
		}

		failed := false
		for _, itemID := range itemIDs {
			if _, err := h.CFClient.DeleteCustomListItem(context.Background(), acc, req.ListID, itemID); err != nil {
				result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", entry.IP, err))
				failed = true
				break
			}
		}
		if failed {
			continue
		}

		result.Success++
		delete(index, entry.IP)
	}

	return result
}

func parseIPListBatchEntries(input string) ([]ipListBatchEntry, []string) {
	lines := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")
	entries := make([]ipListBatchEntry, 0, len(lines))
	var errs []string

	for idx, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		ip, comment, err := parseIPListInput(line)
		if err != nil {
			errs = append(errs, fmt.Sprintf("第 %d 行: %v", idx+1, err))
			continue
		}

		entries = append(entries, ipListBatchEntry{
			IP:      ip,
			Comment: comment,
		})
	}

	if len(entries) == 0 && len(errs) == 0 {
		errs = append(errs, "输入为空")
	}

	return entries, errs
}

func parseIPListInput(input string) (string, string, error) {
	fields := strings.Fields(strings.TrimSpace(input))
	if len(fields) == 0 {
		return "", "", fmt.Errorf("输入为空")
	}

	ipStr, err := normalizeIPListValue(fields[0])
	if err != nil {
		return "", "", err
	}

	comment := strings.TrimSpace(strings.Join(fields[1:], " "))
	return ipStr, comment, nil
}

func normalizeIPListValue(input string) (string, error) {
	ipStr := strings.TrimSpace(input)
	if ipStr == "" {
		return "", fmt.Errorf("IP 不能为空")
	}

	if strings.Contains(ipStr, "/") {
		_, network, err := net.ParseCIDR(ipStr)
		if err != nil {
			return "", err
		}
		return network.String(), nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("IP 无法解析")
	}
	return ip.String(), nil
}
