package telegram

import (
	"fmt"
	"strings"
)

const (
	ipListDeleteItemsPerPage = 8
	setDNSItemsPerPage       = 8
)

func BuildIPListDeleteSelectionView(sessionID string, selection IPListDeleteSelection) IPListPage {
	totalPages := pageCount(len(selection.Items), ipListDeleteItemsPerPage)
	page := clampPage(selection.Page, totalPages)
	start := page * ipListDeleteItemsPerPage
	end := start + ipListDeleteItemsPerPage
	if end > len(selection.Items) {
		end = len(selection.Items)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("【IP 删除选择】\n账号: %s\n页码: %d/%d\n已选择: %d/%d\n\n",
		selection.AccountLabel, page+1, totalPages, countSelected(selection.Selected), len(selection.Items)))
	for i := start; i < end; i++ {
		item := selection.Items[i]
		comment := strings.TrimSpace(item.Comment)
		if comment == "" {
			comment = "无"
		}
		listName := strings.TrimSpace(item.ListName)
		if listName == "" {
			listName = item.ListID
		}
		sb.WriteString(fmt.Sprintf("%d. [%s] %s | 备注: %s\n",
			i+1, truncateDisplay(listName, 18), item.IP, truncateDisplay(comment, 60)))
	}

	var buttons [][]Button
	for i := start; i < end; i++ {
		item := selection.Items[i]
		mark := "☐"
		if selection.Selected[item.Key] {
			mark = "☑"
		}
		token := SetIPListCallbackPayload(IPListCallbackPayload{
			AccountLabel: selection.AccountLabel,
			SessionID:    sessionID,
			ItemKey:      item.Key,
			Page:         page,
		})
		buttons = append(buttons, []Button{{
			Text:         fmt.Sprintf("%s %d. %s", mark, i+1, truncateDisplay(item.IP, 34)),
			CallbackData: fmt.Sprintf("iplist_select_toggle|%s", token),
		}})
	}

	var nav []Button
	if page > 0 {
		token := SetIPListCallbackPayload(IPListCallbackPayload{
			AccountLabel: selection.AccountLabel,
			SessionID:    sessionID,
			Page:         page - 1,
		})
		nav = append(nav, Button{Text: "上一页", CallbackData: fmt.Sprintf("iplist_select_page|%s", token)})
	}
	if page+1 < totalPages {
		token := SetIPListCallbackPayload(IPListCallbackPayload{
			AccountLabel: selection.AccountLabel,
			SessionID:    sessionID,
			Page:         page + 1,
		})
		nav = append(nav, Button{Text: "下一页", CallbackData: fmt.Sprintf("iplist_select_page|%s", token)})
	}
	if len(nav) > 0 {
		buttons = append(buttons, nav)
	}

	confirmToken := SetIPListCallbackPayload(IPListCallbackPayload{
		AccountLabel: selection.AccountLabel,
		SessionID:    sessionID,
		Page:         page,
	})
	buttons = append(buttons, []Button{
		{Text: "确认选择", CallbackData: fmt.Sprintf("iplist_select_done|%s", confirmToken)},
		{Text: "取消", CallbackData: fmt.Sprintf("iplist_select_cancel|%s", confirmToken)},
	})

	return IPListPage{Message: sb.String(), Buttons: buttons}
}

func BuildIPListDeleteConfirmView(sessionID string, items []IPListDeleteItem) IPListPage {
	var accountLabel string
	if len(items) > 0 {
		accountLabel = items[0].AccountLabel
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("⚠️【IP 删除汇总确认】\n账号: %s\n待删除: %d\n", accountLabel, len(items)))
	for i, item := range items {
		if i >= 20 {
			sb.WriteString(fmt.Sprintf("- ... 其余 %d 条\n", len(items)-i))
			break
		}
		comment := strings.TrimSpace(item.Comment)
		if comment == "" {
			comment = "无"
		}
		listName := strings.TrimSpace(item.ListName)
		if listName == "" {
			listName = item.ListID
		}
		sb.WriteString(fmt.Sprintf("- [%s] %s | 备注: %s\n", truncateDisplay(listName, 18), item.IP, truncateDisplay(comment, 50)))
	}
	sb.WriteString("\n此操作不可逆，确认执行删除吗？")

	token := SetIPListCallbackPayload(IPListCallbackPayload{
		AccountLabel: accountLabel,
		SessionID:    sessionID,
	})
	return IPListPage{
		Message: sb.String(),
		Buttons: [][]Button{{
			{Text: "确认删除", CallbackData: fmt.Sprintf("iplist_select_confirm|%s", token)},
			{Text: "取消", CallbackData: fmt.Sprintf("iplist_select_cancel|%s", token)},
		}},
	}
}

func BuildSetDNSSelectionView(sessionID string, selection SetDNSSelection) IPListPage {
	totalPages := pageCount(len(selection.Candidates), setDNSItemsPerPage)
	page := clampPage(selection.Page, totalPages)
	start := page * setDNSItemsPerPage
	end := start + setDNSItemsPerPage
	if end > len(selection.Candidates) {
		end = len(selection.Candidates)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("【setdns 选择域名】\n账号: %s\n页码: %d/%d\n已选择: %d/%d\n\n",
		selection.AccountLabel, page+1, totalPages, countSelected(selection.Selected), len(selection.Candidates)))
	for i := start; i < end; i++ {
		target := selection.Candidates[i]
		sb.WriteString(fmt.Sprintf("%d. %s %s -> %s\n",
			i+1, target.Type, target.Name, truncateDisplay(target.Content, 70)))
		if len(target.Matches) > 0 {
			sb.WriteString(fmt.Sprintf("   匹配: %s\n", strings.Join(target.Matches, ", ")))
		}
	}

	var buttons [][]Button
	for i := start; i < end; i++ {
		target := selection.Candidates[i]
		mark := "☐"
		if selection.Selected[target.Key] {
			mark = "☑"
		}
		token := SetSetDNSCallbackPayload(SetDNSCallbackPayload{
			AccountLabel: selection.AccountLabel,
			SessionID:    sessionID,
			ItemKey:      target.Key,
			Page:         page,
		})
		buttons = append(buttons, []Button{{
			Text:         fmt.Sprintf("%s %d. %s", mark, i+1, truncateDisplay(target.Name, 36)),
			CallbackData: fmt.Sprintf("setdns_toggle|%s", token),
		}})
	}

	var nav []Button
	if page > 0 {
		token := SetSetDNSCallbackPayload(SetDNSCallbackPayload{
			AccountLabel: selection.AccountLabel,
			SessionID:    sessionID,
			Page:         page - 1,
		})
		nav = append(nav, Button{Text: "上一页", CallbackData: fmt.Sprintf("setdns_page|%s", token)})
	}
	if page+1 < totalPages {
		token := SetSetDNSCallbackPayload(SetDNSCallbackPayload{
			AccountLabel: selection.AccountLabel,
			SessionID:    sessionID,
			Page:         page + 1,
		})
		nav = append(nav, Button{Text: "下一页", CallbackData: fmt.Sprintf("setdns_page|%s", token)})
	}
	if len(nav) > 0 {
		buttons = append(buttons, nav)
	}

	token := SetSetDNSCallbackPayload(SetDNSCallbackPayload{
		AccountLabel: selection.AccountLabel,
		SessionID:    sessionID,
		Page:         page,
	})
	buttons = append(buttons, []Button{
		{Text: "确认选择", CallbackData: fmt.Sprintf("setdns_done|%s", token)},
		{Text: "取消", CallbackData: fmt.Sprintf("setdns_cancel|%s", token)},
	})

	return IPListPage{Message: sb.String(), Buttons: buttons}
}

func BuildSetDNSConfirmView(sessionID string, targets []SetDNSRecordTarget) IPListPage {
	var accountLabel string
	if selection, ok := GetSetDNSSelection(sessionID); ok {
		accountLabel = selection.AccountLabel
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("⚠️【setdns 修改汇总确认】\n账号: %s\n待修改: %d\n", accountLabel, len(targets)))
	for i, target := range targets {
		if i >= 20 {
			sb.WriteString(fmt.Sprintf("- ... 其余 %d 条\n", len(targets)-i))
			break
		}
		sb.WriteString(fmt.Sprintf("- %s %s -> %s\n", target.Type, target.Name, truncateDisplay(target.Content, 60)))
	}
	sb.WriteString("\n确认后请发送新的解析目标。")

	token := SetSetDNSCallbackPayload(SetDNSCallbackPayload{
		AccountLabel: accountLabel,
		SessionID:    sessionID,
	})
	return IPListPage{
		Message: sb.String(),
		Buttons: [][]Button{{
			{Text: "确认并输入新目标", CallbackData: fmt.Sprintf("setdns_apply|%s", token)},
			{Text: "返回选择", CallbackData: fmt.Sprintf("setdns_continue|%s", token)},
			{Text: "取消", CallbackData: fmt.Sprintf("setdns_cancel|%s", token)},
		}},
	}
}

func pageCount(total int, pageSize int) int {
	if pageSize <= 0 || total <= 0 {
		return 1
	}
	pages := total / pageSize
	if total%pageSize != 0 {
		pages++
	}
	if pages == 0 {
		return 1
	}
	return pages
}

func clampPage(page int, totalPages int) int {
	if totalPages <= 0 {
		return 0
	}
	if page < 0 {
		return 0
	}
	if page >= totalPages {
		return totalPages - 1
	}
	return page
}

func countSelected(selected map[string]bool) int {
	n := 0
	for _, ok := range selected {
		if ok {
			n++
		}
	}
	return n
}

func truncateDisplay(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	runes := []rune(s)
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + "…"
}
