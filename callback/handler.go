package callback

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"

	"DomainC/cfclient"
	"DomainC/config"
	"DomainC/telegram"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// HandleCallback 处理来自 Notifier 的内联按钮回调
// callbackData 格式：action|accountLabel|domain|[paused yes/no]
func HandleCallback(cb *tgbotapi.CallbackQuery) {
	if cb == nil {
		return
	}
	if cb.Message != nil && cb.Message.Chat != nil && !config.IsTelegramChatAllowed(cb.Message.Chat.ID) {
		return
	}
	callbackData := cb.Data
	user := cb.From
	parts := strings.Split(callbackData, "|")
	if len(parts) < 1 {
		log.Printf("无效的回调数据: %s", callbackData)
		return
	}

	action := parts[0]

	// 避免“处理中”按钮再触发一堆日志
	if action == "noop" {
		return
	}
	if strings.HasPrefix(action, "iplist_") {
		handleIPListCallback(action, parts, user, cb)
		return
	}
	if strings.HasPrefix(action, "getns_") {
		handleGetNSCallback(action, parts, user, cb)
		return
	}
	if strings.HasPrefix(action, "deletecmd_") {
		handleDeleteCommandCallback(action, parts, user, cb)
		return
	}
	if strings.HasPrefix(action, "setdns_") {
		handleSetDNSCallback(action, parts, user, cb)
		return
	}
	if strings.HasPrefix(action, "ssl_") {
		handleOriginSSLCallback(action, parts, user, cb)
		return
	}
	if len(parts) < 3 {
		log.Printf("无效的回调数据: %s", callbackData)
		return
	}

	accountLabel := parts[1]
	domain := strings.ToLower(parts[2])

	paused := ""
	if len(parts) >= 4 {
		paused = parts[3]
	}

	log.Printf("处理回调: action=%s, account=%s, domain=%s, user=%s", action, accountLabel, domain, user.UserName)

	// 创建统一的 Cloudflare 客户端实例
	client := cfclient.NewClient()

	account := cfclient.GetAccountByLabel(accountLabel)
	if account == nil {
		log.Printf("未找到账号标签: %s", accountLabel)
		telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", accountLabel))
		return
	}

	switch action {
	case "pause":
		go func() {
			var successMsg, failMsg string
			if paused == "yes" {
				successMsg = fmt.Sprintf("%s 禁用域名成功: %s --- %s", user.UserName, domain, accountLabel)
				failMsg = fmt.Sprintf("%s 禁用域名失败: %s --- %s (%%v)", user.UserName, domain, accountLabel)
			} else {
				successMsg = fmt.Sprintf("%s 解除禁用成功: %s --- %s", user.UserName, domain, accountLabel)
				failMsg = fmt.Sprintf("%s 解除禁用失败: %s --- %s (%%v)", user.UserName, domain, accountLabel)
			}

			err := client.PauseDomain(context.Background(), *account, domain, paused == "yes")
			if err != nil {
				telegram.SendTelegramAlert(fmt.Sprintf(failMsg, err))
			} else {
				telegram.SendTelegramAlert(successMsg)
			}
		}()

	case "DNS":
		go func() {
			records, err := client.ListDNSRecords(context.Background(), *account, domain)
			if err != nil {
				telegram.SendTelegramAlert(fmt.Sprintf("查询域名解析失败: %s --- %s (%v)", domain, accountLabel, err))
				return
			}

			if len(records) == 0 {
				telegram.SendTelegramAlert(fmt.Sprintf("域名 %s --- %s 没有任何解析记录。", domain, accountLabel))
				return
			}

			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("【域名解析记录】\n域名: %s\n来源: %s\n\n", domain, accountLabel))

			for _, r := range records {
				proxied := "关闭"
				if r.Proxied != nil && *r.Proxied {
					proxied = "开启"
				}
				sb.WriteString(fmt.Sprintf("%s %s → %s (代理: %s)\n", r.Type, r.Name, r.Content, proxied))
			}

			telegram.SendTelegramAlert(sb.String())
		}()

	case "delete":
		go func() {
			confirmMsg := fmt.Sprintf(
				"⚠️【删除二次确认】\n操作人: %s\n域名: %s\n账号: %s\n\n此操作不可逆，确认要删除该域名（Cloudflare Zone）吗？",
				user.UserName, domain, accountLabel,
			)

			buttons := [][]telegram.Button{{
				{Text: "✅ 确认删除", CallbackData: fmt.Sprintf("delete_confirm|%s|%s", accountLabel, domain)},
				{Text: "❌ 取消", CallbackData: fmt.Sprintf("delete_cancel|%s|%s", accountLabel, domain)},
			}}

			telegram.SendTelegramAlertWithButtons(confirmMsg, buttons)
		}()

	case "delete_confirm":
		go func() {
			err := client.DeleteDomain(context.Background(), *account, domain)
			if err != nil {
				telegram.SendTelegramAlert(fmt.Sprintf("删除域名失败: %s --- %s (%v)", domain, accountLabel, err))
				return
			}
			telegram.SendTelegramAlert(fmt.Sprintf("✅ 删除域名成功: %s --- %s (操作人: %s)", domain, accountLabel, user.UserName))
		}()

	case "delete_cancel":
		go func() {
			telegram.SendTelegramAlert(fmt.Sprintf("已取消删除: %s --- %s (操作人: %s)", domain, accountLabel, user.UserName))
		}()
	}
}
func handleIPListCallback(action string, parts []string, user *tgbotapi.User, cb *tgbotapi.CallbackQuery) {
	if len(parts) < 2 {
		log.Printf("无效的 iplist 回调数据: %v", parts)
		return
	}
	token := parts[1]
	payload, ok := telegram.GetIPListCallbackPayload(token)
	if !ok {
		telegram.SendTelegramAlert("操作已过期，请重新打开列表。")
		return
	}

	accountLabel := payload.AccountLabel
	client := cfclient.NewClient()
	sender := telegram.DefaultSender()
	switch action {
	case "iplist_account":
		go func() {
			account := cfclient.GetAccountByLabel(accountLabel)
			if account == nil {
				log.Printf("未找到账号标签: %s", accountLabel)
				telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", accountLabel))
				return
			}

			lists, err := client.ListCustomLists(context.Background(), *account)
			if err != nil {
				telegram.SendTelegramAlert(fmt.Sprintf("查询账号 %s 白名单失败: %v", accountLabel, err))
				return
			}
			if len(lists) == 0 {
				telegram.SendTelegramAlert(fmt.Sprintf("账号 %s 暂无 IP 白名单。", accountLabel))
				return
			}

			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("【IP 白名单】\n账号: %s\n请选择要操作的名单，或直接进入全部 IP 删除选择：\n", accountLabel))

			var buttons [][]telegram.Button
			accountToken := telegram.SetIPListCallbackPayload(telegram.IPListCallbackPayload{
				AccountLabel: accountLabel,
			})
			buttons = append(buttons, []telegram.Button{{
				Text:         "删除IP（全部名单）",
				CallbackData: fmt.Sprintf("iplist_delete_account|%s", accountToken),
			}})
			for i, list := range lists {
				sb.WriteString(fmt.Sprintf("%d. %s (%d)\n", i+1, list.Name, list.NumItems))
				listToken := telegram.SetIPListCallbackPayload(telegram.IPListCallbackPayload{
					AccountLabel: accountLabel,
					ListID:       list.ID,
					ListName:     list.Name,
				})
				buttons = append(buttons, []telegram.Button{
					{Text: "添加 " + list.Name, CallbackData: fmt.Sprintf("iplist_add|%s", listToken)},
					{Text: "删除 " + list.Name, CallbackData: fmt.Sprintf("iplist_delete|%s", listToken)},
				})
			}

			if err := sender.SendWithButtons(context.Background(), sb.String(), buttons); err != nil {
				log.Printf("发送 IP 白名单列表失败: %v", err)
			}
		}()

	case "iplist_edit":
		go func() {
			listName := payload.ListName
			if strings.TrimSpace(listName) == "" {
				account := cfclient.GetAccountByLabel(accountLabel)
				if account != nil {
					if list, err := client.GetCustomList(context.Background(), *account, payload.ListID); err == nil && strings.TrimSpace(list.Name) != "" {
						listName = list.Name
					}
				}
			}
			if strings.TrimSpace(listName) == "" {
				listName = payload.ListID
			}

			telegram.SendTelegramAlertWithButtons(
				fmt.Sprintf("账号: %s\n白名单: %s\n请选择操作：", accountLabel, listName),
				[][]telegram.Button{{
					{Text: "添加", CallbackData: fmt.Sprintf("iplist_add|%s", token)},
					{Text: "删除", CallbackData: fmt.Sprintf("iplist_delete|%s", token)},
				}},
			)
		}()

	case "iplist_delete_account":
		account := cfclient.GetAccountByLabel(accountLabel)
		if account == nil {
			log.Printf("未找到账号标签: %s", accountLabel)
			telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", accountLabel))
			return
		}
		go beginIPListDeleteSelection(client, sender, *account, accountLabel, "")

	case "iplist_delete":
		if payload.ItemID == "" {
			account := cfclient.GetAccountByLabel(accountLabel)
			if account == nil {
				log.Printf("未找到账号标签: %s", accountLabel)
				telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", accountLabel))
				return
			}
			go beginIPListDeleteSelection(client, sender, *account, accountLabel, payload.ListID)
			return
		}

		account := cfclient.GetAccountByLabel(accountLabel)
		if account == nil {
			log.Printf("未找到账号标签: %s", accountLabel)
			telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", accountLabel))
			return
		}

		listID := payload.ListID
		itemID := payload.ItemID
		go func() {
			listName := listID
			if list, err := client.GetCustomList(context.Background(), *account, listID); err == nil && list.Name != "" {
				listName = list.Name
			}

			confirmMsg := fmt.Sprintf(
				"⚠️【删除 IP 二次确认】\n操作人: %s\n账号: %s\n列表: %s\n条目ID: %s\n\n此操作不可逆，确认要删除该条目吗？",
				user.UserName, accountLabel, listName, itemID,
			)

			buttons := [][]telegram.Button{{
				{Text: "✅ 确认删除", CallbackData: fmt.Sprintf("iplist_confirm|%s", token)},
				{Text: "❌ 取消", CallbackData: fmt.Sprintf("iplist_cancel|%s", token)},
			}}

			telegram.SendTelegramAlertWithButtons(confirmMsg, buttons)
		}()
	case "iplist_confirm":
		account := cfclient.GetAccountByLabel(accountLabel)
		if account == nil {
			log.Printf("未找到账号标签: %s", accountLabel)
			telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", accountLabel))
			return
		}

		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(),
				cb.Message.Chat.ID,
				cb.Message.MessageID,
				[][]telegram.Button{{
					{Text: "✅ 已确认，处理中…", CallbackData: "noop"},
				}},
			)
		}

		listID := payload.ListID
		itemID := payload.ItemID
		if itemID == "" {
			telegram.SendTelegramAlert("删除失败：缺少条目 ID。")
			return
		}

		go func() {
			_, err := client.DeleteCustomListItem(context.Background(), *account, listID, itemID)
			if err != nil {
				telegram.SendTelegramAlert(fmt.Sprintf("删除 IP 失败: %v", err))
				return
			}

			telegram.SendTelegramAlert(fmt.Sprintf("✅ 删除 IP 成功（操作人: %s）", user.UserName))

			if cb.Message != nil {
				_ = sender.EditButtons(context.Background(),
					cb.Message.Chat.ID,
					cb.Message.MessageID,
					[][]telegram.Button{{
						{Text: "✅ 已完成", CallbackData: "noop"},
					}},
				)

				_ = sender.ClearButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID)
			}
		}()

	case "iplist_cancel":
		go func() {
			telegram.SendTelegramAlert(fmt.Sprintf("已取消删除（操作人: %s）", user.UserName))
		}()
	case "iplist_select_toggle":
		selection, ok := telegram.ToggleIPListDeleteSelectionItem(payload.SessionID, payload.ItemKey)
		if !ok {
			telegram.SendTelegramAlert("删除选择已过期，请重新执行 /iplist。")
			return
		}
		selection.Page = payload.Page
		renderIPListDeleteSelection(sender, cb, payload.SessionID, selection)

	case "iplist_select_page":
		selection, ok := telegram.SetIPListDeleteSelectionPage(payload.SessionID, payload.Page)
		if !ok {
			telegram.SendTelegramAlert("删除选择已过期，请重新执行 /iplist。")
			return
		}
		renderIPListDeleteSelection(sender, cb, payload.SessionID, selection)

	case "iplist_select_done":
		items, ok := telegram.SelectedIPListDeleteItems(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("删除选择已过期，请重新执行 /iplist。")
			return
		}
		if len(items) == 0 {
			telegram.SendTelegramAlert("请至少选择一条 IP 记录后再确认。")
			return
		}
		page := telegram.BuildIPListDeleteConfirmView(payload.SessionID, items)
		editOrSendPage(sender, cb, page)

	case "iplist_select_confirm":
		items, ok := telegram.SelectedIPListDeleteItems(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("删除选择已过期，请重新执行 /iplist。")
			return
		}
		if len(items) == 0 {
			telegram.SendTelegramAlert("没有已选择的 IP 记录，删除已取消。")
			return
		}
		account := cfclient.GetAccountByLabel(accountLabel)
		if account == nil {
			telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", accountLabel))
			return
		}
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "✅ 已确认，后台删除中…", CallbackData: "noop"},
			}})
		}
		go func() {
			result := telegram.ProcessIPListDeleteItems(context.Background(), client, *account, items)
			telegram.ClearIPListDeleteSelection(payload.SessionID)
			telegram.SendTelegramAlert(result.Summary())
			if cb.Message != nil {
				_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
					{Text: "✅ 删除任务已提交", CallbackData: "noop"},
				}})
			}
		}()

	case "iplist_select_cancel":
		telegram.ClearIPListDeleteSelection(payload.SessionID)
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "已取消", CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(fmt.Sprintf("已取消 IP 删除选择（操作人: %s）", user.UserName))

	case "iplist_add":
		listName := payload.ListName
		if strings.TrimSpace(listName) == "" {
			listName = payload.ListID
		}
		telegram.SetPendingIPListInput(user.ID, telegram.IPListInputRequest{
			AccountLabel: accountLabel,
			ListID:       payload.ListID,
			ListName:     listName,
			Action:       telegram.IPListActionAdd,
		})
		telegram.SendTelegramAlert(fmt.Sprintf("已选择白名单 %s（账号: %s）。\n请直接发送要添加的地址，每行一条，格式：IP 或 CIDR，备注可选。\n示例：\n1.2.3.4 办公网\n2407:cdc0:b010::/112 香港", listName, accountLabel))
	}
}

func beginIPListDeleteSelection(client cfclient.Client, sender telegram.Sender, account config.CF, accountLabel string, onlyListID string) {
	lists, err := client.ListCustomLists(context.Background(), account)
	if err != nil {
		telegram.SendTelegramAlert(fmt.Sprintf("查询账号 %s 白名单失败: %v", accountLabel, err))
		return
	}

	var items []telegram.IPListDeleteItem
	for _, list := range lists {
		if strings.TrimSpace(onlyListID) != "" && list.ID != onlyListID {
			continue
		}

		listItems, err := client.ListCustomListItems(context.Background(), account, list.ID)
		if err != nil {
			telegram.SendTelegramAlert(fmt.Sprintf("读取白名单 %s 失败: %v", list.Name, err))
			return
		}
		for _, item := range listItems {
			if item.ID == "" || item.IP == nil || strings.TrimSpace(*item.IP) == "" {
				continue
			}
			key := list.ID + ":" + item.ID
			items = append(items, telegram.IPListDeleteItem{
				Key:          key,
				AccountLabel: accountLabel,
				ListID:       list.ID,
				ListName:     list.Name,
				ItemID:       item.ID,
				IP:           *item.IP,
				Comment:      item.Comment,
			})
		}
	}

	if len(items) == 0 {
		scope := "全部名单"
		if strings.TrimSpace(onlyListID) != "" {
			scope = onlyListID
		}
		telegram.SendTelegramAlert(fmt.Sprintf("账号 %s 的 %s 暂无可删除 IP 记录。", accountLabel, scope))
		return
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].ListName == items[j].ListName {
			return items[i].IP < items[j].IP
		}
		return items[i].ListName < items[j].ListName
	})

	sessionID := telegram.SetIPListDeleteSelection(telegram.IPListDeleteSelection{
		AccountLabel: accountLabel,
		Items:        items,
		Selected:     make(map[string]bool),
		Page:         0,
	})
	selection, _ := telegram.GetIPListDeleteSelection(sessionID)
	page := telegram.BuildIPListDeleteSelectionView(sessionID, selection)
	if err := sender.SendWithButtons(context.Background(), page.Message, page.Buttons); err != nil {
		log.Printf("发送 IP 删除选择失败: %v", err)
	}
}

func renderIPListDeleteSelection(sender telegram.Sender, cb *tgbotapi.CallbackQuery, sessionID string, selection telegram.IPListDeleteSelection) {
	page := telegram.BuildIPListDeleteSelectionView(sessionID, selection)
	editOrSendPage(sender, cb, page)
}

func editOrSendPage(sender telegram.Sender, cb *tgbotapi.CallbackQuery, page telegram.IPListPage) {
	if cb != nil && cb.Message != nil {
		if err := sender.EditMessageWithButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, page.Message, page.Buttons); err == nil {
			return
		}
	}
	if err := sender.SendWithButtons(context.Background(), page.Message, page.Buttons); err != nil {
		log.Printf("发送交互消息失败: %v", err)
	}
}

func handleGetNSCallback(action string, parts []string, user *tgbotapi.User, cb *tgbotapi.CallbackQuery) {
	if len(parts) < 2 {
		log.Printf("无效的 getns 回调数据: %v", parts)
		return
	}

	token := parts[1]
	payload, ok := telegram.GetGetNSCallbackPayload(token)
	if !ok {
		telegram.SendTelegramAlert("操作已过期，请重新执行 /getns。")
		return
	}

	if action != "getns_select" {
		log.Printf("未知的 getns 回调动作: %s", action)
		return
	}

	accountLabel := payload.AccountLabel
	if cfclient.GetAccountByLabel(accountLabel) == nil {
		log.Printf("未找到账号标签: %s", accountLabel)
		telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", accountLabel))
		return
	}

	telegram.SetPendingGetNSInput(user.ID, telegram.GetNSInputRequest{
		AccountLabel: accountLabel,
	})

	if cb.Message != nil {
		_ = telegram.DefaultSender().EditButtons(context.Background(),
			cb.Message.Chat.ID,
			cb.Message.MessageID,
			[][]telegram.Button{{
				{Text: "已选择 " + accountLabel, CallbackData: "noop"},
			}},
		)
	}

	telegram.SendTelegramAlert(fmt.Sprintf("已选择账号 %s。\n请直接发送要添加的域名，支持多行、空格、逗号或分号分隔。\n示例：\nexample.com\nexample.net", accountLabel))
}

func handleDeleteCommandCallback(action string, parts []string, user *tgbotapi.User, cb *tgbotapi.CallbackQuery) {
	if len(parts) < 2 {
		log.Printf("无效的 delete 回调数据: %v", parts)
		return
	}

	token := parts[1]
	payload, ok := telegram.GetDeleteCallbackPayload(token)
	if !ok {
		telegram.SendTelegramAlert("操作已过期，请重新执行 /delete。")
		return
	}

	sender := telegram.DefaultSender()
	switch action {
	case "deletecmd_select":
		telegram.SetPendingDeleteInput(user.ID, telegram.DeleteInputRequest{})

		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(),
				cb.Message.Chat.ID,
				cb.Message.MessageID,
				[][]telegram.Button{{
					{Text: "已进入批量输入", CallbackData: "noop"},
				}},
			)
		}

		telegram.SendTelegramAlert(telegram.BuildDeleteInputPrompt(""))

	case "deletecmd_confirm":
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(),
				cb.Message.Chat.ID,
				cb.Message.MessageID,
				[][]telegram.Button{{
					{Text: "✅ 已确认，批量处理中…", CallbackData: "noop"},
				}},
			)
		}

		go func() {
			result := telegram.ProcessDeleteBatch(cfclient.NewClient(), config.Cfg.CloudflareAccounts, payload.Domains)
			result.ParseErrors = append(result.ParseErrors, payload.ParseErrors...)
			telegram.SendTelegramAlert(result.Summary())

			if cb.Message != nil {
				_ = sender.EditButtons(context.Background(),
					cb.Message.Chat.ID,
					cb.Message.MessageID,
					[][]telegram.Button{{
						{Text: "✅ 已完成", CallbackData: "noop"},
					}},
				)
				_ = sender.ClearButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID)
			}
		}()

	case "deletecmd_cancel":
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(),
				cb.Message.Chat.ID,
				cb.Message.MessageID,
				[][]telegram.Button{{
					{Text: "❌ 已取消", CallbackData: "noop"},
				}},
			)
		}
		telegram.SendTelegramAlert(fmt.Sprintf("已取消批量删除（操作人: %s）", user.UserName))
	}
}

func handleSetDNSCallback(action string, parts []string, user *tgbotapi.User, cb *tgbotapi.CallbackQuery) {
	if len(parts) < 2 {
		log.Printf("无效的 setdns 回调数据: %v", parts)
		return
	}

	token := parts[1]
	payload, ok := telegram.GetSetDNSCallbackPayload(token)
	if !ok {
		telegram.SendTelegramAlert("操作已过期，请重新执行 /setdns。")
		return
	}

	sender := telegram.DefaultSender()
	switch action {
	case "setdns_account":
		if cfclient.GetAccountByLabel(payload.AccountLabel) == nil {
			telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", payload.AccountLabel))
			return
		}
		telegram.SetPendingSetDNSInput(user.ID, telegram.SetDNSInputRequest{
			AccountLabel: payload.AccountLabel,
			Stage:        telegram.SetDNSInputKeywords,
		})
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "已选择 " + payload.AccountLabel, CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(telegram.BuildSetDNSKeywordPrompt(payload.AccountLabel))

	case "setdns_start", "setdns_continue":
		selection, ok := telegram.GetSetDNSSelection(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("setdns 选择已过期，请重新执行 /setdns。")
			return
		}
		if len(selection.Candidates) == 0 {
			telegram.ClearSetDNSSelection(payload.SessionID)
			telegram.SendTelegramAlert("本次 setdns 没有剩余候选记录，交互已结束。")
			return
		}
		renderSetDNSSelection(sender, cb, payload.SessionID, selection)

	case "setdns_toggle":
		selection, ok := telegram.ToggleSetDNSSelectionItem(payload.SessionID, payload.ItemKey)
		if !ok {
			telegram.SendTelegramAlert("setdns 选择已过期，请重新执行 /setdns。")
			return
		}
		selection.Page = payload.Page
		renderSetDNSSelection(sender, cb, payload.SessionID, selection)

	case "setdns_page":
		selection, ok := telegram.SetSetDNSSelectionPage(payload.SessionID, payload.Page)
		if !ok {
			telegram.SendTelegramAlert("setdns 选择已过期，请重新执行 /setdns。")
			return
		}
		renderSetDNSSelection(sender, cb, payload.SessionID, selection)

	case "setdns_done":
		targets, ok := telegram.SelectedSetDNSRecordTargets(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("setdns 选择已过期，请重新执行 /setdns。")
			return
		}
		if len(targets) == 0 {
			telegram.SendTelegramAlert("请至少选择一条解析记录后再确认。")
			return
		}
		page := telegram.BuildSetDNSConfirmView(payload.SessionID, targets)
		editOrSendPage(sender, cb, page)

	case "setdns_apply":
		targets, ok := telegram.SelectedSetDNSRecordTargets(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("setdns 选择已过期，请重新执行 /setdns。")
			return
		}
		if len(targets) == 0 {
			telegram.SendTelegramAlert("没有已选择的解析记录，请返回选择。")
			return
		}
		telegram.SetPendingSetDNSInput(user.ID, telegram.SetDNSInputRequest{
			AccountLabel: payload.AccountLabel,
			SessionID:    payload.SessionID,
			Stage:        telegram.SetDNSInputNewTarget,
		})
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: fmt.Sprintf("已确认 %d 条，等待新目标", len(targets)), CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(telegram.BuildSetDNSNewTargetPrompt(payload.AccountLabel, len(targets)))

	case "setdns_finish", "setdns_cancel":
		telegram.ClearSetDNSSelection(payload.SessionID)
		telegram.ClearPendingSetDNSInput(user.ID)
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "已结束", CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(fmt.Sprintf("setdns 交互已结束（操作人: %s）", user.UserName))
	}
}

func renderSetDNSSelection(sender telegram.Sender, cb *tgbotapi.CallbackQuery, sessionID string, selection telegram.SetDNSSelection) {
	page := telegram.BuildSetDNSSelectionView(sessionID, selection)
	editOrSendPage(sender, cb, page)
}

func renderOriginSSLDomainSelection(sender telegram.Sender, cb *tgbotapi.CallbackQuery, sessionID string, selection telegram.OriginSSLDomainSelection) {
	page := telegram.BuildOriginSSLDomainSelectionView(sessionID, selection)
	editOrSendPage(sender, cb, page)
}

func handleOriginSSLCallback(action string, parts []string, user *tgbotapi.User, cb *tgbotapi.CallbackQuery) {
	if len(parts) < 2 {
		log.Printf("无效的 ssl 回调数据: %v", parts)
		return
	}

	token := parts[1]
	payload, ok := telegram.GetOriginSSLCallbackPayload(token)
	if !ok {
		telegram.SendTelegramAlert("操作已过期，请重新执行 /ssl。")
		return
	}

	sender := telegram.DefaultSender()
	switch action {
	case "ssl_account":
		account := cfclient.GetAccountByLabel(payload.AccountLabel)
		if account == nil {
			telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", payload.AccountLabel))
			return
		}
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "已选择 " + payload.AccountLabel, CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(fmt.Sprintf("正在读取账号 %s 下所有域名，请稍候。", payload.AccountLabel))
		go func() {
			if err := telegram.BeginOriginSSLDomainSelection(context.Background(), cfclient.NewClient(), sender, *account); err != nil {
				telegram.SendTelegramAlert(fmt.Sprintf("读取 /ssl 域名列表失败: %v", err))
			}
		}()

	case "ssl_continue_domains":
		account := cfclient.GetAccountByLabel(payload.AccountLabel)
		if account == nil {
			telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", payload.AccountLabel))
			return
		}
		telegram.ClearOriginSSLDomainSelection(payload.SessionID)
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "正在重新读取域名", CallbackData: "noop"},
			}})
		}
		go func() {
			if err := telegram.BeginOriginSSLDomainSelection(context.Background(), cfclient.NewClient(), sender, *account); err != nil {
				telegram.SendTelegramAlert(fmt.Sprintf("读取 /ssl 域名列表失败: %v", err))
			}
		}()

	case "ssl_domain_toggle":
		selection, ok := telegram.ToggleOriginSSLDomainSelectionItem(payload.SessionID, payload.ItemKey)
		if !ok {
			telegram.SendTelegramAlert("/ssl 域名选择已过期，请重新执行 /ssl。")
			return
		}
		selection.Page = payload.Page
		renderOriginSSLDomainSelection(sender, cb, payload.SessionID, selection)

	case "ssl_domain_page":
		selection, ok := telegram.SetOriginSSLDomainSelectionPage(payload.SessionID, payload.Page)
		if !ok {
			telegram.SendTelegramAlert("/ssl 域名选择已过期，请重新执行 /ssl。")
			return
		}
		renderOriginSSLDomainSelection(sender, cb, payload.SessionID, selection)

	case "ssl_domain_done":
		items, ok := telegram.SelectedOriginSSLDomainItems(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl 域名选择已过期，请重新执行 /ssl。")
			return
		}
		if len(items) == 0 {
			telegram.SendTelegramAlert("请至少选择一个域名后再确认。")
			return
		}
		selection, ok := telegram.GetOriginSSLDomainSelection(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl 域名选择已过期，请重新执行 /ssl。")
			return
		}
		if len(config.Cfg.AWSTargets) > 0 {
			page := telegram.BuildOriginSSLAWSSelectionView(payload.SessionID, selection)
			editOrSendPage(sender, cb, page)
		} else {
			telegram.SetPendingOriginSSLInput(user.ID, telegram.OriginSSLInputRequest{
				AccountLabel:    payload.AccountLabel,
				SessionID:       payload.SessionID,
				Stage:           telegram.OriginSSLInputBlockCountries,
				SelectedDomains: telegram.OriginSSLDomainNames(items),
			})
			if cb.Message != nil {
				_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
					{Text: "等待国家/地区拦截输入", CallbackData: "noop"},
				}})
			}
			telegram.SendTelegramAlert(telegram.BuildOriginSSLBlockCountriesPrompt(telegram.OriginSSLInputRequest{SessionID: payload.SessionID}, ""))
		}

	case "ssl_domain_aws_toggle":
		selection, ok := telegram.ToggleOriginSSLDomainAWSAlias(payload.SessionID, payload.Value)
		if !ok {
			telegram.SendTelegramAlert("/ssl AWS 选择已过期，请重新执行 /ssl。")
			return
		}
		page := telegram.BuildOriginSSLAWSSelectionView(payload.SessionID, selection)
		editOrSendPage(sender, cb, page)

	case "ssl_domain_aws_done":
		items, ok := telegram.SelectedOriginSSLDomainItems(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl 域名选择已过期，请重新执行 /ssl。")
			return
		}
		if len(items) == 0 {
			telegram.SendTelegramAlert("请至少选择一个域名后再确认。")
			return
		}
		selection, _ := telegram.GetOriginSSLDomainSelection(payload.SessionID)
		telegram.SetPendingOriginSSLInput(user.ID, telegram.OriginSSLInputRequest{
			AccountLabel:    payload.AccountLabel,
			SessionID:       payload.SessionID,
			Stage:           telegram.OriginSSLInputBlockCountries,
			SelectedDomains: telegram.OriginSSLDomainNames(items),
			AWSAliases:      sortedSelectedKeys(selection.AWSAliases),
		})
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "等待国家/地区拦截输入", CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(telegram.BuildOriginSSLBlockCountriesPrompt(telegram.OriginSSLInputRequest{SessionID: payload.SessionID}, ""))

	case "ssl_domain_ssl_confirm":
		items, ok := telegram.SelectedOriginSSLDomainItems(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl 域名选择已过期，请重新执行 /ssl。")
			return
		}
		if len(items) == 0 {
			telegram.SendTelegramAlert("没有已选择域名，无法创建 SSL。")
			return
		}
		account := cfclient.GetAccountByLabel(payload.AccountLabel)
		if account == nil {
			telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", payload.AccountLabel))
			return
		}
		selection, ok := telegram.GetOriginSSLDomainSelection(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl 域名选择已过期，请重新执行 /ssl。")
			return
		}
		awsAliases := sortedSelectedKeys(selection.AWSAliases)
		blockCountries := append([]string(nil), selection.BlockCountries...)
		go func() {
			result := telegram.ProcessOriginSSLDomainItems(context.Background(), cfclient.NewClient(), *account, items, awsAliases, blockCountries)
			telegram.SendTelegramAlert(result.Summary())
			telegram.SendOriginSSLInteractiveARNOutputs(sender, result)
		}()
		page := telegram.BuildOriginSSLDNSQuestionView(payload.SessionID, payload.AccountLabel, len(items))
		editOrSendPage(sender, cb, page)

	case "ssl_dns_yes":
		items, ok := telegram.SelectedOriginSSLDomainItems(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl 域名选择已过期，请重新执行 /ssl。")
			return
		}
		if len(items) == 0 {
			telegram.SendTelegramAlert("请至少选择一个域名后再创建解析。")
			return
		}
		telegram.SetPendingOriginSSLInput(user.ID, telegram.OriginSSLInputRequest{
			AccountLabel:     payload.AccountLabel,
			SessionID:        payload.SessionID,
			Stage:            telegram.OriginSSLInputDNSTarget,
			SelectedDomains:  telegram.OriginSSLDomainNames(items),
		})
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "等待解析目标输入", CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(telegram.BuildOriginSSLDNSTargetPrompt(payload.AccountLabel, len(items), ""))

	case "ssl_dns_proxy":
		items, ok := telegram.SelectedOriginSSLDomainItems(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl 域名选择已过期，请重新执行 /ssl。")
			return
		}
		if len(items) == 0 {
			telegram.SendTelegramAlert("请至少选择一个域名后再创建解析。")
			return
		}
		req := telegram.OriginSSLInputRequest{
			AccountLabel:     payload.AccountLabel,
			SessionID:        payload.SessionID,
			Stage:            telegram.OriginSSLInputDNSRecords,
			DNSTarget:        payload.DNSTarget,
			DNSRecordType:    payload.DNSRecordType,
			Proxied:          payload.Proxied,
			SelectedDomains:  telegram.OriginSSLDomainNames(items),
		}
		telegram.SetPendingOriginSSLInput(user.ID, req)
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "等待解析域名输入", CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(telegram.BuildOriginSSLDNSRecordsPrompt(req, nil))

	case "ssl_dns_create_confirm":
		plan, ok := telegram.GetOriginSSLDNSPlan(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl DNS 创建计划已过期，请重新执行 /ssl。")
			return
		}
		account := cfclient.GetAccountByLabel(plan.AccountLabel)
		if account == nil {
			telegram.SendTelegramAlert(fmt.Sprintf("操作失败：未找到账号 %s", plan.AccountLabel))
			return
		}
		go func() {
			result := telegram.ProcessOriginSSLDNSPlan(context.Background(), cfclient.NewClient(), *account, plan)
			telegram.ClearOriginSSLDNSPlan(payload.SessionID)
			telegram.SendTelegramAlert(result.Summary())
		}()
		page := telegram.BuildOriginSSLContinueView(plan.SessionID, plan.AccountLabel)
		editOrSendPage(sender, cb, page)

	case "ssl_dns_create_cancel":
		plan, ok := telegram.GetOriginSSLDNSPlan(payload.SessionID)
		telegram.ClearOriginSSLDNSPlan(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl DNS 创建计划已过期。")
			return
		}
		page := telegram.BuildOriginSSLContinueView(plan.SessionID, plan.AccountLabel)
		editOrSendPage(sender, cb, page)

	case "ssl_dns_name_toggle":
		selection, ok := telegram.ToggleOriginSSLDNSNameSelectionDomain(payload.SessionID, payload.Value)
		if !ok {
			telegram.SendTelegramAlert("/ssl 解析名选择已过期，请重新执行 /ssl。")
			return
		}
		selection.Page = payload.Page
		page := telegram.BuildOriginSSLDNSNameDomainSelectionView(payload.SessionID, selection)
		editOrSendPage(sender, cb, page)

	case "ssl_dns_name_page":
		selection, ok := telegram.SetOriginSSLDNSNameSelectionPage(payload.SessionID, payload.Page)
		if !ok {
			telegram.SendTelegramAlert("/ssl 解析名选择已过期，请重新执行 /ssl。")
			return
		}
		page := telegram.BuildOriginSSLDNSNameDomainSelectionView(payload.SessionID, selection)
		editOrSendPage(sender, cb, page)

	case "ssl_dns_name_all":
		selection, ok := telegram.SelectAllOriginSSLDNSNameDomains(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl 解析名选择已过期，请重新执行 /ssl。")
			return
		}
		newPlan := telegram.BuildOriginSSLDNSNamePlan(selection.AccountLabel, selection.OriginSessionID, selection.Domains, selection.Names, selection.DNSRecordType, selection.DNSTarget, selection.Proxied)
		combinedRecords := append([]telegram.OriginSSLDNSRecordPlan(nil), selection.PendingDNSRecords...)
		combinedRecords = append(combinedRecords, newPlan.Records...)
		telegram.ClearOriginSSLDNSNameSelection(payload.SessionID)
		plan := telegram.OriginSSLDNSPlan{
			AccountLabel: selection.AccountLabel,
			SessionID:    selection.OriginSessionID,
			Records:      combinedRecords,
		}
		planID := telegram.SetOriginSSLDNSPlan(plan)
		page := telegram.BuildOriginSSLDNSPlanConfirmView(planID, plan)
		editOrSendPage(sender, cb, page)

	case "ssl_dns_name_done":
		selection, ok := telegram.GetOriginSSLDNSNameSelection(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl 解析名选择已过期，请重新执行 /ssl。")
			return
		}
		selectedDomains, ok := telegram.SelectedOriginSSLDNSNameDomains(payload.SessionID)
		if !ok {
			telegram.SendTelegramAlert("/ssl 解析名选择已过期，请重新执行 /ssl。")
			return
		}
		if len(selectedDomains) == 0 {
			telegram.SendTelegramAlert("请至少选择一个域名后再确认。")
			return
		}
		newPlan := telegram.BuildOriginSSLDNSNamePlan(selection.AccountLabel, selection.OriginSessionID, selectedDomains, selection.Names, selection.DNSRecordType, selection.DNSTarget, selection.Proxied)
		combinedRecords := append([]telegram.OriginSSLDNSRecordPlan(nil), selection.PendingDNSRecords...)
		combinedRecords = append(combinedRecords, newPlan.Records...)
		remaining := remainingStringItems(selection.Domains, selectedDomains)
		telegram.ClearOriginSSLDNSNameSelection(payload.SessionID)
		if len(remaining) == 0 {
			plan := telegram.OriginSSLDNSPlan{
				AccountLabel: selection.AccountLabel,
				SessionID:    selection.OriginSessionID,
				Records:      combinedRecords,
			}
			planID := telegram.SetOriginSSLDNSPlan(plan)
			page := telegram.BuildOriginSSLDNSPlanConfirmView(planID, plan)
			editOrSendPage(sender, cb, page)
			return
		}
		req := telegram.OriginSSLInputRequest{
			AccountLabel:      selection.AccountLabel,
			SessionID:         selection.OriginSessionID,
			Stage:             telegram.OriginSSLInputDNSRecords,
			DNSTarget:         selection.DNSTarget,
			DNSRecordType:     selection.DNSRecordType,
			Proxied:           selection.Proxied,
			SelectedDomains:   remaining,
			PendingDNSRecords: combinedRecords,
		}
		telegram.SetPendingOriginSSLInput(user.ID, req)
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "等待剩余域名解析输入", CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(telegram.BuildOriginSSLDNSRecordsPrompt(req, nil))

	case "ssl_dns_name_cancel":
		selection, ok := telegram.GetOriginSSLDNSNameSelection(payload.SessionID)
		telegram.ClearOriginSSLDNSNameSelection(payload.SessionID)
		if ok {
			telegram.ClearOriginSSLDomainSelection(selection.OriginSessionID)
		}
		telegram.ClearPendingOriginSSLInput(user.ID)
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "已结束", CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(fmt.Sprintf("/ssl 交互已结束（操作人: %s）", user.UserName))

	case "ssl_finish":
		telegram.ClearOriginSSLDomainSelection(payload.SessionID)
		telegram.ClearPendingOriginSSLInput(user.ID)
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "已结束", CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(fmt.Sprintf("/ssl 交互已结束（操作人: %s）", user.UserName))

	case "ssl_domain_cancel":
		telegram.ClearOriginSSLDomainSelection(payload.SessionID)
		telegram.ClearPendingOriginSSLInput(user.ID)
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: "已取消", CallbackData: "noop"},
			}})
		}
		telegram.SendTelegramAlert(fmt.Sprintf("已取消 /ssl 域名选择（操作人: %s）", user.UserName))

	case "ssl_aws_toggle":
		selection := telegram.ToggleOriginSSLAlias(user.ID, payload.Value)
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, telegram.BuildOriginSSLAWSButtons(selection))
		}

	case "ssl_aws_done":
		selection := telegram.GetOriginSSLSelection(user.ID)
		req := telegram.OriginSSLInputRequest{
			AWSAliases: sortedSelectedKeys(selection.AWSAliases),
		}
		telegram.SetPendingOriginSSLInput(user.ID, req)

		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: fmt.Sprintf("已选择 %d 个 AWS 目标", len(req.AWSAliases)), CallbackData: "noop"},
			}})
		}

		telegram.SendTelegramAlert(telegram.BuildOriginSSLInputPrompt(req))
	}
}

func sortedSelectedKeys(items map[string]bool) []string {
	out := make([]string, 0, len(items))
	for key, selected := range items {
		if !selected || strings.TrimSpace(key) == "" {
			continue
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func remainingStringItems(all []string, selected []string) []string {
	selectedSet := make(map[string]struct{}, len(selected))
	for _, item := range selected {
		item = strings.TrimSpace(strings.ToLower(item))
		if item == "" {
			continue
		}
		selectedSet[item] = struct{}{}
	}
	var out []string
	for _, item := range all {
		normalized := strings.TrimSpace(strings.ToLower(item))
		if normalized == "" {
			continue
		}
		if _, ok := selectedSet[normalized]; ok {
			continue
		}
		out = append(out, normalized)
	}
	return out
}
