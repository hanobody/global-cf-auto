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
			sb.WriteString(fmt.Sprintf("【IP 白名单】\n账号: %s\n请选择要操作的名单：\n", accountLabel))

			var buttons [][]telegram.Button
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

	case "iplist_delete":
		if payload.ItemID == "" {
			listName := payload.ListName
			if strings.TrimSpace(listName) == "" {
				listName = payload.ListID
			}
			telegram.SetPendingIPListInput(user.ID, telegram.IPListInputRequest{
				AccountLabel: accountLabel,
				ListID:       payload.ListID,
				ListName:     listName,
				Action:       telegram.IPListActionDelete,
			})
			telegram.SendTelegramAlert(fmt.Sprintf("已选择白名单 %s（账号: %s）。\n请直接发送要删除的地址，每行一条，只需填写 IP 或 CIDR。\n示例：\n1.2.3.4\n2407:cdc0:b010::/112", listName, accountLabel))
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
	case "ssl_cf_toggle":
		selection := telegram.ToggleOriginSSLAccount(user.ID, payload.Value)
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, telegram.BuildOriginSSLAccountButtons(config.Cfg.CloudflareAccounts, selection))
		}

	case "ssl_cf_next":
		selection := telegram.GetOriginSSLSelection(user.ID)
		if len(selection.AccountLabels) == 0 {
			telegram.SendTelegramAlert("请至少选择一个 Cloudflare 账号。")
			return
		}

		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, [][]telegram.Button{{
				{Text: fmt.Sprintf("已选择 %d 个 Cloudflare 账号", len(selection.AccountLabels)), CallbackData: "noop"},
			}})
		}

		if err := sender.SendWithButtons(context.Background(), telegram.OriginSSLTargetPromptText(), telegram.BuildOriginSSLAWSButtons(selection)); err != nil {
			log.Printf("发送 /ssl AWS 目标选择失败: %v", err)
		}

	case "ssl_aws_toggle":
		selection := telegram.ToggleOriginSSLAlias(user.ID, payload.Value)
		if cb.Message != nil {
			_ = sender.EditButtons(context.Background(), cb.Message.Chat.ID, cb.Message.MessageID, telegram.BuildOriginSSLAWSButtons(selection))
		}

	case "ssl_aws_done":
		selection := telegram.GetOriginSSLSelection(user.ID)
		if len(selection.AccountLabels) == 0 {
			telegram.SendTelegramAlert("请至少选择一个 Cloudflare 账号。")
			return
		}

		req := telegram.OriginSSLInputRequest{
			AccountLabels: sortedSelectedKeys(selection.AccountLabels),
			AWSAliases:    sortedSelectedKeys(selection.AWSAliases),
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
