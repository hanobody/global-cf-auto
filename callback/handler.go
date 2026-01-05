package callback

import (
	"context"
	"fmt"
	"log"
	"strings"

	"DomainC/cfclient"
	"DomainC/telegram"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// HandleCallback 处理来自 Notifier 的内联按钮回调
// callbackData 格式：action|accountLabel|domain|[paused yes/no]
func HandleCallback(callbackData string, user *tgbotapi.User) {
	parts := strings.Split(callbackData, "|")
	if len(parts) < 3 {
		log.Printf("无效的回调数据: %s", callbackData)
		return
	}

	action := parts[0]
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