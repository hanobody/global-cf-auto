package telegram

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strconv" // 用于 TTL 转换
	"strings"

	"DomainC/cfclient"
	"DomainC/config"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// CommandHandler 处理群组中的命令消息
// 需要传入 Cloudflare 客户端与账号列表。
type CommandHandler struct {
	CFClient cfclient.Client
	Accounts []config.CF
	Sender   Sender
	ChatID   int64
	operator *tgbotapi.User
}

func NewCommandHandler(cf cfclient.Client, sender Sender, accounts []config.CF, chatID int64) *CommandHandler {
	if cf == nil {
		cf = cfclient.NewClient()
	}
	if sender == nil {
		sender = DefaultSender()
	}
	return &CommandHandler{CFClient: cf, Accounts: accounts, Sender: sender, ChatID: chatID}
}

// HandleMessage 分发 Telegram 文本命令
func (h *CommandHandler) HandleMessage(msg *tgbotapi.Message) {
	if msg == nil || msg.Text == "" {
		return
	}
	if h.ChatID != 0 && msg.Chat != nil && msg.Chat.ID != h.ChatID {
		return
	}
	if !msg.IsCommand() {
		return
	}
	h.operator = msg.From
	args := strings.Fields(msg.CommandArguments())
	switch msg.Command() {
	case "dns":
		go h.handleDNSCommand(strings.ToLower(msg.Command()), args)
	case "getns":
		go h.handleGetNSCommand(args)
	case "status":
		go h.handleStatusCommand(args)
	case "delete":
		go h.handleDeleteCommand(args)
	case "setdns":
		go h.handleSetDNSCommand(args)
	}
}

func (h *CommandHandler) handleDNSCommand(_ string, args []string) {
	if len(args) < 1 {
		h.sendText("用法: /dns <domain.com>")
		return
	}
	domain := strings.ToLower(args[0])

	account, zone, err := h.findZone(domain)
	if err != nil {
		if errors.Is(err, cfclient.ErrZoneNotFound) {
			h.sendText(fmt.Sprintf("域名 %s 不属于任何 Cloudflare 账号。", domain))
			return
		}
		h.sendText(fmt.Sprintf("查询域名失败: %v", err))
		return
	}

	records, err := h.CFClient.ListDNSRecords(context.Background(), *account, zone.Name)
	if err != nil {
		h.sendText(fmt.Sprintf("获取 %s 解析失败: %v", domain, err))
		return
	}

	if len(records) == 0 {
		h.sendText(fmt.Sprintf("域名 %s 没有 DNS 记录。", domain))
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("域名 %s 的 DNS 记录（账号: %s）:\n", domain, account.Label))
	for _, r := range records {
		proxied := "否"
		if *r.Proxied {
			proxied = "是"
		}
		sb.WriteString(fmt.Sprintf("- %s %s → %s (代理: %s, TTL: %d)\n", r.Type, r.Name, r.Content, proxied, r.TTL))
	}
	h.sendText(sb.String())
}

func (h *CommandHandler) handleGetNSCommand(args []string) {
	if len(args) < 1 {
		h.sendText("用法: /getns <domain.com>")
		return
	}
	domain := strings.ToLower(args[0])

	if account, zone, err := h.findZone(domain); err == nil {
		h.sendText(fmt.Sprintf("域名 %s 已在账号 %s 下，NS: %s", zone.Name, account.Label, strings.Join(zone.NameServers, ", ")))
		return
	}

	account := h.defaultAccount()
	if account == nil {
		h.sendText("未配置可用的 Cloudflare 账号，无法添加域名。")
		return
	}

	zone, err := h.CFClient.CreateZone(context.Background(), *account, domain)
	if err != nil {
		h.sendText(fmt.Sprintf("添加域名失败: %v,%s---%s", err, domain, account.Label))
		return
	}

	h.sendText(fmt.Sprintf("已将 %s 添加到账号 %s，NS 请设置为: %s", zone.Name, account.Label, strings.Join(zone.NameServers, ", ")))
}

func (h *CommandHandler) handleStatusCommand(args []string) {
	if len(args) < 1 {
		h.sendText("用法: /status <domain.com>")
		return
	}
	domain := strings.ToLower(args[0])

	account, zone, err := h.findZone(domain)
	if err != nil {
		if errors.Is(err, cfclient.ErrZoneNotFound) {
			h.sendText(fmt.Sprintf("域名 %s 不属于任何 Cloudflare 账号。", domain))
			return
		}
		h.sendText(fmt.Sprintf("查询状态失败: %v", err))
		return
	}

	operator := formatOperator(h.operator)
	h.sendText(fmt.Sprintf("域名 %s 状态: %s (暂停: %v)\n账号: %s\n操作人: %s", zone.Name, zone.Status, zone.Paused, account.Label, operator))
}

func (h *CommandHandler) handleDeleteCommand(args []string) {
	if len(args) < 1 {
		h.sendText("用法: /delete <domain.com>")
		return
	}
	domain := strings.ToLower(args[0])

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
		"⚠️【删除二次确认】\n操作人: %s\n域名: %s\n账号: %s\n\n此操作不可逆，确认要删除该域名（Cloudflare Zone）吗？", op, domain, account.Label,
	)

	buttons := [][]Button{{
		{Text: "✅ 确认删除", CallbackData: fmt.Sprintf("delete_confirm|%s|%s", account.Label, domain)},
		{Text: "❌ 取消", CallbackData: fmt.Sprintf("delete_cancel|%s|%s", account.Label, domain)},
	}}
	SendTelegramAlertWithButtons(confirmMsg, buttons)
}

func (h *CommandHandler) handleSetDNSCommand(args []string) {
	if len(args) < 4 {
		h.sendText("用法: /setdns <domain.com> <type> <name> <content> [proxied:yes/no] [ttl:seconds]\n示例: /setdns example.com A @ 192.0.2.1 yes 3600")
		return
	}
	domain := strings.ToLower(args[0])
	params := cfclient.DNSRecordParams{ // 直接使用 cfclient 包中的类型
		Type:    strings.ToUpper(args[1]),
		Name:    args[2],
		Content: args[3],
		Proxied: false,
		TTL:     1, // Cloudflare 自动 TTL
	}
	if len(args) >= 5 {
		params.Proxied = strings.ToLower(args[4]) == "yes" || strings.ToLower(args[4]) == "true"
	}
	if len(args) >= 6 {
		if ttl, err := strconv.Atoi(args[5]); err == nil && ttl > 0 {
			params.TTL = ttl
		}
	}

	account, _, err := h.findZone(domain)
	if err != nil {
		h.sendText(fmt.Sprintf("域名 %s 不属于任何 Cloudflare 账号。", domain))
		return
	}

	record, err := h.CFClient.UpsertDNSRecord(context.Background(), *account, domain, params)
	if err != nil {
		h.sendText(fmt.Sprintf("设置 DNS 记录失败: %v", err))
		return
	}

	proxyStatus := "否"
	if record.Proxied != nil && *record.Proxied {
		proxyStatus = "是"
	}
	h.sendText(fmt.Sprintf("已在账号 %s 设置记录: %s %s → %s (代理:%s)", account.Label, record.Type, record.Name, record.Content, proxyStatus))
}

func (h *CommandHandler) findZone(domain string) (*config.CF, cfclient.ZoneDetail, error) {
	var lastErr error
	for i := range h.Accounts {
		acc := h.Accounts[i]
		zone, err := h.CFClient.GetZoneDetails(context.Background(), acc, domain)
		if err != nil {
			if errors.Is(err, cfclient.ErrZoneNotFound) {
				lastErr = err
				continue
			}
			return nil, cfclient.ZoneDetail{}, err
		}
		return &acc, zone, nil
	}
	if lastErr == nil {
		lastErr = cfclient.ErrZoneNotFound
	}
	return nil, cfclient.ZoneDetail{}, lastErr
}

func (h *CommandHandler) deleteZone(domain string) (*config.CF, error) {
	var lastErr error
	for i := range h.Accounts {
		acc := h.Accounts[i]
		err := h.CFClient.DeleteDomain(context.Background(), acc, domain)
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

// defaultAccount 随机返回一个 Cloudflare 账号配置
func (h *CommandHandler) defaultAccount() *config.CF {
	if len(h.Accounts) == 0 {
		return nil
	}
	idx := rand.Intn(len(h.Accounts))
	return &h.Accounts[idx]
}

func (h *CommandHandler) sendText(msg string) {
	_ = h.Sender.Send(context.Background(), msg)
}

func deriveDomainFromName(name string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return ""
}

func formatOperator(u *tgbotapi.User) string {
	if u == nil {
		return "unknown"
	}
	if u.UserName != "" {
		return "@" + u.UserName
	}
	name := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if name != "" {
		return name
	}
	return fmt.Sprintf("id:%d", u.ID)
}
