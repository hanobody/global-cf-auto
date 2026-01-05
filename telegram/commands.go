package telegram

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	case "csv":
		go h.handleCSVCommand(args)
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
func (h *CommandHandler) handleCSVCommand(args []string) {
	// 1) 用户只输入 /csv：提示可选账号
	if len(args) < 1 {
		h.sendText(h.csvPromptText())
		return
	}

	selector := strings.TrimSpace(args[0])
	if selector == "" {
		h.sendText(h.csvPromptText())
		return
	}

	// 2) 选择账号
	var targets []config.CF
	if strings.EqualFold(selector, "all") {
		targets = append(targets, h.Accounts...)
		if len(targets) == 0 {
			h.sendText("未配置可用的 Cloudflare 账号，无法导出。")
			return
		}
	} else {
		acc := h.getAccountByLabel(selector)
		if acc == nil {
			h.sendText(fmt.Sprintf("未找到账号 %s。\n\n%s", selector, h.csvPromptText()))
			return
		}
		targets = []config.CF{*acc}
	}

	// 3) 拉取数据并生成 CSV
	ctx := context.Background()
	csvBytes, filename, err := h.buildDNSExportCSV(ctx, targets)
	if err != nil {
		h.sendText(fmt.Sprintf("导出失败: %v", err))
		return
	}

	// 4) 写入临时文件并发送回群
	tmpFile, err := os.CreateTemp("", "dns-export-*.csv")
	if err != nil {
		h.sendText(fmt.Sprintf("创建临时文件失败: %v", err))
		return
	}
	tmpPath := tmpFile.Name()

	// 用完即删（如果你希望保留，去掉 os.Remove 这一行）
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(csvBytes); err != nil {
		h.sendText(fmt.Sprintf("写入临时文件失败: %v", err))
		return
	}
	_ = tmpFile.Sync()

	finalPath := filepath.Join(os.TempDir(), filename)
	_ = os.Rename(tmpPath, finalPath)
	tmpPath = finalPath

	if err := h.Sender.SendDocumentPath(context.Background(), tmpPath, "📦 Cloudflare DNS 导出"); err != nil {
		h.sendText(fmt.Sprintf("发送导出文件失败: %v", err))
		return
	}

	h.sendText(fmt.Sprintf("✅ 导出完成：%s", filename))

}

// 提示文本：可导出的账号 + 示例
func (h *CommandHandler) csvPromptText() string {
	if len(h.Accounts) == 0 {
		return "未配置可用的 Cloudflare 账号，无法导出。"
	}

	var sb strings.Builder
	sb.WriteString("您想导出哪个账号？\n目前可以导出的账号：\n")
	for _, a := range h.Accounts {
		if strings.TrimSpace(a.Label) == "" {
			continue
		}
		sb.WriteString("- " + a.Label + "\n")
	}
	sb.WriteString("- all\n\n请输入：\n/csv all\n或者：\n/csv AAAAA")
	return sb.String()
}

// 按 Label 查账号（忽略大小写）
func (h *CommandHandler) getAccountByLabel(label string) *config.CF {
	for i := range h.Accounts {
		if strings.EqualFold(strings.TrimSpace(h.Accounts[i].Label), strings.TrimSpace(label)) {
			return &h.Accounts[i]
		}
	}
	return nil
}

func (h *CommandHandler) buildDNSExportCSV(ctx context.Context, accounts []config.CF) ([]byte, string, error) {
	// 文件名：dns-export-YYYYMMDD-HHMMSS.csv
	filename := fmt.Sprintf("dns-export-%s.csv", time.Now().Format("20060102-150405"))

	buf := &bytes.Buffer{}
	w := csv.NewWriter(buf)
	w.UseCRLF = false

	// Header
	if err := w.Write([]string{
		"所属账户",
		"主域名",
		"子域名",
		"解析类型",
		"解析地址",
		"是否代理",
		"Zone状态",
		"是否暂停",
	}); err != nil {
		return nil, "", err
	}

	for _, acc := range accounts {
		zones, err := h.CFClient.ListZones(ctx, acc)
		if err != nil {
			return nil, "", fmt.Errorf("列出账号 %s 的域名失败: %w", acc.Label, err)
		}

		for _, z := range zones {
			zonePaused := "否"
			if z.Paused {
				zonePaused = "是"
			}

			records, err := h.CFClient.ListDNSRecords(ctx, acc, z.Name)
			if err != nil {
				return nil, "", fmt.Errorf("获取 %s(%s) DNS 失败: %w", z.Name, acc.Label, err)
			}

			// 没有记录也写一行（保留 zone 维度信息）
			if len(records) == 0 {
				_ = w.Write([]string{
					acc.Label,
					z.Name,
					"",
					"",
					"",
					"",
					z.Status,
					zonePaused,
				})
				continue
			}

			for _, r := range records {
				proxied := "否"
				if r.Proxied != nil && *r.Proxied {
					proxied = "是"
				}

				subDomain := r.Name
				if subDomain == "@" || subDomain == z.Name {
					subDomain = z.Name
				}

				if err := w.Write([]string{
					acc.Label,  // 所属账户
					z.Name,     // 主域名
					subDomain,  // 子域名（完整 FQDN）
					r.Type,     // 解析类型
					r.Content,  // 解析地址
					proxied,    // 是否代理
					z.Status,   // Zone状态
					zonePaused, // 是否暂停
				}); err != nil {
					return nil, "", err
				}
			}
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, "", err
	}

	return buf.Bytes(), filename, nil
}
