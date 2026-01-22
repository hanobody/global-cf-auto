package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"DomainC/cfclient"
)

func (h *CommandHandler) handleCLSCommand(args []string) {
	if len(args) < 1 {
		h.sendText("用法: /cls <domain.com | sub.domain.com | URL>")
		return
	}

	raw := strings.TrimSpace(args[0])
	q, err := extractDomainOrHost(raw)
	if err != nil {
		h.sendText(fmt.Sprintf("参数不合法：%v\n用法: /cls <domain.com | sub.domain.com | URL>", err))
		return
	}

	account, zone, err := h.findZone(q)
	if err != nil {
		if errors.Is(err, cfclient.ErrZoneNotFound) {
			h.sendText(fmt.Sprintf("域名 %s 不属于任何 Cloudflare 账号。", q))
			return
		}
		h.sendText(fmt.Sprintf("查询域名失败: %v", err))
		return
	}

	if err := h.CFClient.PurgeZoneCache(context.Background(), *account, zone.ID); err != nil {
		h.sendText(fmt.Sprintf("清理缓存失败: %v", err))
		return
	}

	operator := formatOperator(h.operator)
	h.sendText(fmt.Sprintf("✅ 已清理缓存：%s (账号: %s，操作人: %s)", zone.Name, account.Label, operator))
}
