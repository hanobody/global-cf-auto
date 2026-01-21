package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"DomainC/cfclient"
)

func (h *CommandHandler) handleDelDNSCommand(args []string) {
	if len(args) < 1 {
		h.sendText("用法: /deldns <sub.domain.com | domain.com | URL>")
		return
	}

	raw := strings.TrimSpace(args[0])
	q, err := extractDomainOrHost(raw)
	if err != nil {
		h.sendText(fmt.Sprintf("参数不合法：%v\n用法: /deldns <sub.domain.com | domain.com | URL>", err))
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

	deleted, err := h.CFClient.DeleteDNSRecord(context.Background(), *account, zone.Name, q)
	if err != nil {
		h.sendText(fmt.Sprintf("删除解析记录失败: %v", err))
		return
	}

	if deleted == 0 {
		h.sendText(fmt.Sprintf("未找到 %s 的解析记录（账号: %s，Zone: %s）。", q, account.Label, zone.Name))
		return
	}

	operator := formatOperator(h.operator)
	h.sendText(fmt.Sprintf("✅ 已删除 %d 条解析记录：%s (账号: %s，Zone: %s，操作人: %s)", deleted, q, account.Label, zone.Name, operator))
}
