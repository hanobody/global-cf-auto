package telegram

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"DomainC/cfclient"
	"DomainC/config"
)

func (h *CommandHandler) handleSetDNSCommand(args []string) {
	if len(args) >= 4 {
		h.handleSetDNSDirect(args)
		return
	}

	if len(h.Accounts) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法修改解析。")
		return
	}

	if len(args) == 0 {
		h.sendSetDNSAccountSelector()
		return
	}

	if len(args) == 1 {
		selector := strings.TrimSpace(args[0])
		if acc := h.getAccountByLabel(selector); acc != nil {
			h.beginSetDNSKeywordInput(*acc)
			return
		}
	}

	h.sendText("交互用法: /setdns 后选择账号，再发送一个或多个关键词。\n旧用法仍可用: /setdns <domain.com> <type> <name> <content> [proxied:yes/no]")
}

func (h *CommandHandler) handleSetDNSDirect(args []string) {
	domain := strings.ToLower(strings.TrimSpace(args[0]))

	params := cfclient.DNSRecordParams{
		Type:    strings.ToUpper(args[1]),
		Name:    args[2],
		Content: args[3],
		Proxied: false,
		TTL:     3600,
	}

	if len(args) >= 5 {
		v := strings.ToLower(strings.TrimSpace(args[4]))
		params.Proxied = v == "yes" || v == "true" || v == "1"
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
	h.sendText(fmt.Sprintf("已在账号 %s 设置记录: %s %s -> %s (代理:%s, TTL:%d)",
		account.Label, record.Type, record.Name, record.Content, proxyStatus, params.TTL,
	))

	if strings.TrimSpace(params.Name) == "@" {
		wwwParams := cfclient.DNSRecordParams{
			Type:    "CNAME",
			Name:    "www",
			Content: domain,
			Proxied: params.Proxied,
			TTL:     3600,
		}

		wwwRecord, wwwErr := h.CFClient.UpsertDNSRecord(context.Background(), *account, domain, wwwParams)
		if wwwErr != nil {
			h.sendText(fmt.Sprintf("已设置根域记录，但设置 www CNAME 失败: %v", wwwErr))
			return
		}

		wwwProxyStatus := "否"
		if wwwRecord.Proxied != nil && *wwwRecord.Proxied {
			wwwProxyStatus = "是"
		}
		h.sendText(fmt.Sprintf("已自动设置 www 记录: %s %s -> %s (代理:%s, TTL:%d)",
			wwwRecord.Type, wwwRecord.Name, wwwRecord.Content, wwwProxyStatus, wwwParams.TTL,
		))
	}
}

func (h *CommandHandler) sendSetDNSAccountSelector() {
	var buttons [][]Button
	for _, acc := range h.Accounts {
		label := strings.TrimSpace(acc.Label)
		if label == "" {
			continue
		}
		token := SetSetDNSCallbackPayload(SetDNSCallbackPayload{AccountLabel: label})
		buttons = append(buttons, []Button{{
			Text:         label,
			CallbackData: fmt.Sprintf("setdns_account|%s", token),
		}})
	}
	if len(buttons) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法修改解析。")
		return
	}
	if err := h.Sender.SendWithButtons(context.Background(), h.setDNSPromptText(), buttons); err != nil {
		h.sendText(fmt.Sprintf("发送 setdns 账号选择失败: %v", err))
	}
}

func (h *CommandHandler) beginSetDNSKeywordInput(account config.CF) {
	if h.operator != nil {
		SetPendingSetDNSInput(h.operator.ID, SetDNSInputRequest{
			AccountLabel: account.Label,
			Stage:        SetDNSInputKeywords,
		})
	}
	h.sendText(BuildSetDNSKeywordPrompt(account.Label))
}

func (h *CommandHandler) setDNSPromptText() string {
	var sb strings.Builder
	sb.WriteString("请选择要修改解析的 Cloudflare 账号：\n")
	for _, acc := range h.Accounts {
		if strings.TrimSpace(acc.Label) == "" {
			continue
		}
		sb.WriteString("- " + acc.Label + "\n")
	}
	sb.WriteString("\n选择后发送关键词，支持 IP 片段或域名片段。")
	return sb.String()
}

func BuildSetDNSKeywordPrompt(accountLabel string) string {
	return fmt.Sprintf("已选择账号 %s。\n请发送一个或多个关键词，用于筛选该账号下所有解析记录。\n支持空格、换行、逗号或分号分隔。\n示例：\n1.2.3\nold-target.example.com\npromo", accountLabel)
}

func BuildSetDNSNewTargetPrompt(accountLabel string, selected int) string {
	return fmt.Sprintf("已确认 %d 条解析记录（账号: %s）。\n请发送新的解析目标，例如 IP 或域名。\n系统会在后台限速更新，记录类型、名称、代理状态和 TTL 会尽量保持不变。", selected, accountLabel)
}

func (h *CommandHandler) handlePendingSetDNSInput(msgText string, userID int64) bool {
	req, ok := GetPendingSetDNSInput(userID)
	if !ok {
		return false
	}

	switch req.Stage {
	case SetDNSInputKeywords:
		h.handlePendingSetDNSKeywords(msgText, userID, req)
	case SetDNSInputNewTarget:
		h.handlePendingSetDNSNewTarget(msgText, userID, req)
	default:
		ClearPendingSetDNSInput(userID)
		h.sendText("未知的 setdns 交互状态，已取消。")
	}
	return true
}

func (h *CommandHandler) handlePendingSetDNSKeywords(msgText string, userID int64, req SetDNSInputRequest) {
	keywords := parseSetDNSKeywords(msgText)
	if len(keywords) == 0 {
		h.sendText(BuildSetDNSKeywordPrompt(req.AccountLabel))
		return
	}

	acc := h.getAccountByLabel(req.AccountLabel)
	if acc == nil {
		ClearPendingSetDNSInput(userID)
		h.sendText(fmt.Sprintf("未找到账号 %s，已取消 setdns。", req.AccountLabel))
		return
	}

	h.sendText(fmt.Sprintf("正在读取账号 %s 下所有解析记录并按关键词筛选，请稍候...", acc.Label))
	candidates, failures, err := h.findSetDNSCandidates(context.Background(), *acc, keywords)
	if err != nil {
		h.sendText(fmt.Sprintf("读取解析记录失败: %v", err))
		return
	}
	if len(candidates) == 0 {
		h.sendText(BuildSetDNSNoMatchMessage(acc.Label, keywords, failures))
		return
	}

	sessionID := SetSetDNSSelection(SetDNSSelection{
		AccountLabel: acc.Label,
		Keywords:     keywords,
		Candidates:   candidates,
		Selected:     make(map[string]bool),
		Page:         0,
	})
	ClearPendingSetDNSInput(userID)
	msg, buttons := BuildSetDNSMatchSummary(sessionID, acc.Label, keywords, candidates, failures)
	if err := h.Sender.SendWithButtons(context.Background(), msg, buttons); err != nil {
		h.sendText(fmt.Sprintf("发送 setdns 筛选结果失败: %v", err))
	}
}

func (h *CommandHandler) handlePendingSetDNSNewTarget(msgText string, userID int64, req SetDNSInputRequest) {
	newTarget := normalizeSetDNSNewTarget(msgText)
	if newTarget == "" {
		h.sendText(BuildSetDNSNewTargetPrompt(req.AccountLabel, 0))
		return
	}

	targets, ok := SelectedSetDNSRecordTargets(req.SessionID)
	if !ok {
		ClearPendingSetDNSInput(userID)
		h.sendText("setdns 选择已过期，请重新执行 /setdns。")
		return
	}
	if len(targets) == 0 {
		ClearPendingSetDNSInput(userID)
		h.sendText("没有已选择的解析记录，本轮 setdns 已取消。")
		return
	}

	acc := h.getAccountByLabel(req.AccountLabel)
	if acc == nil {
		ClearPendingSetDNSInput(userID)
		h.sendText(fmt.Sprintf("未找到账号 %s，已取消 setdns。", req.AccountLabel))
		return
	}

	keys := make([]string, 0, len(targets))
	for _, target := range targets {
		keys = append(keys, target.Key)
	}
	remaining, _ := RemoveSetDNSRecordTargets(req.SessionID, keys)
	ClearPendingSetDNSInput(userID)

	go func() {
		result := ProcessSetDNSUpdateTargets(context.Background(), h.CFClient, *acc, targets, newTarget)
		h.sendText(result.Summary())
	}()

	if len(remaining.Candidates) == 0 {
		ClearSetDNSSelection(req.SessionID)
		h.sendText(fmt.Sprintf("已开始后台更新 %d 条解析记录，当前筛选结果已全部安排处理。", len(targets)))
		return
	}

	token := SetSetDNSCallbackPayload(SetDNSCallbackPayload{
		AccountLabel: req.AccountLabel,
		SessionID:    req.SessionID,
	})
	buttons := [][]Button{{
		{Text: fmt.Sprintf("继续修改剩余 %d 条", len(remaining.Candidates)), CallbackData: fmt.Sprintf("setdns_continue|%s", token)},
		{Text: "结束本次修改", CallbackData: fmt.Sprintf("setdns_finish|%s", token)},
	}}
	if err := h.Sender.SendWithButtons(context.Background(),
		fmt.Sprintf("已开始后台更新 %d 条解析记录为：%s\n是否继续修改剩余候选记录？", len(targets), newTarget),
		buttons,
	); err != nil {
		h.sendText(fmt.Sprintf("发送 setdns 继续选择失败: %v", err))
	}
}

func (h *CommandHandler) findSetDNSCandidates(ctx context.Context, account config.CF, keywords []string) ([]SetDNSRecordTarget, []string, error) {
	zones, err := h.CFClient.ListZones(ctx, account)
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(zones, func(i, j int) bool {
		return zones[i].Name < zones[j].Name
	})

	pacer := newBatchAPIPacerWithInterval(300 * time.Millisecond)
	var candidates []SetDNSRecordTarget
	var failures []string
	for _, zone := range zones {
		if err := pacer.Wait(ctx); err != nil {
			return nil, failures, err
		}
		records, err := h.CFClient.ListDNSRecords(ctx, account, zone.Name)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", zone.Name, err))
			continue
		}
		for _, record := range records {
			matches := matchSetDNSKeywords(zone.Name, record.Name, record.Content, keywords)
			if len(matches) == 0 || strings.TrimSpace(record.ID) == "" {
				continue
			}
			var proxied *bool
			if record.Proxied != nil {
				v := *record.Proxied
				proxied = &v
			}
			candidates = append(candidates, SetDNSRecordTarget{
				Key:      zone.Name + ":" + record.ID,
				ZoneName: zone.Name,
				RecordID: record.ID,
				Type:     record.Type,
				Name:     record.Name,
				Content:  record.Content,
				TTL:      record.TTL,
				Proxied:  proxied,
				Matches:  matches,
			})
		}
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Name == candidates[j].Name {
			return candidates[i].Content < candidates[j].Content
		}
		return candidates[i].Name < candidates[j].Name
	})
	return candidates, failures, nil
}

func parseSetDNSKeywords(input string) []string {
	fields := strings.FieldsFunc(input, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';' || r == '，' || r == '；'
	})
	seen := make(map[string]struct{}, len(fields))
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		kw := strings.ToLower(strings.TrimSpace(field))
		if kw == "" {
			continue
		}
		if _, ok := seen[kw]; ok {
			continue
		}
		seen[kw] = struct{}{}
		out = append(out, kw)
	}
	return out
}

func matchSetDNSKeywords(zoneName string, recordName string, content string, keywords []string) []string {
	haystack := strings.ToLower(strings.Join([]string{zoneName, recordName, content}, "\n"))
	var matches []string
	for _, keyword := range keywords {
		if strings.Contains(haystack, keyword) {
			matches = append(matches, keyword)
		}
	}
	return matches
}

func normalizeSetDNSNewTarget(input string) string {
	lines := strings.Fields(strings.TrimSpace(input))
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSuffix(lines[0], ".")
}

func BuildSetDNSNoMatchMessage(accountLabel string, keywords []string, failures []string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("账号 %s 没有筛选到匹配解析记录。\n关键词: %s", accountLabel, strings.Join(keywords, ", ")))
	if len(failures) > 0 {
		sb.WriteString("\n\n以下 Zone 读取失败:")
		for _, item := range failures {
			sb.WriteString("\n- " + item)
		}
	}
	return sb.String()
}

func BuildSetDNSMatchSummary(sessionID string, accountLabel string, keywords []string, candidates []SetDNSRecordTarget, failures []string) (string, [][]Button) {
	domains := make(map[string]struct{})
	for _, candidate := range candidates {
		domains[candidate.Name] = struct{}{}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("【setdns 筛选结果】\n账号: %s\n关键词: %s\n匹配解析记录: %d\n涉及域名: %d\n\n",
		accountLabel, strings.Join(keywords, ", "), len(candidates), len(domains)))
	limit := 35
	for i, candidate := range candidates {
		if i >= limit {
			sb.WriteString(fmt.Sprintf("- ... 其余 %d 条匹配记录\n", len(candidates)-i))
			break
		}
		sb.WriteString(fmt.Sprintf("- %s %s -> %s", candidate.Type, candidate.Name, truncateDisplay(candidate.Content, 70)))
		if len(candidate.Matches) > 0 {
			sb.WriteString(fmt.Sprintf(" (匹配: %s)", strings.Join(candidate.Matches, ", ")))
		}
		sb.WriteString("\n")
	}
	if len(failures) > 0 {
		sb.WriteString("\n读取失败的 Zone:")
		for i, item := range failures {
			if i >= 5 {
				sb.WriteString(fmt.Sprintf("\n- ... 其余 %d 个失败", len(failures)-i))
				break
			}
			sb.WriteString("\n- " + item)
		}
	}
	sb.WriteString("\n请确认是否进入修改选择。")

	token := SetSetDNSCallbackPayload(SetDNSCallbackPayload{
		AccountLabel: accountLabel,
		SessionID:    sessionID,
	})
	buttons := [][]Button{{
		{Text: "进入选择修改", CallbackData: fmt.Sprintf("setdns_start|%s", token)},
		{Text: "取消", CallbackData: fmt.Sprintf("setdns_cancel|%s", token)},
	}}
	return sb.String(), buttons
}

type SetDNSUpdateResult struct {
	AccountLabel string
	NewTarget    string
	Success      []SetDNSRecordTarget
	Failed       []string
}

func (r SetDNSUpdateResult) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("✅ setdns 后台更新完成\n账号: %s\n新目标: %s\n成功: %d", r.AccountLabel, r.NewTarget, len(r.Success)))
	if len(r.Failed) > 0 {
		sb.WriteString(fmt.Sprintf("\n失败: %d", len(r.Failed)))
		for _, item := range r.Failed {
			sb.WriteString("\n- " + item)
		}
	}
	return sb.String()
}

func ProcessSetDNSUpdateTargets(ctx context.Context, client cfclient.Client, account config.CF, targets []SetDNSRecordTarget, newTarget string) SetDNSUpdateResult {
	result := SetDNSUpdateResult{
		AccountLabel: account.Label,
		NewTarget:    newTarget,
	}
	if client == nil {
		client = cfclient.NewClient()
	}

	pacer := newBatchAPIPacerWithInterval(1500 * time.Millisecond)
	for _, target := range targets {
		if err := pacer.Wait(ctx); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: 等待执行失败: %v", target.Name, err))
			continue
		}
		if err := updateSetDNSRecordWithRetry(ctx, client, account, target, newTarget); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s %s: %v", target.Type, target.Name, err))
			continue
		}
		result.Success = append(result.Success, target)
	}
	return result
}

func updateSetDNSRecordWithRetry(ctx context.Context, client cfclient.Client, account config.CF, target SetDNSRecordTarget, newTarget string) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		_, err := client.UpdateDNSRecord(ctx, account, target.ZoneName, cfclient.DNSRecordUpdateParams{
			ID:      target.RecordID,
			Type:    target.Type,
			Name:    target.Name,
			Content: newTarget,
			Proxied: target.Proxied,
			TTL:     target.TTL,
		})
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableCloudflareError(err) || attempt == 2 {
			break
		}

		timer := time.NewTimer(time.Duration(attempt+1) * 3 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}
