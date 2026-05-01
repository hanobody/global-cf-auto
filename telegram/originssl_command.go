package telegram

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"html"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"DomainC/cfclient"
	"DomainC/config"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acm"
)

type originSSLImportResult struct {
	Alias  string
	Region string
	ARN    string
	Err    error
}

type originSSLDomainResult struct {
	Domain       string
	AccountLabel string
	StrictErr    error
	Imports      []originSSLImportResult
}

type originSSLBatchResult struct {
	AWSAliases    []string
	Success       []originSSLDomainResult
	ParseErrors   []string
	Failed        []string
}

type originSSLARNEntry struct {
	Domain       string
	AccountLabel string
	Alias        string
	Region       string
	ARN          string
}

const (
	originSSLStatusPollInterval = 2 * time.Minute
	originSSLStatusPollAttempts = 180
	originSSLTaskConcurrency    = 3
	originSSLDNSRecordLimit     = 500
)

type OriginSSLInteractiveDomainResult struct {
	Domain       string
	AccountLabel string
	CertID       string
	StrictErr    error
	Imports      []OriginSSLAWSImportResult
	SpeedApplied []string
	SpeedFailed  []string
}

type OriginSSLAWSImportResult struct {
	Alias  string
	Region string
	ARN    string
	Err    error
}

type OriginSSLInteractiveResult struct {
	AccountLabel string
	AWSAliases   []string
	Success      []OriginSSLInteractiveDomainResult
	Failed       []string
}

type OriginSSLDNSCreateResult struct {
	AccountLabel string
	Success      []OriginSSLDNSRecordPlan
	Failed       []string
}

func (r OriginSSLInteractiveResult) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("SSL 后台任务完成\n账号: %s\n成功: %d", r.AccountLabel, len(r.Success)))
	if len(r.AWSAliases) == 0 {
		sb.WriteString("\nAWS 导入: 未选择")
	} else {
		sb.WriteString("\nAWS 导入: " + strings.Join(formatAWSTargets(r.AWSAliases), ", "))
	}
	if len(r.Success) > 0 {
		var arnLines []string
		for _, item := range r.Success {
			strict := "ok"
			if item.StrictErr != nil {
				strict = "failed: " + item.StrictErr.Error()
			}
			importOK := 0
			for _, imp := range item.Imports {
				if imp.Err == nil && strings.TrimSpace(imp.ARN) != "" {
					importOK++
					arnLines = append(arnLines, fmt.Sprintf("%s | %s(%s) | %s", item.Domain, imp.Alias, imp.Region, extractARNResourceID(imp.ARN)))
				}
			}
			sb.WriteString(fmt.Sprintf("\n- %s | Full(Strict): %s | Speed:%d/%d | ACM:%d/%d",
				item.Domain, strict, len(item.SpeedApplied), len(item.SpeedApplied)+len(item.SpeedFailed), importOK, len(item.Imports)))
		}
		if len(arnLines) > 0 {
			sb.WriteString("\n\nARN 对照:")
			for i, line := range arnLines {
				if i >= 10 {
					sb.WriteString(fmt.Sprintf("\n- ... 其余 %d 条 ARN", len(arnLines)-i))
					break
				}
				sb.WriteString("\n- " + line)
			}
		}
	}
	if len(r.Failed) > 0 {
		sb.WriteString(fmt.Sprintf("\n失败: %d", len(r.Failed)))
		for i, item := range r.Failed {
			if i >= 20 {
				sb.WriteString(fmt.Sprintf("\n- ... 其余 %d 条失败", len(r.Failed)-i))
				break
			}
			sb.WriteString("\n- " + item)
		}
	}
	return sb.String()
}

func (r OriginSSLDNSCreateResult) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ssl DNS 后台创建完成\n账号: %s\n成功: %d", r.AccountLabel, len(r.Success)))
	if len(r.Failed) > 0 {
		sb.WriteString(fmt.Sprintf("\n失败: %d", len(r.Failed)))
		for i, item := range r.Failed {
			if i >= 20 {
				sb.WriteString(fmt.Sprintf("\n- ... 其余 %d 条失败", len(r.Failed)-i))
				break
			}
			sb.WriteString("\n- " + item)
		}
	}
	return sb.String()
}

func (r originSSLBatchResult) SummaryText() string {
	var sb strings.Builder
	sb.WriteString("✅ /ssl 处理完成")
	sb.WriteString("\nCloudflare 账号: 自动按域名识别")

	sb.WriteString("\nAWS 目标: ")
	if len(r.AWSAliases) == 0 {
		sb.WriteString("未选择（只生成源站证书）")
	} else {
		sb.WriteString(strings.Join(formatAWSTargets(r.AWSAliases), ", "))
	}

	sb.WriteString(fmt.Sprintf("\n成功域名: %d", len(r.Success)))

	var importFailLines []string
	arnCount := 0
	for _, item := range r.Success {
		successImports := 0
		for _, imp := range item.Imports {
			if imp.Err == nil && strings.TrimSpace(imp.ARN) != "" {
				arnCount++
				successImports++
				continue
			}
			importFailLines = append(importFailLines, fmt.Sprintf("%s / %s (%s): %v", item.Domain, imp.Alias, imp.Region, imp.Err))
		}
		strictStatus := "已设置"
		if item.StrictErr != nil {
			strictStatus = "失败: " + item.StrictErr.Error()
		}
		sb.WriteString(fmt.Sprintf("\n- %s -> %s | Full(Strict): %s | ACM: %d/%d", item.Domain, item.AccountLabel, strictStatus, successImports, len(item.Imports)))
	}
	sb.WriteString(fmt.Sprintf("\n成功 ARN: %d", arnCount))

	if len(r.ParseErrors) > 0 {
		sb.WriteString("\n\n格式错误:")
		for _, item := range r.ParseErrors {
			sb.WriteString("\n- " + item)
		}
	}

	if len(r.Failed) > 0 {
		sb.WriteString("\n\n处理失败:")
		for _, item := range r.Failed {
			sb.WriteString("\n- " + item)
		}
	}

	if len(importFailLines) > 0 {
		sb.WriteString("\n\nACM 导入失败:")
		for _, item := range importFailLines {
			sb.WriteString("\n- " + item)
		}
	}

	return sb.String()
}

func (h *CommandHandler) handleOriginSSLCommand(args []string) {
	if len(h.Accounts) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法生成源站证书。")
		return
	}

	if len(args) == 0 {
		h.startOriginSSLInteractive()
		return
	}

	if len(args) == 1 {
		if acc := h.getAccountByLabel(strings.TrimSpace(args[0])); acc != nil {
			h.beginOriginSSLDomainSelection(*acc)
			return
		}
	}

	domainArgs, awsAliases := splitOriginSSLDirectArgs(args)
	if len(domainArgs) == 0 {
		h.startOriginSSLInteractive()
		return
	}

	domains, parseErrors := parseGetNSDomainsInput(strings.Join(domainArgs, "\n"))
	if len(domains) == 0 {
		h.sendText(h.originSSLRetryPrompt(OriginSSLInputRequest{
			AWSAliases:    awsAliases,
		}, parseErrors))
		return
	}

	req := OriginSSLInputRequest{
		AWSAliases:    awsAliases,
	}
	result := h.processOriginSSLBatch(req, domains)
	result.ParseErrors = append(result.ParseErrors, parseErrors...)
	h.sendOriginSSLResult(result)
}

func (h *CommandHandler) startOriginSSLInteractive() {
	if h.operator != nil {
		ClearPendingOriginSSLInput(h.operator.ID)
	}
	h.sendOriginSSLAccountSelector()
}

func (h *CommandHandler) sendOriginSSLAccountSelector() {
	var buttons [][]Button
	for _, acc := range h.Accounts {
		label := strings.TrimSpace(acc.Label)
		if label == "" {
			continue
		}
		token := SetOriginSSLCallbackPayload(OriginSSLCallbackPayload{AccountLabel: label})
		buttons = append(buttons, []Button{{
			Text:         label,
			CallbackData: fmt.Sprintf("ssl_account|%s", token),
		}})
	}
	if len(buttons) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法生成源站证书。")
		return
	}
	if err := h.Sender.SendWithButtons(context.Background(), h.originSSLPromptText(), buttons); err != nil {
		h.sendText(fmt.Sprintf("发送 /ssl 账号选择失败: %v", err))
	}
}

func (h *CommandHandler) beginOriginSSLDomainSelection(account config.CF) {
	if h.operator != nil {
		ClearPendingOriginSSLInput(h.operator.ID)
	}
	h.sendText(fmt.Sprintf("正在读取账号 %s 下所有域名，请稍候。", account.Label))
	if err := BeginOriginSSLDomainSelection(context.Background(), h.CFClient, h.Sender, account); err != nil {
		h.sendText(fmt.Sprintf("读取 /ssl 域名列表失败: %v", err))
	}
}

func (h *CommandHandler) sendOriginSSLTargetSelector(userID int64) {
	selection := GetOriginSSLSelection(userID)
	if err := h.Sender.SendWithButtons(context.Background(), OriginSSLTargetPromptText(), BuildOriginSSLAWSButtons(selection)); err != nil {
		h.sendText(fmt.Sprintf("发送 /ssl AWS 目标选择失败: %v", err))
	}
}

func BuildOriginSSLAWSButtons(selection OriginSSLSelection) [][]Button {
	aliases := sortedAWSTargetAliases()
	flat := make([]Button, 0, len(aliases))
	for _, alias := range aliases {
		mark := "☐"
		if selection.AWSAliases[alias] {
			mark = "☑"
		}
		target := config.Cfg.AWSTargets[alias]
		token := SetOriginSSLCallbackPayload(OriginSSLCallbackPayload{Value: alias})
		flat = append(flat, Button{
			Text:         fmt.Sprintf("%s %s (%s)", mark, alias, target.Region),
			CallbackData: fmt.Sprintf("ssl_aws_toggle|%s", token),
		})
	}

	buttons := chunkButtons(flat, 2)
	doneToken := SetOriginSSLCallbackPayload(OriginSSLCallbackPayload{})
	buttons = append(buttons, []Button{{
		Text:         fmt.Sprintf("开始输入域名（已选 %d）", len(selection.AWSAliases)),
		CallbackData: fmt.Sprintf("ssl_aws_done|%s", doneToken),
	}})
	return buttons
}

func chunkButtons(flat []Button, width int) [][]Button {
	if width <= 0 {
		width = 1
	}
	buttons := make([][]Button, 0, (len(flat)+width-1)/width)
	for i := 0; i < len(flat); i += width {
		end := i + width
		if end > len(flat) {
			end = len(flat)
		}
		row := make([]Button, 0, end-i)
		row = append(row, flat[i:end]...)
		buttons = append(buttons, row)
	}
	return buttons
}

func OriginSSLTargetPromptText() string {
	var sb strings.Builder
	sb.WriteString("Cloudflare 账号会按域名自动识别。\n")
	sb.WriteString("请选择要导入证书的 AWS 目标（可多选，可不选）：\n")
	for _, alias := range sortedAWSTargetAliases() {
		target := config.Cfg.AWSTargets[alias]
		sb.WriteString(fmt.Sprintf("- %s (%s)\n", alias, target.Region))
	}
	sb.WriteString("\n完成后直接输入一个或多个主域名。")
	return sb.String()
}

func BeginOriginSSLDomainSelection(ctx context.Context, client cfclient.Client, sender Sender, account config.CF) error {
	if client == nil {
		client = cfclient.NewClient()
	}
	if sender == nil {
		sender = DefaultSender()
	}

	zones, err := client.ListZoneSummaries(ctx, account)
	if err != nil {
		return err
	}
	if len(zones) == 0 {
		return sender.Send(ctx, fmt.Sprintf("账号 %s 暂无可选择域名。", account.Label))
	}

	items := buildOriginSSLDomainItems(account.Label, zones)
	sessionID := SetOriginSSLDomainSelection(OriginSSLDomainSelection{
		AccountLabel: account.Label,
		Items:        items,
		Selected:     make(map[string]bool),
		Page:         0,
	})
	selection, _ := GetOriginSSLDomainSelection(sessionID)
	page := BuildOriginSSLDomainSelectionView(sessionID, selection)
	return sender.SendWithButtons(ctx, page.Message, page.Buttons)
}

func buildOriginSSLDomainItems(accountLabel string, zones []cfclient.ZoneSummary) []OriginSSLDomainItem {
	items := make([]OriginSSLDomainItem, 0, len(zones))
	for _, zone := range zones {
		name := strings.TrimSpace(strings.ToLower(zone.Name))
		if name == "" {
			continue
		}
		key := strings.TrimSpace(zone.ID)
		if key == "" {
			key = name
		}
		items = append(items, OriginSSLDomainItem{
			Key:              key,
			AccountLabel:     accountLabel,
			ZoneID:           zone.ID,
			Name:             name,
			Status:           zone.Status,
			Paused:           zone.Paused,
			CreatedOn:        zone.CreatedOn,
			Plan:             zone.Plan,
			SecurityInsights: zone.SecurityInsights,
			UniqueVisitors:   zone.UniqueVisitors,
		})
	}
	sortOriginSSLDomainItems(items)
	return items
}

func sortOriginSSLDomainItems(items []OriginSSLDomainItem) {
	sort.Slice(items, func(i, j int) bool {
		iToday := isTodayLocal(items[i].CreatedOn)
		jToday := isTodayLocal(items[j].CreatedOn)
		if iToday != jToday {
			return iToday
		}
		if !items[i].CreatedOn.Equal(items[j].CreatedOn) {
			return items[i].CreatedOn.After(items[j].CreatedOn)
		}
		return items[i].Name < items[j].Name
	})
}

func isTodayLocal(t time.Time) bool {
	if t.IsZero() {
		return false
	}
	now := time.Now()
	ny, nm, nd := now.Date()
	ty, tm, td := t.Local().Date()
	return ny == ty && nm == tm && nd == td
}

func (h *CommandHandler) handlePendingOriginSSLInput(msgText string, userID int64) bool {
	req, ok := GetPendingOriginSSLInput(userID)
	if !ok {
		return false
	}

	switch req.Stage {
	case OriginSSLInputDNSTarget:
		h.handlePendingOriginSSLDNSTarget(msgText, userID, req)
		return true
	case OriginSSLInputDNSRecords:
		h.handlePendingOriginSSLDNSRecords(msgText, userID, req)
		return true
	case "", OriginSSLInputDomains:
	default:
		ClearPendingOriginSSLInput(userID)
		h.sendText("未知的 /ssl 交互状态，已取消。")
		return true
	}

	domains, parseErrors := parseGetNSDomainsInput(msgText)
	if len(domains) == 0 {
		h.sendText(h.originSSLRetryPrompt(req, parseErrors))
		return true
	}

	result := h.processOriginSSLBatch(req, domains)
	result.ParseErrors = append(result.ParseErrors, parseErrors...)
	if len(result.ParseErrors) == 0 && len(result.Failed) == 0 {
		ClearPendingOriginSSLInput(userID)
	}
	h.sendOriginSSLResult(result)
	return true
}

func (h *CommandHandler) handlePendingOriginSSLDNSTarget(msgText string, userID int64, req OriginSSLInputRequest) {
	if isOriginSSLStopInput(msgText) {
		ClearPendingOriginSSLInput(userID)
		ClearOriginSSLDomainSelection(req.SessionID)
		h.sendText("/ssl 交互已结束。")
		return
	}

	recordType, target, err := ParseOriginSSLDNSTarget(msgText)
	if err != nil {
		h.sendText(BuildOriginSSLDNSTargetPrompt(req.AccountLabel, len(req.SelectedDomains), err.Error()))
		return
	}

	ClearPendingOriginSSLInput(userID)
	page := BuildOriginSSLDNSProxyView(req.SessionID, req.AccountLabel, recordType, target)
	if err := h.Sender.SendWithButtons(context.Background(), page.Message, page.Buttons); err != nil {
		h.sendText(fmt.Sprintf("发送 /ssl DNS 代理选择失败: %v", err))
	}
}

func (h *CommandHandler) handlePendingOriginSSLDNSRecords(msgText string, userID int64, req OriginSSLInputRequest) {
	if isOriginSSLStopInput(msgText) {
		ClearPendingOriginSSLInput(userID)
		ClearOriginSSLDomainSelection(req.SessionID)
		h.sendText("/ssl 交互已结束。")
		return
	}

	if names, ok := parseOriginSSLDNSNamesOnly(msgText); ok {
		h.handlePendingOriginSSLDNSNames(names, userID, req)
		return
	}

	plan, parseErrors := BuildOriginSSLDNSPlan(req.AccountLabel, req.SessionID, req.SelectedDomains, req.DNSRecordType, req.DNSTarget, req.Proxied, msgText)
	if len(plan.Records) == 0 {
		h.sendText(BuildOriginSSLDNSRecordsPrompt(req, parseErrors))
		return
	}
	plan.Records = mergeOriginSSLDNSRecords(req.PendingDNSRecords, plan.Records)

	ClearPendingOriginSSLInput(userID)
	planID := SetOriginSSLDNSPlan(plan)
	page := BuildOriginSSLDNSPlanConfirmView(planID, plan)
	if err := h.Sender.SendWithButtons(context.Background(), page.Message, page.Buttons); err != nil {
		h.sendText(fmt.Sprintf("发送 /ssl DNS 创建确认失败: %v", err))
	}
}

func (h *CommandHandler) handlePendingOriginSSLDNSNames(names []string, userID int64, req OriginSSLInputRequest) {
	domains := normalizeOriginSSLSelectedDomains(req.SelectedDomains)
	if len(domains) == 0 {
		h.sendText(BuildOriginSSLDNSRecordsPrompt(req, []string{"没有剩余可创建解析的域名"}))
		return
	}
	if len(domains) == 1 {
		plan := BuildOriginSSLDNSNamePlan(req.AccountLabel, req.SessionID, domains, names, req.DNSRecordType, req.DNSTarget, req.Proxied)
		plan.Records = mergeOriginSSLDNSRecords(req.PendingDNSRecords, plan.Records)
		ClearPendingOriginSSLInput(userID)
		planID := SetOriginSSLDNSPlan(plan)
		page := BuildOriginSSLDNSPlanConfirmView(planID, plan)
		if err := h.Sender.SendWithButtons(context.Background(), page.Message, page.Buttons); err != nil {
			h.sendText(fmt.Sprintf("发送 /ssl DNS 创建确认失败: %v", err))
		}
		return
	}

	nameSessionID := SetOriginSSLDNSNameSelection(OriginSSLDNSNameSelection{
		AccountLabel:      req.AccountLabel,
		OriginSessionID:   req.SessionID,
		DNSTarget:         req.DNSTarget,
		DNSRecordType:     req.DNSRecordType,
		Proxied:           req.Proxied,
		Names:             names,
		Domains:           domains,
		Selected:          make(map[string]bool),
		PendingDNSRecords: append([]OriginSSLDNSRecordPlan(nil), req.PendingDNSRecords...),
		Page:              0,
	})
	ClearPendingOriginSSLInput(userID)
	selection, _ := GetOriginSSLDNSNameSelection(nameSessionID)
	page := BuildOriginSSLDNSNameDomainSelectionView(nameSessionID, selection)
	if err := h.Sender.SendWithButtons(context.Background(), page.Message, page.Buttons); err != nil {
		h.sendText(fmt.Sprintf("发送 /ssl 解析名适用域名选择失败: %v", err))
	}
}

func (h *CommandHandler) originSSLInputPrompt(req OriginSSLInputRequest) string {
	return BuildOriginSSLInputPrompt(req)
}

func BuildOriginSSLInputPrompt(req OriginSSLInputRequest) string {
	var sb strings.Builder
	sb.WriteString("已完成 /ssl 选择。\n")
	sb.WriteString("Cloudflare 账号: 自动按域名识别")
	sb.WriteString("\nAWS 目标: ")
	if len(req.AWSAliases) == 0 {
		sb.WriteString("未选择（只生成源站证书）")
	} else {
		sb.WriteString(strings.Join(formatAWSTargets(req.AWSAliases), ", "))
	}
	sb.WriteString("\n\n请直接发送一个或多个主域名，支持多行、空格、逗号或分号分隔。\n示例：\nexample.com\nexample.net")
	return sb.String()
}

func BuildOriginSSLDNSTargetPrompt(accountLabel string, selected int, errText string) string {
	var sb strings.Builder
	if strings.TrimSpace(errText) != "" {
		sb.WriteString("解析目标无法识别: " + errText + "\n\n")
	}
	sb.WriteString(fmt.Sprintf("账号: %s\n已选择域名: %d\n", accountLabel, selected))
	sb.WriteString("请发送一个解析目标，只能一条。\n")
	sb.WriteString("IPv4 会创建 A 记录，域名会创建 CNAME 记录。\n")
	sb.WriteString("发送 关闭、结束、exit 或 stop 可以结束本次流程。\n")
	sb.WriteString("示例:\n1.2.3.4\norigin.example.com")
	return sb.String()
}

func BuildOriginSSLDNSRecordsPrompt(req OriginSSLInputRequest, errs []string) string {
	var sb strings.Builder
	if len(errs) > 0 {
		sb.WriteString("以下输入未识别或不属于已选域名:\n")
		for i, item := range errs {
			if i >= 20 {
				sb.WriteString(fmt.Sprintf("- ... 其余 %d 条\n", len(errs)-i))
				break
			}
			sb.WriteString("- " + item + "\n")
		}
		sb.WriteString("\n")
	}
	proxy := "关闭"
	if req.Proxied {
		proxy = "开启"
	}
	sb.WriteString(fmt.Sprintf("账号: %s\n解析目标: %s %s\n代理: %s\n", req.AccountLabel, req.DNSRecordType, req.DNSTarget, proxy))
	if len(req.SelectedDomains) > 0 {
		sb.WriteString(fmt.Sprintf("剩余域名: %d\n", len(req.SelectedDomains)))
	}
	sb.WriteString("请发送要创建解析的完整域名，支持空格、换行、逗号或分号分隔。\n")
	sb.WriteString("也可以只发送解析名，例如 @ a www，系统会再询问适用哪些域名。\n")
	sb.WriteString("发送 关闭、结束、exit 或 stop 可以结束本次流程。\n")
	sb.WriteString("示例:\na.123.com b.123.com fr.abc.com 123.com cad.com\n")
	sb.WriteString("根域记录会自动额外创建 www CNAME 指向根域。")
	return sb.String()
}

func (h *CommandHandler) originSSLRetryPrompt(req OriginSSLInputRequest, errs []string) string {
	var sb strings.Builder
	if len(errs) > 0 {
		sb.WriteString("以下域名未识别：\n")
		for _, item := range errs {
			sb.WriteString("- " + item + "\n")
		}
		sb.WriteString("\n")
	}
	sb.WriteString(h.originSSLInputPrompt(req))
	return strings.TrimSpace(sb.String())
}

func splitOriginSSLDirectArgs(args []string) ([]string, []string) {
	domains := make([]string, 0, len(args))
	aliases := make([]string, 0, len(args))
	seenAlias := make(map[string]bool)

	for _, arg := range args {
		token := strings.TrimSpace(arg)
		if token == "" {
			continue
		}
		if _, ok := config.Cfg.AWSTargets[token]; ok {
			if seenAlias[token] {
				continue
			}
			seenAlias[token] = true
			aliases = append(aliases, token)
			continue
		}
		domains = append(domains, token)
	}

	return domains, aliases
}

func ParseOriginSSLDNSTarget(input string) (string, string, error) {
	fields := splitOriginSSLFields(input)
	if len(fields) != 1 {
		return "", "", fmt.Errorf("只能输入一个目标")
	}

	target := strings.TrimSpace(strings.ToLower(fields[0]))
	target = strings.TrimSuffix(target, ".")
	if target == "" {
		return "", "", fmt.Errorf("目标为空")
	}
	if strings.Contains(target, "/") || strings.Contains(target, "://") {
		return "", "", fmt.Errorf("目标不能包含 URL、路径或 CIDR")
	}

	ip := net.ParseIP(target)
	if ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return "", "", fmt.Errorf("暂不支持 IPv6 作为本流程目标")
		}
		return "A", ip4.String(), nil
	}
	if looksLikeIPv4Literal(target) {
		return "", "", fmt.Errorf("IPv4 地址格式不合法")
	}

	host, ok := normalizeOriginSSLHostname(target)
	if !ok {
		return "", "", fmt.Errorf("不是有效 IPv4 或域名")
	}
	return "CNAME", host, nil
}

func isOriginSSLStopInput(input string) bool {
	normalized := strings.ToLower(strings.TrimSpace(input))
	switch normalized {
	case "关闭", "结束", "exit", "stop":
		return true
	default:
		return false
	}
}

func BuildOriginSSLDNSPlan(accountLabel string, sessionID string, selectedDomains []string, recordType string, target string, proxied bool, input string) (OriginSSLDNSPlan, []string) {
	plan := OriginSSLDNSPlan{
		AccountLabel: accountLabel,
		SessionID:    sessionID,
	}
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	target = strings.TrimSpace(target)
	if recordType == "" || target == "" {
		return plan, []string{"解析目标不完整"}
	}
	if recordType != "A" && recordType != "CNAME" {
		return plan, []string{"不支持的解析类型: " + recordType}
	}

	zones := normalizeOriginSSLSelectedDomains(selectedDomains)
	if len(zones) == 0 {
		return plan, []string{"没有可用的已选域名"}
	}

	fields := splitOriginSSLFields(input)
	if len(fields) == 0 {
		return plan, []string{"输入为空"}
	}

	seen := make(map[string]struct{})
	seenName := make(map[string]struct{})
	rootDomains := make(map[string]struct{})
	var errs []string
	for _, field := range fields {
		host, ok := normalizeOriginSSLHostname(field)
		if !ok {
			errs = append(errs, field)
			continue
		}

		domain, name, ok := matchOriginSSLSelectedDomain(host, zones)
		if !ok {
			errs = append(errs, field)
			continue
		}

		appendRecord := func(record OriginSSLDNSRecordPlan) {
			if len(plan.Records) >= originSSLDNSRecordLimit {
				return
			}
			key := strings.Join([]string{record.Domain, record.Name, record.Type}, "|")
			if _, exists := seen[key]; exists {
				return
			}
			seen[key] = struct{}{}
			seenName[strings.Join([]string{record.Domain, record.Name}, "|")] = struct{}{}
			plan.Records = append(plan.Records, record)
		}

		appendRecord(OriginSSLDNSRecordPlan{
			AccountLabel: accountLabel,
			Domain:       domain,
			Name:         name,
			FQDN:         fqdnFromOriginSSLName(domain, name),
			Type:         recordType,
			Content:      target,
			Proxied:      proxied,
		})

		if name == "@" {
			rootDomains[domain] = struct{}{}
		}

		if len(plan.Records) >= originSSLDNSRecordLimit {
			errs = append(errs, fmt.Sprintf("记录数量超过上限 %d，本次已停止继续解析", originSSLDNSRecordLimit))
			break
		}
	}

	rootList := make([]string, 0, len(rootDomains))
	for domain := range rootDomains {
		rootList = append(rootList, domain)
	}
	sort.Strings(rootList)
	for _, domain := range rootList {
		if len(plan.Records) >= originSSLDNSRecordLimit {
			errs = append(errs, fmt.Sprintf("记录数量超过上限 %d，部分自动 www 记录未加入", originSSLDNSRecordLimit))
			break
		}
		if _, exists := seenName[strings.Join([]string{domain, "www"}, "|")]; exists {
			continue
		}
		key := strings.Join([]string{domain, "www", "CNAME"}, "|")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		seenName[strings.Join([]string{domain, "www"}, "|")] = struct{}{}
		plan.Records = append(plan.Records, OriginSSLDNSRecordPlan{
			AccountLabel: accountLabel,
			Domain:       domain,
			Name:         "www",
			FQDN:         "www." + domain,
			Type:         "CNAME",
			Content:      domain,
			Proxied:      proxied,
			AutoWWW:      true,
		})
	}
	return plan, errs
}

func BuildOriginSSLDNSNamePlan(accountLabel string, sessionID string, domains []string, names []string, recordType string, target string, proxied bool) OriginSSLDNSPlan {
	plan := OriginSSLDNSPlan{
		AccountLabel: accountLabel,
		SessionID:    sessionID,
	}
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	target = strings.TrimSpace(target)
	seen := make(map[string]struct{})
	seenName := make(map[string]struct{})
	rootDomains := make(map[string]struct{})

	appendRecord := func(record OriginSSLDNSRecordPlan) {
		if len(plan.Records) >= originSSLDNSRecordLimit {
			return
		}
		key := strings.Join([]string{record.Domain, record.Name, record.Type}, "|")
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		seenName[strings.Join([]string{record.Domain, record.Name}, "|")] = struct{}{}
		plan.Records = append(plan.Records, record)
	}

	for _, domain := range normalizeOriginSSLSelectedDomains(domains) {
		for _, name := range normalizeOriginSSLDNSNames(names) {
			appendRecord(OriginSSLDNSRecordPlan{
				AccountLabel: accountLabel,
				Domain:       domain,
				Name:         name,
				FQDN:         fqdnFromOriginSSLName(domain, name),
				Type:         recordType,
				Content:      target,
				Proxied:      proxied,
			})
			if name == "@" {
				rootDomains[domain] = struct{}{}
			}
		}
	}

	rootList := make([]string, 0, len(rootDomains))
	for domain := range rootDomains {
		rootList = append(rootList, domain)
	}
	sort.Strings(rootList)
	for _, domain := range rootList {
		if _, exists := seenName[strings.Join([]string{domain, "www"}, "|")]; exists {
			continue
		}
		appendRecord(OriginSSLDNSRecordPlan{
			AccountLabel: accountLabel,
			Domain:       domain,
			Name:         "www",
			FQDN:         "www." + domain,
			Type:         "CNAME",
			Content:      domain,
			Proxied:      proxied,
			AutoWWW:      true,
		})
	}
	return plan
}

func mergeOriginSSLDNSRecords(existing []OriginSSLDNSRecordPlan, next []OriginSSLDNSRecordPlan) []OriginSSLDNSRecordPlan {
	out := make([]OriginSSLDNSRecordPlan, 0, len(existing)+len(next))
	seen := make(map[string]struct{}, len(existing)+len(next))
	appendRecord := func(record OriginSSLDNSRecordPlan) {
		if len(out) >= originSSLDNSRecordLimit {
			return
		}
		key := strings.Join([]string{record.Domain, record.Name, record.Type}, "|")
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, record)
	}
	for _, record := range existing {
		appendRecord(record)
	}
	for _, record := range next {
		appendRecord(record)
	}
	return out
}

func remainingOriginSSLDNSDomains(all []string, selected []string) []string {
	selectedSet := make(map[string]struct{}, len(selected))
	for _, domain := range normalizeOriginSSLSelectedDomains(selected) {
		selectedSet[domain] = struct{}{}
	}
	var remaining []string
	for _, domain := range normalizeOriginSSLSelectedDomains(all) {
		if _, ok := selectedSet[domain]; ok {
			continue
		}
		remaining = append(remaining, domain)
	}
	return remaining
}

func splitOriginSSLFields(input string) []string {
	fields := strings.FieldsFunc(input, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';' || r == '，' || r == '；'
	})
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		out = append(out, field)
	}
	return out
}

func parseOriginSSLDNSNamesOnly(input string) ([]string, bool) {
	fields := splitOriginSSLFields(input)
	if len(fields) == 0 {
		return nil, false
	}
	names := make([]string, 0, len(fields))
	for _, field := range fields {
		name, ok := normalizeOriginSSLDNSName(field)
		if !ok {
			return nil, false
		}
		names = append(names, name)
	}
	return normalizeOriginSSLDNSNames(names), true
}

func normalizeOriginSSLDNSNames(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		normalized, ok := normalizeOriginSSLDNSName(name)
		if !ok {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func normalizeOriginSSLDNSName(input string) (string, bool) {
	name := strings.TrimSpace(strings.ToLower(input))
	name = strings.TrimSuffix(name, ".")
	if name == "@" {
		return "@", true
	}
	if name == "" || strings.Contains(name, ".") || strings.Contains(name, "://") || strings.ContainsAny(name, "/?#[]@") {
		return "", false
	}
	if len(name) > 63 || strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return "", false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return "", false
	}
	return name, true
}

func normalizeOriginSSLHostname(input string) (string, bool) {
	host := strings.TrimSpace(strings.ToLower(input))
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return "", false
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/?#[]@") {
		return "", false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", false
		}
	}
	return host, true
}

func looksLikeIPv4Literal(input string) bool {
	parts := strings.Split(input, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func normalizeOriginSSLSelectedDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		host, ok := normalizeOriginSSLHostname(domain)
		if !ok {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) == len(out[j]) {
			return out[i] < out[j]
		}
		return len(out[i]) > len(out[j])
	})
	return out
}

func matchOriginSSLSelectedDomain(host string, zones []string) (string, string, bool) {
	for _, zone := range zones {
		if host == zone {
			return zone, "@", true
		}
		suffix := "." + zone
		if strings.HasSuffix(host, suffix) {
			name := strings.TrimSuffix(host, suffix)
			if name == "" || strings.Contains(name, "..") {
				return "", "", false
			}
			return zone, name, true
		}
	}
	return "", "", false
}

func fqdnFromOriginSSLName(domain string, name string) string {
	if name == "@" || strings.TrimSpace(name) == "" {
		return domain
	}
	return name + "." + domain
}

func originSSLDomainNames(items []OriginSSLDomainItem) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		name := strings.TrimSpace(strings.ToLower(item.Name))
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	return out
}

func OriginSSLDomainNames(items []OriginSSLDomainItem) []string {
	return originSSLDomainNames(items)
}

func ProcessOriginSSLDomainItems(ctx context.Context, client cfclient.Client, account config.CF, items []OriginSSLDomainItem, awsAliases []string) OriginSSLInteractiveResult {
	result := OriginSSLInteractiveResult{
		AccountLabel: account.Label,
		AWSAliases:   append([]string(nil), awsAliases...),
	}
	if client == nil {
		client = cfclient.NewClient()
	}
	if len(items) == 0 {
		return result
	}
	items = append([]OriginSSLDomainItem(nil), items...)
	sort.SliceStable(items, func(i, j int) bool {
		iActive := strings.EqualFold(strings.TrimSpace(items[i].Status), "active") && !items[i].Paused
		jActive := strings.EqualFold(strings.TrimSpace(items[j].Status), "active") && !items[j].Paused
		if iActive != jActive {
			return iActive
		}
		return items[i].Name < items[j].Name
	})

	cfPacer := newBatchAPIPacerWithInterval(2 * time.Second)
	awsPacer := newBatchAPIPacerWithInterval(2 * time.Second)
	sem := make(chan struct{}, originSSLTaskConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, item := range items {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			domainResult, err := processOriginSSLDomainItem(ctx, client, account, item, cfPacer, awsPacer, awsAliases)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", item.Name, err))
				return
			}
			result.Success = append(result.Success, domainResult)
		}()
	}

	wg.Wait()
	sort.Slice(result.Success, func(i, j int) bool {
		return result.Success[i].Domain < result.Success[j].Domain
	})
	sort.Strings(result.Failed)
	return result
}

func processOriginSSLDomainItem(ctx context.Context, client cfclient.Client, account config.CF, item OriginSSLDomainItem, cfPacer *batchAPIPacer, awsPacer *batchAPIPacer, awsAliases []string) (OriginSSLInteractiveDomainResult, error) {
	zone, err := waitOriginSSLZoneActive(ctx, client, account, item)
	if err != nil {
		return OriginSSLInteractiveDomainResult{}, err
	}

	if err := cfPacer.Wait(ctx); err != nil {
		return OriginSSLInteractiveDomainResult{}, fmt.Errorf("创建 Origin CA 前等待失败: %w", err)
	}
	cert, err := createOriginSSLCertWithRetry(ctx, client, account, item.Name)
	if err != nil {
		return OriginSSLInteractiveDomainResult{}, err
	}

	domainResult := OriginSSLInteractiveDomainResult{
		Domain:       item.Name,
		AccountLabel: account.Label,
		CertID:       cert.ID,
	}

	if err := cfPacer.Wait(ctx); err != nil {
		domainResult.StrictErr = fmt.Errorf("设置 Full(Strict) 前等待失败: %w", err)
	} else {
		domainResult.StrictErr = setOriginSSLStrictWithRetry(ctx, client, account, zone.ID)
	}

	for _, awsAlias := range awsAliases {
		target, ok := config.Cfg.AWSTargets[awsAlias]
		if !ok {
			domainResult.Imports = append(domainResult.Imports, OriginSSLAWSImportResult{
				Alias: awsAlias,
				Err:   fmt.Errorf("未知 AWS 目标别名"),
			})
			continue
		}
		if err := awsPacer.Wait(ctx); err != nil {
			domainResult.Imports = append(domainResult.Imports, OriginSSLAWSImportResult{
				Alias:  awsAlias,
				Region: target.Region,
				Err:    fmt.Errorf("导入 ACM 前等待失败: %w", err),
			})
			continue
		}
		arn, importErr := importToACM(ctx, target, cert.CertificatePEM, cert.PrivateKeyPEM)
		domainResult.Imports = append(domainResult.Imports, OriginSSLAWSImportResult{
			Alias:  awsAlias,
			Region: target.Region,
			ARN:    arn,
			Err:    importErr,
		})
	}

	if err := cfPacer.Wait(ctx); err != nil {
		domainResult.SpeedFailed = append(domainResult.SpeedFailed, "speed settings: "+err.Error())
		return domainResult, nil
	}
	for _, setting := range client.ApplyRecommendedSpeedSettings(ctx, account, zone.ID) {
		if setting.Err != nil {
			domainResult.SpeedFailed = append(domainResult.SpeedFailed, fmt.Sprintf("%s: %v", setting.Name, setting.Err))
			continue
		}
		domainResult.SpeedApplied = append(domainResult.SpeedApplied, setting.Name)
	}

	return domainResult, nil
}

func waitOriginSSLZoneActive(ctx context.Context, client cfclient.Client, account config.CF, item OriginSSLDomainItem) (cfclient.ZoneDetail, error) {
	if strings.EqualFold(strings.TrimSpace(item.Status), "active") && strings.TrimSpace(item.ZoneID) != "" && !item.Paused {
		return cfclient.ZoneDetail{
			ID:     item.ZoneID,
			Name:   item.Name,
			Status: item.Status,
			Paused: item.Paused,
		}, nil
	}

	var lastErr error
	for attempt := 0; attempt < originSSLStatusPollAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(originSSLStatusPollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return cfclient.ZoneDetail{}, ctx.Err()
			case <-timer.C:
			}
		}

		zone, err := client.GetZoneDetails(ctx, account, item.Name)
		if err != nil {
			lastErr = err
			continue
		}
		if strings.EqualFold(strings.TrimSpace(zone.Status), "active") && !zone.Paused {
			return zone, nil
		}
		lastErr = fmt.Errorf("zone status=%s paused=%v", zone.Status, zone.Paused)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("等待 zone active 超时")
	}
	return cfclient.ZoneDetail{}, fmt.Errorf("等待域名 active 超时: %w", lastErr)
}

func createOriginSSLCertWithRetry(ctx context.Context, client cfclient.Client, account config.CF, domain string) (cfclient.OriginCert, error) {
	hostnames := []string{domain, "*." + domain}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		cert, err := client.CreateOriginCertificate(ctx, account, hostnames)
		if err == nil {
			return cert, nil
		}
		lastErr = err
		if !isRetryableCloudflareError(err) || attempt == 2 {
			break
		}
		if err := waitOriginSSLRetry(ctx, attempt); err != nil {
			return cfclient.OriginCert{}, err
		}
	}
	return cfclient.OriginCert{}, fmt.Errorf("创建 Origin CA 失败: %w", lastErr)
}

func setOriginSSLStrictWithRetry(ctx context.Context, client cfclient.Client, account config.CF, zoneID string) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		err := client.SetZoneSSLFullStrict(ctx, account, zoneID)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableCloudflareError(err) || attempt == 2 {
			break
		}
		if err := waitOriginSSLRetry(ctx, attempt); err != nil {
			return err
		}
	}
	return lastErr
}

func ProcessOriginSSLDNSPlan(ctx context.Context, client cfclient.Client, account config.CF, plan OriginSSLDNSPlan) OriginSSLDNSCreateResult {
	result := OriginSSLDNSCreateResult{AccountLabel: account.Label}
	if client == nil {
		client = cfclient.NewClient()
	}

	pacer := newBatchAPIPacerWithInterval(1500 * time.Millisecond)
	for _, record := range plan.Records {
		if err := pacer.Wait(ctx); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: 等待执行失败: %v", record.FQDN, err))
			continue
		}
		if err := upsertOriginSSLDNSRecordWithRetry(ctx, client, account, record); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s %s: %v", record.Type, record.FQDN, err))
			continue
		}
		result.Success = append(result.Success, record)
	}
	return result
}

func upsertOriginSSLDNSRecordWithRetry(ctx context.Context, client cfclient.Client, account config.CF, record OriginSSLDNSRecordPlan) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		_, err := client.UpsertDNSRecord(ctx, account, record.Domain, cfclient.DNSRecordParams{
			Type:    record.Type,
			Name:    record.Name,
			Content: record.Content,
			Proxied: record.Proxied,
			TTL:     3600,
		})
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableCloudflareError(err) || attempt == 2 {
			break
		}
		if err := waitOriginSSLRetry(ctx, attempt); err != nil {
			return err
		}
	}
	return lastErr
}

func waitOriginSSLRetry(ctx context.Context, attempt int) error {
	timer := time.NewTimer(time.Duration(attempt+1) * 3 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (h *CommandHandler) processOriginSSLBatch(req OriginSSLInputRequest, domains []string) originSSLBatchResult {
	result := originSSLBatchResult{
		AWSAliases:    append([]string(nil), req.AWSAliases...),
	}

	accounts := append([]config.CF(nil), h.Accounts...)
	if len(accounts) == 0 {
		result.Failed = append(result.Failed, "未找到可用的 Cloudflare 账号")
		return result
	}

	ctx := context.Background()
	cfPacer := newBatchAPIPacer()
	awsPacer := newBatchAPIPacer()
	for _, domain := range domains {
		acc, zone, err := h.findAccountByDomainInAccounts(ctx, domain, accounts)
		if err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", domain, err))
			continue
		}

		hostnames := []string{domain, "*." + domain}
		if err := cfPacer.Wait(ctx); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: 创建源站证书前等待失败: %v", domain, err))
			continue
		}
		cert, err := h.CFClient.CreateOriginCertificate(ctx, acc, hostnames)
		if err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: 创建源站证书失败: %v", domain, err))
			continue
		}

		domainResult := originSSLDomainResult{
			Domain:       domain,
			AccountLabel: acc.Label,
		}

		if err := cfPacer.Wait(ctx); err != nil {
			domainResult.StrictErr = fmt.Errorf("设置 Full(Strict) 前等待失败: %w", err)
		} else if serr := h.CFClient.SetZoneSSLFullStrict(ctx, acc, zone.ID); serr != nil {
			domainResult.StrictErr = serr
		}

		if err := cfPacer.Wait(ctx); err == nil {
			_ = h.CFClient.ApplyRecommendedSpeedSettings(ctx, acc, zone.ID)
		}

		for _, awsAlias := range req.AWSAliases {
			target, ok := config.Cfg.AWSTargets[awsAlias]
			if !ok {
				domainResult.Imports = append(domainResult.Imports, originSSLImportResult{
					Alias: awsAlias,
					Err:   fmt.Errorf("未知 AWS 目标别名"),
				})
				continue
			}

			if err := awsPacer.Wait(ctx); err != nil {
				domainResult.Imports = append(domainResult.Imports, originSSLImportResult{
					Alias:  awsAlias,
					Region: target.Region,
					Err:    fmt.Errorf("导入 ACM 前等待失败: %w", err),
				})
				continue
			}

			arn, importErr := importToACM(ctx, target, cert.CertificatePEM, cert.PrivateKeyPEM)
			domainResult.Imports = append(domainResult.Imports, originSSLImportResult{
				Alias:  awsAlias,
				Region: target.Region,
				ARN:    arn,
				Err:    importErr,
			})
		}

		result.Success = append(result.Success, domainResult)
	}

	return result
}

func (h *CommandHandler) findAccountByDomainInAccounts(ctx context.Context, domain string, accounts []config.CF) (config.CF, cfclient.ZoneDetail, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return config.CF{}, cfclient.ZoneDetail{}, fmt.Errorf("域名为空")
	}

	type matchedItem struct {
		Account config.CF
		Zone    cfclient.ZoneDetail
	}
	var matches []matchedItem

	for _, acc := range accounts {
		zone, err := h.CFClient.GetZoneDetails(ctx, acc, domain)
		if err != nil {
			if err == cfclient.ErrZoneNotFound || strings.Contains(strings.ToLower(err.Error()), "zone not found") {
				continue
			}
			return config.CF{}, cfclient.ZoneDetail{}, err
		}
		if !strings.EqualFold(strings.TrimSpace(zone.Name), domain) {
			continue
		}
		matches = append(matches, matchedItem{Account: acc, Zone: zone})
	}

	if len(matches) == 0 {
		return config.CF{}, cfclient.ZoneDetail{}, fmt.Errorf("域名 %s 不在任何可用 Cloudflare 账号中", domain)
	}
	if len(matches) > 1 {
		return config.CF{}, cfclient.ZoneDetail{}, fmt.Errorf("域名 %s 在多个 Cloudflare 账号中重复，无法确定唯一来源", domain)
	}
	return matches[0].Account, matches[0].Zone, nil
}

func sortedAWSTargetAliases() []string {
	aliases := make([]string, 0, len(config.Cfg.AWSTargets))
	for alias := range config.Cfg.AWSTargets {
		if strings.TrimSpace(alias) == "" {
			continue
		}
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	return aliases
}

func formatAWSTargets(aliases []string) []string {
	out := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		target, ok := config.Cfg.AWSTargets[alias]
		if !ok {
			out = append(out, alias)
			continue
		}
		out = append(out, fmt.Sprintf("%s(%s)", alias, target.Region))
	}
	return out
}

func (h *CommandHandler) sendOriginSSLResult(result originSSLBatchResult) {
	h.sendText(result.SummaryText())
	h.sendOriginSSLARNOutputs(result)
}

func (h *CommandHandler) sendOriginSSLARNOutputs(result originSSLBatchResult) {
	entries := collectOriginSSLARNEntries(result)
	if len(entries) == 0 {
		return
	}

	if len(entries) > 20 {
		if err := h.sendOriginSSLARNCSV(entries); err != nil {
			h.sendText(fmt.Sprintf("发送 /ssl ARN CSV 失败: %v", err))
		}
	} else {
		h.sendOriginSSLARNMappingBlock(entries)
	}

	h.sendOriginSSLARNCopyBlocks(entries)
}

func collectOriginSSLARNEntries(result originSSLBatchResult) []originSSLARNEntry {
	entries := make([]originSSLARNEntry, 0)
	for _, item := range result.Success {
		for _, imp := range item.Imports {
			if imp.Err != nil || strings.TrimSpace(imp.ARN) == "" {
				continue
			}
			entries = append(entries, originSSLARNEntry{
				Domain:       item.Domain,
				AccountLabel: item.AccountLabel,
				Alias:        imp.Alias,
				Region:       imp.Region,
				ARN:          strings.TrimSpace(imp.ARN),
			})
		}
	}
	return entries
}

func (h *CommandHandler) sendOriginSSLARNMappingBlock(entries []originSSLARNEntry) {
	lines := make([]string, 0, len(entries))
	for _, entry := range entries {
		lines = append(lines, fmt.Sprintf("%s | %s | %s | %s", entry.Domain, entry.Region, entry.Alias, extractARNResourceID(entry.ARN)))
	}
	h.sendOriginSSLPreBlocks("ARN 对照", lines)
}

func (h *CommandHandler) sendOriginSSLARNCopyBlocks(entries []originSSLARNEntry) {
	lines := make([]string, 0, len(entries))
	for i, entry := range entries {
		line := entry.ARN
		if i < len(entries)-1 {
			line += ","
		}
		lines = append(lines, line)
	}
	h.sendOriginSSLPreBlocks("ARN 批量复制", lines)
}

func (h *CommandHandler) sendOriginSSLPreBlocks(title string, lines []string) {
	lines = filterBlankLines(lines)
	if len(lines) == 0 {
		return
	}

	htmlSender, ok := h.Sender.(HTMLSender)
	if !ok {
		h.sendOriginSSLFallbackBlocks(title, lines)
		return
	}

	ctx := context.Background()
	for _, block := range buildOriginSSLHTMLPreBlocks(title, lines) {
		if err := htmlSender.SendHTML(ctx, block); err != nil {
			h.sendOriginSSLFallbackBlocks(title, lines)
			return
		}
	}
}

func (h *CommandHandler) sendOriginSSLFallbackBlocks(title string, lines []string) {
	blocks := buildOriginSSLTextBlocks(title, lines)
	for _, block := range blocks {
		h.sendText(block)
	}
}

func buildOriginSSLHTMLPreBlocks(title string, lines []string) []string {
	return buildOriginSSLBlocks(title, lines, func(title string, body []string) string {
		var sb strings.Builder
		sb.WriteString("<b>" + html.EscapeString(title) + "</b>\n<pre>")
		for i, line := range body {
			if i > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(html.EscapeString(line))
		}
		sb.WriteString("</pre>")
		return sb.String()
	})
}

func buildOriginSSLTextBlocks(title string, lines []string) []string {
	return buildOriginSSLBlocks(title, lines, func(title string, body []string) string {
		var sb strings.Builder
		sb.WriteString(title)
		for _, line := range body {
			sb.WriteString("\n" + line)
		}
		return sb.String()
	})
}

func buildOriginSSLBlocks(title string, lines []string, render func(title string, body []string) string) []string {
	if len(lines) == 0 {
		return nil
	}

	chunks := make([][]string, 0, 1)
	current := make([]string, 0, len(lines))
	for _, line := range lines {
		candidate := append(append([]string(nil), current...), line)
		if len(current) > 0 && len(render(title, candidate)) > tgMaxLen {
			chunks = append(chunks, append([]string(nil), current...))
			current = []string{line}
			continue
		}
		current = candidate
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}

	blocks := make([]string, 0, len(chunks))
	for i, chunk := range chunks {
		chunkTitle := title
		if len(chunks) > 1 {
			chunkTitle = fmt.Sprintf("%s (%d/%d)", title, i+1, len(chunks))
		}
		blocks = append(blocks, render(chunkTitle, chunk))
	}
	return blocks
}

func filterBlankLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func (h *CommandHandler) sendOriginSSLARNCSV(entries []originSSLARNEntry) error {
	csvBytes, filename, err := buildOriginSSLARNCSV(entries)
	if err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp("", "origin-ssl-arn-*.csv")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmpFile.Write(csvBytes); err != nil {
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}

	finalPath := filepath.Join(os.TempDir(), filename)
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err == nil {
		tmpPath = finalPath
	}

	return h.Sender.SendDocumentPath(context.Background(), tmpPath, fmt.Sprintf("📄 /ssl ARN 对照 (%d 条)", len(entries)))
}

func buildOriginSSLARNCSV(entries []originSSLARNEntry) ([]byte, string, error) {
	filename := fmt.Sprintf("origin-ssl-arn-%s.csv", time.Now().Format("20060102-150405"))
	buf := &bytes.Buffer{}
	w := csv.NewWriter(buf)
	w.UseCRLF = false

	if err := w.Write([]string{"域名", "Cloudflare账号", "AWS目标", "区域", "ARN_ID", "ARN尾段", "完整ARN"}); err != nil {
		return nil, "", err
	}

	for _, entry := range entries {
		if err := w.Write([]string{
			entry.Domain,
			entry.AccountLabel,
			entry.Alias,
			entry.Region,
			extractARNResourceID(entry.ARN),
			extractARNTail(entry.ARN),
			entry.ARN,
		}); err != nil {
			return nil, "", err
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, "", err
	}

	return buf.Bytes(), filename, nil
}

func extractARNResourceID(arn string) string {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return ""
	}
	if idx := strings.LastIndex(arn, "/"); idx >= 0 && idx < len(arn)-1 {
		return arn[idx+1:]
	}
	if idx := strings.LastIndex(arn, ":"); idx >= 0 && idx < len(arn)-1 {
		return arn[idx+1:]
	}
	return arn
}

func extractARNTail(arn string) string {
	id := extractARNResourceID(arn)
	if idx := strings.LastIndex(id, "-"); idx >= 0 && idx < len(id)-1 {
		return id[idx+1:]
	}
	return id
}

func (h *CommandHandler) originSSLPromptText() string {
	if len(h.Accounts) == 0 {
		return "未配置可用的 Cloudflare 账号，无法生成源站证书。"
	}

	var sb strings.Builder
	sb.WriteString("/ssl 交互流程会先选择 Cloudflare 账号，再从该账号已有域名中分页选择。\n")
	sb.WriteString("确认后可后台创建 Origin CA 证书、设置 Full(Strict)、启用可用加速建议，并可继续创建 DNS 解析。\n\n")
	sb.WriteString("兼容直接命令：/ssl example.com example.net aws-alias\n\n")
	sb.WriteString("请选择目标 Cloudflare 账号：\n")
	for _, acc := range h.Accounts {
		if strings.TrimSpace(acc.Label) == "" {
			continue
		}
		sb.WriteString("- " + acc.Label + "\n")
	}
	return sb.String()
}

func importToACM(ctx context.Context, target config.AWSTarget, certPEM, keyPEM string) (string, error) {
	if strings.TrimSpace(target.Region) == "" {
		return "", fmt.Errorf("aws target region 为空")
	}
	if strings.TrimSpace(target.Creds.AccessKeyID) == "" || strings.TrimSpace(target.Creds.SecretAccessKey) == "" {
		return "", fmt.Errorf("aws target creds 不完整")
	}

	cfg, err := awscfg.LoadDefaultConfig(
		ctx,
		awscfg.WithRegion(target.Region),
		awscfg.WithCredentialsProvider(
			aws.NewCredentialsCache(
				credentials.NewStaticCredentialsProvider(
					target.Creds.AccessKeyID,
					target.Creds.SecretAccessKey,
					target.Creds.SessionToken,
				),
			),
		),
	)
	if err != nil {
		return "", fmt.Errorf("load aws config: %w", err)
	}

	client := acm.NewFromConfig(cfg)

	certBody := []byte(strings.TrimSpace(certPEM) + "\n")
	privKey := []byte(strings.TrimSpace(keyPEM) + "\n")

	out, err := client.ImportCertificate(ctx, &acm.ImportCertificateInput{
		Certificate: certBody,
		PrivateKey:  privKey,
	})
	if err != nil {
		return "", fmt.Errorf("acm import certificate: %w", err)
	}
	return *out.CertificateArn, nil
}
