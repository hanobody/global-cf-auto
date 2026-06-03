package telegram

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"DomainC/cfclient"
	"DomainC/config"
)

const (
	cfIPBlockPerAccountInterval = 2 * time.Second
	cfIPBlockMaxFailureLines    = 80
)

type cloudflareAccountIPBlockManager interface {
	ListZones(ctx context.Context, account config.CF) ([]cfclient.ZoneDetail, error)
	EnsureIPBlockRule(ctx context.Context, account config.CF, zoneID string, values []string) (string, error)
	DeleteIPBlockRule(ctx context.Context, account config.CF, zoneID string, values []string) (string, error)
	ClearIPBlockRule(ctx context.Context, account config.CF, zoneID string) (string, error)
	DeleteAccountIPAccessRules(ctx context.Context, account config.CF, values []string) (cfclient.AccountIPAccessRuleDeleteResult, error)
	ClearAccountIPAccessRulesByNote(ctx context.Context, account config.CF, note string) (cfclient.AccountIPAccessRuleDeleteResult, error)
}

type cfIPBlockAccountResult struct {
	AccountLabel  string
	Processed     int
	Created       int
	Updated       int
	AlreadyExists int
	Deleted       int
	NotFound      int
	Skipped       int
	Failed        []string
}

type cfIPBlockBatchResult struct {
	Action   string
	Values   []string
	Accounts []cfIPBlockAccountResult
	Failed   []string
}

type cfIPAccessAccountResult struct {
	AccountLabel string
	Matched      int
	Deleted      int
	NotFound     int
	Failed       []string
}

type cfIPAccessBatchResult struct {
	Action   string
	Values   []string
	Accounts []cfIPAccessAccountResult
	Failed   []string
}

func (h *CommandHandler) handleCFIPBlockCommand(args []string) {
	if len(h.Accounts) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法设置 WAF IP 黑名单。")
		return
	}
	manager, ok := h.CFClient.(cloudflareAccountIPBlockManager)
	if !ok {
		h.sendText("当前 Cloudflare 客户端不支持 WAF IP 黑名单管理。")
		return
	}
	scope, scopedArgs := splitCFIPBlockScope(args)
	if scope == "account" {
		action, values, err := parseCFIPAccessArgs(scopedArgs)
		if err != nil {
			h.sendText(err.Error() + "\n\n" + cfIPBlockUsage())
			return
		}
		accounts := append([]config.CF(nil), h.Accounts...)
		go func() {
			result := processCFIPAccessAllAccounts(context.Background(), manager, accounts, action, values)
			h.sendText(result.Summary())
		}()
		h.sendText(fmt.Sprintf("Cloudflare 账号级 IP 访问规则任务已提交：动作 %s，账号 %d，目标 %s。",
			action, len(accounts), cfIPAccessTargetLabel(action, values)))
		return
	}
	args = scopedArgs
	action, values, err := parseCFIPBlockArgs(args)
	if err != nil {
		h.sendText(err.Error() + "\n\n" + cfIPBlockUsage())
		return
	}
	accounts := append([]config.CF(nil), h.Accounts...)
	go func() {
		result := processCFIPBlockAllAccounts(context.Background(), manager, accounts, action, values)
		h.sendText(result.Summary())
	}()
	h.sendText(fmt.Sprintf("Cloudflare WAF IP 黑名单任务已提交：动作 %s，账号 %d，目标 %s。\n账号之间并发执行，每个账号内部限速 %s/域名。",
		action, len(accounts), cfIPBlockTargetLabel(action, values), cfIPBlockPerAccountInterval))
}

func parseCFIPBlockArgs(args []string) (string, []string, error) {
	if len(args) < 1 {
		return "", nil, fmt.Errorf("参数不足")
	}
	action := normalizeCFIPBlockAction(args[0])
	if action == "" {
		return "", nil, fmt.Errorf("action 必须是 add/delete/clear")
	}
	if action == "clear" || (action == "delete" && len(args) >= 2 && isCFIPBlockClearTargetArg(args[1])) {
		return "clear", nil, nil
	}
	if len(args) < 2 {
		return "", nil, fmt.Errorf("参数不足")
	}
	values, err := parseCFIPBlockValues(args[1:])
	if err != nil {
		return "", nil, err
	}
	if len(values) == 0 {
		return "", nil, fmt.Errorf("至少需要一个 IP 地址或支持的 CIDR")
	}
	return action, values, nil
}

func normalizeCFIPBlockAction(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "add", "create", "enable", "on", "block":
		return "add"
	case "delete", "del", "remove", "rm", "disable", "off", "unblock":
		return "delete"
	case "clear", "clean", "reset", "delete_all", "delete_rule", "clear_rule", "清空":
		return "clear"
	default:
		return ""
	}
}

func splitCFIPBlockScope(args []string) (string, []string) {
	if len(args) > 0 && isCFIPBlockAllAccountsArg(args[0]) {
		args = args[1:]
	}
	if len(args) > 0 && isCFIPAccessScopeArg(args[0]) {
		return "account", args[1:]
	}
	return "zone", args
}

func isCFIPAccessScopeArg(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "account", "access", "access_rule", "access_rules", "ip_access", "ipaccess", "account_access", "账号级":
		return true
	default:
		return false
	}
}

func isCFIPBlockClearTargetArg(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "all", "*", "rule", "rules", "list", "blacklist", "全部", "全部规则", "列表":
		return true
	default:
		return false
	}
}

func isCFIPBlockAllAccountsArg(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "all", "*", "accounts", "all_accounts", "allaccounts", "全部", "全部账号", "所有账号":
		return true
	default:
		return false
	}
}

func parseCFIPBlockValues(args []string) ([]string, error) {
	var raw []string
	for _, arg := range args {
		for _, field := range strings.FieldsFunc(arg, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
		}) {
			field = strings.TrimSpace(field)
			if field != "" {
				raw = append(raw, field)
			}
		}
	}
	return cfclient.NormalizeIPAccessRuleValues(raw)
}

func cfIPBlockUsage() string {
	return "用法：\n/cf_ipblock add 1.2.3.4,5.6.7.8\n/cf_ipblock delete 1.2.3.4\n/cf_ipblock clear\n/cf_ipblock access clear\n/cf_ipblock access delete 1.2.3.4\n\n说明：默认操作每个域名的 Zone WAF 自定义规则 telegram-auto-block-ips。access 操作 Cloudflare 账号级 IP 访问规则，只删除备注为 telegram-auto-ip-blacklist 的规则。"
}

func parseCFIPAccessArgs(args []string) (string, []string, error) {
	if len(args) < 1 {
		return "", nil, fmt.Errorf("参数不足")
	}
	action := normalizeCFIPBlockAction(args[0])
	if action == "" {
		return "", nil, fmt.Errorf("账号级 action 必须是 delete/clear")
	}
	if action == "add" {
		return "", nil, fmt.Errorf("账号级 IP 访问规则当前只支持 delete/clear")
	}
	if action == "clear" || (action == "delete" && len(args) >= 2 && isCFIPBlockClearTargetArg(args[1])) {
		return "clear", nil, nil
	}
	if len(args) < 2 {
		return "", nil, fmt.Errorf("参数不足")
	}
	values, err := parseCFIPBlockValues(args[1:])
	if err != nil {
		return "", nil, err
	}
	if len(values) == 0 {
		return "", nil, fmt.Errorf("至少需要一个 IP 地址或支持的 CIDR")
	}
	return "delete", values, nil
}

func cfIPBlockTargetLabel(action string, values []string) string {
	if action == "clear" {
		return "整条自动规则"
	}
	return fmt.Sprintf("IP/IP段 %d", len(values))
}

func cfIPAccessTargetLabel(action string, values []string) string {
	if action == "clear" {
		return "备注 " + cfclient.AccountIPAccessRuleNote
	}
	return fmt.Sprintf("IP/IP段 %d", len(values))
}

func processCFIPAccessAllAccounts(ctx context.Context, manager cloudflareAccountIPBlockManager, accounts []config.CF, action string, values []string) cfIPAccessBatchResult {
	result := cfIPAccessBatchResult{
		Action: action,
		Values: append([]string(nil), values...),
	}
	ch := make(chan cfIPAccessAccountResult, len(accounts))
	var wg sync.WaitGroup
	for _, account := range accounts {
		account := account
		if strings.TrimSpace(account.Label) == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch <- processCFIPAccessAccount(ctx, manager, account, action, values)
		}()
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	for accountResult := range ch {
		result.Accounts = append(result.Accounts, accountResult)
		for _, item := range accountResult.Failed {
			result.Failed = append(result.Failed, accountResult.AccountLabel+": "+item)
		}
	}
	sort.Slice(result.Accounts, func(i, j int) bool { return result.Accounts[i].AccountLabel < result.Accounts[j].AccountLabel })
	sort.Strings(result.Failed)
	return result
}

func processCFIPAccessAccount(ctx context.Context, manager cloudflareAccountIPBlockManager, account config.CF, action string, values []string) cfIPAccessAccountResult {
	result := cfIPAccessAccountResult{AccountLabel: account.Label}
	var deleteResult cfclient.AccountIPAccessRuleDeleteResult
	var err error
	if action == "clear" {
		deleteResult, err = manager.ClearAccountIPAccessRulesByNote(ctx, account, cfclient.AccountIPAccessRuleNote)
	} else {
		deleteResult, err = manager.DeleteAccountIPAccessRules(ctx, account, values)
	}
	if err != nil {
		result.Failed = append(result.Failed, formatCFIPAccessPermissionError(err))
		return result
	}
	result.Matched = deleteResult.Matched
	result.Deleted = deleteResult.Deleted
	result.NotFound = deleteResult.NotFound
	for _, item := range deleteResult.Failed {
		result.Failed = append(result.Failed, formatCFIPAccessPermissionError(errors.New(item)))
	}
	sort.Strings(result.Failed)
	return result
}

func formatCFIPAccessPermissionError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "authentication") || strings.Contains(lower, "not authorized") || strings.Contains(lower, "permission") {
		return "missing_permission: API Token 缺少账号级 IP Access Rules/Firewall 编辑权限；可在 Cloudflare 控制台手工删除，或给 Token 补权限后重试: " + msg
	}
	return msg
}

func processCFIPBlockAllAccounts(ctx context.Context, manager cloudflareAccountIPBlockManager, accounts []config.CF, action string, values []string) cfIPBlockBatchResult {
	result := cfIPBlockBatchResult{
		Action: action,
		Values: append([]string(nil), values...),
	}
	ch := make(chan cfIPBlockAccountResult, len(accounts))
	var wg sync.WaitGroup
	for _, account := range accounts {
		account := account
		if strings.TrimSpace(account.Label) == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch <- processCFIPBlockAccount(ctx, manager, account, action, values)
		}()
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	for accountResult := range ch {
		result.Accounts = append(result.Accounts, accountResult)
		for _, item := range accountResult.Failed {
			result.Failed = append(result.Failed, accountResult.AccountLabel+": "+item)
		}
	}
	sort.Slice(result.Accounts, func(i, j int) bool { return result.Accounts[i].AccountLabel < result.Accounts[j].AccountLabel })
	sort.Strings(result.Failed)
	return result
}

func processCFIPBlockAccount(ctx context.Context, manager cloudflareAccountIPBlockManager, account config.CF, action string, values []string) cfIPBlockAccountResult {
	result := cfIPBlockAccountResult{AccountLabel: account.Label}
	zones, err := manager.ListZones(ctx, account)
	if err != nil {
		result.Failed = append(result.Failed, "读取域名失败: "+err.Error())
		return result
	}
	pacer := newBatchAPIPacerWithInterval(cfIPBlockPerAccountInterval)
	for _, zone := range zones {
		zoneID := strings.TrimSpace(zone.ID)
		name := strings.TrimSpace(zone.Name)
		if zoneID == "" {
			result.Failed = append(result.Failed, name+": 缺少 zone_id")
			continue
		}
		if err := pacer.Wait(ctx); err != nil {
			result.Failed = append(result.Failed, name+": 等待执行失败: "+err.Error())
			continue
		}
		var status string
		var err error
		if action == "clear" {
			status, err = manager.ClearIPBlockRule(ctx, account, zoneID)
		} else if action == "delete" {
			status, err = manager.DeleteIPBlockRule(ctx, account, zoneID, values)
		} else {
			status, err = manager.EnsureIPBlockRule(ctx, account, zoneID, values)
		}
		if err != nil {
			result.Failed = append(result.Failed, name+": "+err.Error())
			continue
		}
		result.Processed++
		switch status {
		case "created":
			result.Created++
		case "updated":
			result.Updated++
		case "already_exists":
			result.AlreadyExists++
		case "deleted":
			result.Deleted++
		case "not_found":
			result.NotFound++
		case "skipped":
			result.Skipped++
		default:
			result.Updated++
		}
	}
	sort.Strings(result.Failed)
	return result
}

func (r cfIPBlockBatchResult) Summary() string {
	var created, updated, existing, deleted, notFound, skipped int
	for _, account := range r.Accounts {
		created += account.Created
		updated += account.Updated
		existing += account.AlreadyExists
		deleted += account.Deleted
		notFound += account.NotFound
		skipped += account.Skipped
	}
	var sb strings.Builder
	processed := 0
	for _, account := range r.Accounts {
		processed += account.Processed
	}
	sb.WriteString(fmt.Sprintf("Cloudflare WAF IP 黑名单完成\n动作: %s\n账号: %d\n目标: %s\n已处理域名:%d\ncreated:%d updated:%d already_exists:%d deleted:%d not_found:%d skipped:%d failed:%d",
		r.Action, len(r.Accounts), cfIPBlockTargetLabel(r.Action, r.Values), processed, created, updated, existing, deleted, notFound, skipped, len(r.Failed)))
	for _, account := range r.Accounts {
		sb.WriteString(fmt.Sprintf("\n- %s | domains:%d created:%d updated:%d exists:%d deleted:%d not_found:%d failed:%d",
			account.AccountLabel, account.Processed, account.Created, account.Updated, account.AlreadyExists, account.Deleted, account.NotFound, len(account.Failed)))
	}
	if len(r.Failed) > 0 {
		sb.WriteString("\n\n失败明细:")
		limit := len(r.Failed)
		if limit > cfIPBlockMaxFailureLines {
			limit = cfIPBlockMaxFailureLines
		}
		for _, item := range r.Failed[:limit] {
			sb.WriteString("\n- " + item)
		}
		if len(r.Failed) > limit {
			sb.WriteString(fmt.Sprintf("\n- 还有 %d 条失败明细未显示，请分批重试或查看日志。", len(r.Failed)-limit))
		}
	}
	return sb.String()
}

func (r cfIPAccessBatchResult) Summary() string {
	var matched, deleted, notFound int
	for _, account := range r.Accounts {
		matched += account.Matched
		deleted += account.Deleted
		notFound += account.NotFound
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Cloudflare 账号级 IP 访问规则完成\n动作: %s\n账号: %d\n目标: %s\nmatched:%d deleted:%d not_found:%d failed:%d\n备注:%s",
		r.Action, len(r.Accounts), cfIPAccessTargetLabel(r.Action, r.Values), matched, deleted, notFound, len(r.Failed), cfclient.AccountIPAccessRuleNote))
	for _, account := range r.Accounts {
		sb.WriteString(fmt.Sprintf("\n- %s | matched:%d deleted:%d not_found:%d failed:%d",
			account.AccountLabel, account.Matched, account.Deleted, account.NotFound, len(account.Failed)))
	}
	if len(r.Failed) > 0 {
		sb.WriteString("\n\n失败明细:")
		limit := len(r.Failed)
		if limit > cfIPBlockMaxFailureLines {
			limit = cfIPBlockMaxFailureLines
		}
		for _, item := range r.Failed[:limit] {
			sb.WriteString("\n- " + item)
		}
		if len(r.Failed) > limit {
			sb.WriteString(fmt.Sprintf("\n- 还有 %d 条失败明细未显示，请分批重试或查看日志。", len(r.Failed)-limit))
		}
	}
	return sb.String()
}
