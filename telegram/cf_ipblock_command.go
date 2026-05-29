package telegram

import (
	"context"
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
	EnsureAccountIPAccessBlockRule(ctx context.Context, account config.CF, value string) (string, error)
	DeleteAccountIPAccessBlockRule(ctx context.Context, account config.CF, value string) (string, error)
}

type cfIPBlockAccountResult struct {
	AccountLabel  string
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

func (h *CommandHandler) handleCFIPBlockCommand(args []string) {
	if len(h.Accounts) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法设置账号级 IP 黑名单。")
		return
	}
	action, values, err := parseCFIPBlockArgs(args)
	if err != nil {
		h.sendText(err.Error() + "\n\n" + cfIPBlockUsage())
		return
	}
	manager, ok := h.CFClient.(cloudflareAccountIPBlockManager)
	if !ok {
		h.sendText("当前 Cloudflare 客户端不支持账号级 IP 黑名单管理。")
		return
	}
	accounts := append([]config.CF(nil), h.Accounts...)
	go func() {
		result := processCFIPBlockAllAccounts(context.Background(), manager, accounts, action, values)
		h.sendText(result.Summary())
	}()
	h.sendText(fmt.Sprintf("Cloudflare 账号级 IP 黑名单任务已提交：动作 %s，账号 %d，IP/IP段 %d。\n账号之间并发执行，每个账号内部限速 %s/条。",
		action, len(accounts), len(values), cfIPBlockPerAccountInterval))
}

func parseCFIPBlockArgs(args []string) (string, []string, error) {
	if len(args) > 0 && isCFIPBlockAllAccountsArg(args[0]) {
		args = args[1:]
	}
	if len(args) < 2 {
		return "", nil, fmt.Errorf("参数不足")
	}
	action := normalizeCFIPBlockAction(args[0])
	if action == "" {
		return "", nil, fmt.Errorf("action 必须是 add/delete")
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
	default:
		return ""
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
	return "用法：\n/cf_ipblock add 1.2.3.4,5.6.7.8\n/cf_ipblock delete 1.2.3.4\n/cf_ipblock all add 1.2.3.4\n\n说明：该命令默认对所有已配置 Cloudflare 账号创建账号级 block IP Access Rule，作用于账号下所有域名。"
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
	pacer := newBatchAPIPacerWithInterval(cfIPBlockPerAccountInterval)
	for _, value := range values {
		if err := pacer.Wait(ctx); err != nil {
			result.Failed = append(result.Failed, value+": 等待执行失败: "+err.Error())
			continue
		}
		var status string
		var err error
		if action == "delete" {
			status, err = manager.DeleteAccountIPAccessBlockRule(ctx, account, value)
		} else {
			status, err = manager.EnsureAccountIPAccessBlockRule(ctx, account, value)
		}
		if err != nil {
			result.Failed = append(result.Failed, value+": "+err.Error())
			continue
		}
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
	sb.WriteString(fmt.Sprintf("Cloudflare 账号级 IP 黑名单完成\n动作: %s\n账号: %d\nIP/IP段: %d\ncreated:%d updated:%d already_exists:%d deleted:%d not_found:%d skipped:%d failed:%d",
		r.Action, len(r.Accounts), len(r.Values), created, updated, existing, deleted, notFound, skipped, len(r.Failed)))
	for _, account := range r.Accounts {
		sb.WriteString(fmt.Sprintf("\n- %s | created:%d updated:%d exists:%d deleted:%d not_found:%d failed:%d",
			account.AccountLabel, account.Created, account.Updated, account.AlreadyExists, account.Deleted, account.NotFound, len(account.Failed)))
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
