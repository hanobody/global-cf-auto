package telegram

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"DomainC/cfclient"
	"DomainC/config"
)

const cfRulesItemsPerPage = 8

type CFRulesDomainItem struct {
	Key          string
	AccountLabel string
	ZoneID       string
	Name         string
	Status       string
	Plan         string
}

type CFRulesSelection struct {
	AccountLabel string
	Items        []CFRulesDomainItem
	Selected     map[string]bool
	Page         int
}

type CFRulesCallbackPayload struct {
	AccountLabel string
	SessionID    string
	ItemKey      string
	Page         int
	Action       string
	Feature      string
}

type CFRulesBatchResult struct {
	AccountLabel string
	Action       string
	Feature      string
	Success      []cfclient.FeatureManageResult
	Failed       []string
}

type cloudflareFeatureManager interface {
	ManageZoneFeatures(ctx context.Context, account config.CF, domain string, zoneID string, opts cfclient.FeatureManageOptions) cfclient.FeatureManageResult
}

var cfRulesState = struct {
	mu        sync.Mutex
	callbacks map[string]CFRulesCallbackPayload
	sessions  map[string]CFRulesSelection
}{
	callbacks: make(map[string]CFRulesCallbackPayload),
	sessions:  make(map[string]CFRulesSelection),
}

func (h *CommandHandler) handleCFRulesCommand(args []string) {
	if len(h.Accounts) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法检查规则。")
		return
	}
	if len(args) == 0 {
		h.sendCFRulesAccountSelector()
		return
	}

	account := h.getAccountByLabel(args[0])
	if account == nil {
		h.sendText("未找到 Cloudflare 账号：" + args[0])
		return
	}
	if len(args) == 1 {
		h.sendText(fmt.Sprintf("正在读取账号 %s 下所有域名，请稍候。", account.Label))
		if err := BeginCFRulesDomainSelection(context.Background(), h.CFClient, h.Sender, *account); err != nil {
			h.sendText(fmt.Sprintf("读取域名失败: %v", err))
		}
		return
	}

	domain, err := extractDomainOrHost(args[1])
	if err != nil && !strings.EqualFold(args[1], "all") {
		h.sendText(fmt.Sprintf("%s: %v", args[1], err))
		return
	}
	action := "enable"
	feature := "all"
	for _, arg := range args[2:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "action":
			action = normalizeCFRulesAction(value)
			if action == "" {
				h.sendText("action 参数必须是 enable/update/on 或 disable/delete/off")
				return
			}
		case "feature":
			feature = normalizeCFRulesFeature(value)
			if feature == "" {
				h.sendText("feature 参数必须是 all/security/speed/cache")
				return
			}
		}
	}

	zones, err := h.CFClient.ListZoneSummaries(context.Background(), *account)
	if err != nil {
		h.sendText(fmt.Sprintf("读取域名失败: %v", err))
		return
	}
	items := buildCFRulesDomainItems(account.Label, zones)
	if !strings.EqualFold(args[1], "all") {
		items = filterCFRulesDomainItems(items, domain)
	}
	if len(items) == 0 {
		h.sendText("没有匹配的域名。")
		return
	}
	go func() {
		result := ProcessCFRulesItems(context.Background(), h.CFClient, *account, items, action, feature, config.DefaultBlockCountries())
		h.sendText(result.Summary())
	}()
	h.sendText(fmt.Sprintf("Cloudflare 规则检查任务已提交：账号 %s，域名 %d，动作 %s，功能 %s", account.Label, len(items), action, feature))
}

func (h *CommandHandler) sendCFRulesAccountSelector() {
	var buttons [][]Button
	for _, acc := range h.Accounts {
		label := strings.TrimSpace(acc.Label)
		if label == "" {
			continue
		}
		token := SetCFRulesCallbackPayload(CFRulesCallbackPayload{AccountLabel: label})
		buttons = append(buttons, []Button{{
			Text:         label,
			CallbackData: fmt.Sprintf("cfrules_account|%s", token),
		}})
	}
	if err := h.Sender.SendWithButtons(context.Background(), "请选择要检查规则的 Cloudflare 账号：", buttons); err != nil {
		h.sendText(fmt.Sprintf("发送账号选择失败: %v", err))
	}
}

func SetCFRulesCallbackPayload(payload CFRulesCallbackPayload) string {
	token := newInteractionToken()
	cfRulesState.mu.Lock()
	defer cfRulesState.mu.Unlock()
	cfRulesState.callbacks[token] = payload
	return token
}

func GetCFRulesCallbackPayload(token string) (CFRulesCallbackPayload, bool) {
	cfRulesState.mu.Lock()
	defer cfRulesState.mu.Unlock()
	payload, ok := cfRulesState.callbacks[token]
	return payload, ok
}

func SetCFRulesSelection(selection CFRulesSelection) string {
	sessionID := newInteractionToken()
	cfRulesState.mu.Lock()
	defer cfRulesState.mu.Unlock()
	cfRulesState.sessions[sessionID] = cloneCFRulesSelection(selection)
	return sessionID
}

func GetCFRulesSelection(sessionID string) (CFRulesSelection, bool) {
	cfRulesState.mu.Lock()
	defer cfRulesState.mu.Unlock()
	selection, ok := cfRulesState.sessions[sessionID]
	if !ok {
		return CFRulesSelection{}, false
	}
	return cloneCFRulesSelection(selection), true
}

func ToggleCFRulesSelectionItem(sessionID string, key string) (CFRulesSelection, bool) {
	cfRulesState.mu.Lock()
	defer cfRulesState.mu.Unlock()
	selection, ok := cfRulesState.sessions[sessionID]
	if !ok {
		return CFRulesSelection{}, false
	}
	if selection.Selected == nil {
		selection.Selected = make(map[string]bool)
	}
	if selection.Selected[key] {
		delete(selection.Selected, key)
	} else {
		selection.Selected[key] = true
	}
	cfRulesState.sessions[sessionID] = selection
	return cloneCFRulesSelection(selection), true
}

func SelectAllCFRulesDomains(sessionID string) (CFRulesSelection, bool) {
	cfRulesState.mu.Lock()
	defer cfRulesState.mu.Unlock()
	selection, ok := cfRulesState.sessions[sessionID]
	if !ok {
		return CFRulesSelection{}, false
	}
	if selection.Selected == nil {
		selection.Selected = make(map[string]bool)
	}
	for _, item := range selection.Items {
		selection.Selected[item.Key] = true
	}
	cfRulesState.sessions[sessionID] = selection
	return cloneCFRulesSelection(selection), true
}

func SetCFRulesSelectionPage(sessionID string, page int) (CFRulesSelection, bool) {
	cfRulesState.mu.Lock()
	defer cfRulesState.mu.Unlock()
	selection, ok := cfRulesState.sessions[sessionID]
	if !ok {
		return CFRulesSelection{}, false
	}
	selection.Page = page
	cfRulesState.sessions[sessionID] = selection
	return cloneCFRulesSelection(selection), true
}

func SelectedCFRulesDomainItems(sessionID string) ([]CFRulesDomainItem, bool) {
	selection, ok := GetCFRulesSelection(sessionID)
	if !ok {
		return nil, false
	}
	items := make([]CFRulesDomainItem, 0, len(selection.Selected))
	for _, item := range selection.Items {
		if selection.Selected[item.Key] {
			items = append(items, item)
		}
	}
	return items, true
}

func ClearCFRulesSelection(sessionID string) {
	cfRulesState.mu.Lock()
	defer cfRulesState.mu.Unlock()
	delete(cfRulesState.sessions, sessionID)
}

func cloneCFRulesSelection(selection CFRulesSelection) CFRulesSelection {
	out := CFRulesSelection{
		AccountLabel: selection.AccountLabel,
		Items:        append([]CFRulesDomainItem(nil), selection.Items...),
		Selected:     make(map[string]bool, len(selection.Selected)),
		Page:         selection.Page,
	}
	for key, selected := range selection.Selected {
		out.Selected[key] = selected
	}
	return out
}

func BeginCFRulesDomainSelection(ctx context.Context, client cfclient.Client, sender Sender, account config.CF) error {
	zones, err := client.ListZoneSummaries(ctx, account)
	if err != nil {
		return err
	}
	items := buildCFRulesDomainItems(account.Label, zones)
	if len(items) == 0 {
		return sender.Send(ctx, fmt.Sprintf("账号 %s 暂无域名。", account.Label))
	}
	sessionID := SetCFRulesSelection(CFRulesSelection{
		AccountLabel: account.Label,
		Items:        items,
		Selected:     make(map[string]bool),
	})
	selection, _ := GetCFRulesSelection(sessionID)
	page := BuildCFRulesDomainSelectionView(sessionID, selection)
	return sender.SendWithButtons(ctx, page.Message, page.Buttons)
}

func buildCFRulesDomainItems(accountLabel string, zones []cfclient.ZoneSummary) []CFRulesDomainItem {
	items := make([]CFRulesDomainItem, 0, len(zones))
	for _, zone := range zones {
		name := strings.TrimSpace(strings.ToLower(zone.Name))
		if name == "" {
			continue
		}
		key := strings.TrimSpace(zone.ID)
		if key == "" {
			key = name
		}
		items = append(items, CFRulesDomainItem{
			Key:          key,
			AccountLabel: accountLabel,
			ZoneID:       zone.ID,
			Name:         name,
			Status:       zone.Status,
			Plan:         zone.Plan,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items
}

func filterCFRulesDomainItems(items []CFRulesDomainItem, domain string) []CFRulesDomainItem {
	out := make([]CFRulesDomainItem, 0, 1)
	for _, item := range items {
		if strings.EqualFold(item.Name, domain) {
			out = append(out, item)
		}
	}
	return out
}

func BuildCFRulesDomainSelectionView(sessionID string, selection CFRulesSelection) IPListPage {
	totalPages := pageCount(len(selection.Items), cfRulesItemsPerPage)
	page := clampPage(selection.Page, totalPages)
	start := page * cfRulesItemsPerPage
	end := start + cfRulesItemsPerPage
	if end > len(selection.Items) {
		end = len(selection.Items)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("【Cloudflare 规则检查】\n账号: %s\n页码: %d/%d\n已选择: %d/%d\n\n",
		selection.AccountLabel, page+1, totalPages, countSelected(selection.Selected), len(selection.Items)))
	for i := start; i < end; i++ {
		item := selection.Items[i]
		sb.WriteString(fmt.Sprintf("%d. %s | %s | %s\n", i+1, item.Name, normalizeDisplayValue(item.Status), normalizeDisplayValue(item.Plan)))
	}

	var buttons [][]Button
	for i := start; i < end; i++ {
		item := selection.Items[i]
		mark := "☐"
		if selection.Selected[item.Key] {
			mark = "☑"
		}
		token := SetCFRulesCallbackPayload(CFRulesCallbackPayload{
			AccountLabel: selection.AccountLabel,
			SessionID:    sessionID,
			ItemKey:      item.Key,
			Page:         page,
		})
		buttons = append(buttons, []Button{{
			Text:         fmt.Sprintf("%s %d. %s", mark, i+1, truncateDisplay(item.Name, 36)),
			CallbackData: fmt.Sprintf("cfrules_toggle|%s", token),
		}})
	}
	var nav []Button
	if page > 0 {
		token := SetCFRulesCallbackPayload(CFRulesCallbackPayload{AccountLabel: selection.AccountLabel, SessionID: sessionID, Page: page - 1})
		nav = append(nav, Button{Text: "上一页", CallbackData: fmt.Sprintf("cfrules_page|%s", token)})
	}
	if page+1 < totalPages {
		token := SetCFRulesCallbackPayload(CFRulesCallbackPayload{AccountLabel: selection.AccountLabel, SessionID: sessionID, Page: page + 1})
		nav = append(nav, Button{Text: "下一页", CallbackData: fmt.Sprintf("cfrules_page|%s", token)})
	}
	if len(nav) > 0 {
		buttons = append(buttons, nav)
	}
	token := SetCFRulesCallbackPayload(CFRulesCallbackPayload{AccountLabel: selection.AccountLabel, SessionID: sessionID})
	buttons = append(buttons, []Button{
		{Text: "全选", CallbackData: fmt.Sprintf("cfrules_all|%s", token)},
		{Text: "确认选择", CallbackData: fmt.Sprintf("cfrules_done|%s", token)},
		{Text: "取消", CallbackData: fmt.Sprintf("cfrules_cancel|%s", token)},
	})
	return IPListPage{Message: sb.String(), Buttons: buttons}
}

func BuildCFRulesActionView(sessionID string, items []CFRulesDomainItem) IPListPage {
	accountLabel := ""
	if len(items) > 0 {
		accountLabel = items[0].AccountLabel
	}
	msg := fmt.Sprintf("已选择账号 %s 的 %d 个域名。\n请选择要异步检查并执行的功能：", accountLabel, len(items))
	token := func(action string, feature string) string {
		return SetCFRulesCallbackPayload(CFRulesCallbackPayload{
			AccountLabel: accountLabel,
			SessionID:    sessionID,
			Action:       action,
			Feature:      feature,
		})
	}
	return IPListPage{
		Message: msg,
		Buttons: [][]Button{
			{
				{Text: "开启/更新全部", CallbackData: fmt.Sprintf("cfrules_run|%s", token("enable", "all"))},
				{Text: "关闭/删除全部", CallbackData: fmt.Sprintf("cfrules_run|%s", token("disable", "all"))},
			},
			{
				{Text: "开启/更新安全", CallbackData: fmt.Sprintf("cfrules_run|%s", token("enable", "security"))},
				{Text: "关闭安全", CallbackData: fmt.Sprintf("cfrules_run|%s", token("disable", "security"))},
			},
			{
				{Text: "开启/更新速度", CallbackData: fmt.Sprintf("cfrules_run|%s", token("enable", "speed"))},
				{Text: "关闭速度", CallbackData: fmt.Sprintf("cfrules_run|%s", token("disable", "speed"))},
			},
			{
				{Text: "开启/更新缓存", CallbackData: fmt.Sprintf("cfrules_run|%s", token("enable", "cache"))},
				{Text: "关闭缓存", CallbackData: fmt.Sprintf("cfrules_run|%s", token("disable", "cache"))},
			},
			{
				{Text: "返回选择", CallbackData: fmt.Sprintf("cfrules_back|%s", token("", ""))},
				{Text: "取消", CallbackData: fmt.Sprintf("cfrules_cancel|%s", token("", ""))},
			},
		},
	}
}

func ProcessCFRulesItems(ctx context.Context, client cfclient.Client, account config.CF, items []CFRulesDomainItem, action string, feature string, blockCountries []string) CFRulesBatchResult {
	result := CFRulesBatchResult{AccountLabel: account.Label, Action: action, Feature: feature}
	manager, ok := client.(cloudflareFeatureManager)
	if !ok {
		result.Failed = append(result.Failed, "当前 Cloudflare 客户端不支持规则管理")
		return result
	}
	security := feature == "all" || feature == "security"
	speed := feature == "all" || feature == "speed"
	cache := feature == "all" || feature == "cache"
	for _, item := range items {
		zoneID := strings.TrimSpace(item.ZoneID)
		if zoneID == "" {
			result.Failed = append(result.Failed, item.Name+": 缺少 zone_id")
			continue
		}
		managed := manager.ManageZoneFeatures(ctx, account, item.Name, zoneID, cfclient.FeatureManageOptions{
			AccountID:      account.AccountID,
			BlockCountries: blockCountries,
			Action:         action,
			Security:       security,
			Speed:          speed,
			Cache:          cache,
		})
		if len(managed.Errors) > 0 {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: %s", item.Name, strings.Join(managed.Errors, "; ")))
		}
		result.Success = append(result.Success, managed)
	}
	sort.Slice(result.Success, func(i, j int) bool { return result.Success[i].Domain < result.Success[j].Domain })
	sort.Strings(result.Failed)
	return result
}

func (r CFRulesBatchResult) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Cloudflare 规则检查完成\n账号: %s\n动作: %s\n功能: %s\n已处理: %d", r.AccountLabel, r.Action, r.Feature, len(r.Success)))
	for _, item := range r.Success {
		sb.WriteString(fmt.Sprintf("\n- %s | 安全:%s | 速度:%s | 缓存:%s",
			item.Domain,
			normalizeDisplayValue(item.SecurityRuleStatus),
			compactSpeedStatus(item.SpeedStatus),
			normalizeDisplayValue(item.CacheRuleStatus),
		))
	}
	if len(r.Failed) > 0 {
		sb.WriteString(fmt.Sprintf("\n\n失败: %d", len(r.Failed)))
		for _, item := range r.Failed {
			sb.WriteString("\n- " + item)
		}
	}
	return sb.String()
}

func normalizeCFRulesAction(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "enable", "update", "on":
		return "enable"
	case "disable", "delete", "off":
		return "disable"
	default:
		return ""
	}
}

func normalizeCFRulesFeature(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "all":
		return "all"
	case "security", "waf":
		return "security"
	case "speed":
		return "speed"
	case "cache":
		return "cache"
	default:
		return ""
	}
}
