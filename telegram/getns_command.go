package telegram

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"DomainC/cfclient"
	"DomainC/config"
	"DomainC/registrarclient"
	"DomainC/reminder"
)

const (
	getNSCreateZoneInterval  = 3 * time.Second
	getNSFeatureInitInterval = 2 * time.Second
)

type getNSDomainResult struct {
	Domain       string
	AccountLabel string
}

type getNSBatchResult struct {
	TargetAccount       string
	Created             []getNSDomainResult
	Existing            []getNSDomainResult
	ParseErrors         []string
	Failed              []string
	ManualNS            []string
	RegistrarSynced     int
	RegistrarSyncQueued []string
	Provisioned         []cfclient.ProvisionResult
	PostInitQueued      []string
}

type getNSRegistrarSyncTask struct {
	Domain      string
	NameServers []string
}

type getNSFeatureInitTask struct {
	Account config.CF
	Domain  string
	ZoneID  string
	Options getNSPostInitOptions
}

type getNSRegistrarSyncResult struct {
	Synced   []string
	ManualNS []string
	Failed   []string
}

type getNSPostInitOptions struct {
	EnableSecurity bool
	EnableSpeed    bool
	EnableCache    bool
	EnableRUM      bool
	BlockCountries []string
}

func (o getNSPostInitOptions) Any() bool {
	return o.EnableSecurity || o.EnableSpeed || o.EnableCache || o.EnableRUM
}

func defaultGetNSPostInitOptions() getNSPostInitOptions {
	return getNSPostInitOptions{BlockCountries: config.DefaultBlockCountries()}
}

func (r getNSBatchResult) HasInputErrors() bool {
	return len(r.ParseErrors) > 0 || len(r.Failed) > 0
}

func (r getNSBatchResult) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("✅ /getns 处理完成\n目标账号: %s\n新增: %d\n已存在: %d", r.TargetAccount, len(r.Created), len(r.Existing)))
	if r.RegistrarSynced > 0 {
		sb.WriteString(fmt.Sprintf("\n注册商已自动同步: %d", r.RegistrarSynced))
	}
	if len(r.RegistrarSyncQueued) > 0 {
		sb.WriteString(fmt.Sprintf("\n注册商后台同步已提交: %d", len(r.RegistrarSyncQueued)))
	}

	if len(r.Existing) > 0 {
		sb.WriteString("\n\n已存在:")
		for _, item := range r.Existing {
			sb.WriteString(fmt.Sprintf("\n- %s -> %s", item.Domain, item.AccountLabel))
		}
	}

	if len(r.ManualNS) > 0 {
		sb.WriteString("\n\n需手动设置 NS:")
		for _, item := range r.ManualNS {
			sb.WriteString("\n" + item)
		}
	}

	if len(r.Provisioned) > 0 {
		sb.WriteString("\n\nCloudflare 初始化:")
		for _, item := range r.Provisioned {
			block := item.CountryBlockStatus
			if len(item.CountryBlockCountries) > 0 {
				block += " " + strings.Join(item.CountryBlockCountries, ",")
			}
			sb.WriteString(fmt.Sprintf("\n- %s | WAF:%s | Speed:%s | RUM:%s", item.Domain, block, compactSpeedStatus(item.SpeedStatus), item.RUMStatus))
		}
	}

	if len(r.PostInitQueued) > 0 {
		sb.WriteString("\n\nCloudflare 后台初始化已提交:")
		for _, domain := range r.PostInitQueued {
			sb.WriteString("\n- " + domain)
		}
	}

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

	if r.HasInputErrors() {
		sb.WriteString("\n\n可继续直接发送失败域名重试。")
	}

	return sb.String()
}

func (r getNSRegistrarSyncResult) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("注册商 NS 后台同步完成\n已同步: %d\n需手动: %d\n失败: %d", len(r.Synced), len(r.ManualNS), len(r.Failed)))
	if len(r.Synced) > 0 {
		sb.WriteString("\n\n已同步:")
		for _, item := range r.Synced {
			sb.WriteString("\n- " + item)
		}
	}
	if len(r.ManualNS) > 0 {
		sb.WriteString("\n\n需手动设置 NS:")
		for _, item := range r.ManualNS {
			sb.WriteString("\n" + item)
		}
	}
	if len(r.Failed) > 0 {
		sb.WriteString("\n\n失败:")
		for _, item := range r.Failed {
			sb.WriteString("\n- " + item)
		}
	}
	return sb.String()
}

func (h *CommandHandler) handleGetNSCommand(args []string) {
	if len(h.Accounts) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法添加域名。")
		return
	}

	if len(args) == 0 {
		h.sendGetNSAccountSelector()
		return
	}

	cleanArgs, postInitOpts, optionErr := parseGetNSPostInitArgs(args)
	if optionErr != nil {
		h.sendText(optionErr.Error())
		return
	}

	domains, selected, selectorErr := h.parseGetNSDomainsAndAccount(cleanArgs)
	if selectorErr != nil {
		h.sendText(selectorErr.Error())
		return
	}

	if selected == nil {
		h.sendGetNSAccountSelector()
		return
	}

	if len(domains) == 0 {
		if h.operator != nil {
			req := newGetNSInputRequest(selected.Label, postInitOpts)
			if req.EnableSecurity && len(req.BlockCountries) == 0 {
				req.Stage = GetNSInputBlockCountries
				SetPendingGetNSInput(h.operator.ID, req)
				h.sendText(BuildGetNSBlockCountriesPrompt(req, ""))
				return
			}
			SetPendingGetNSInput(h.operator.ID, req)
		}
		h.sendText(h.getNSInputPrompt(selected.Label, postInitOpts))
		return
	}
	if postInitOpts.EnableSecurity && len(postInitOpts.BlockCountries) == 0 {
		h.sendText("已开启安全规则初始化，但没有可用的国家/地区代码。请使用 block=CN,RU，或配置 CF_DEFAULT_BLOCK_COUNTRIES。")
		return
	}

	result := h.processGetNSBatch(*selected, domains, postInitOpts)
	if h.operator != nil && !result.HasInputErrors() {
		ClearPendingGetNSInput(h.operator.ID)
	}
	h.sendText(result.Summary())
}

func (h *CommandHandler) sendGetNSAccountSelector() {
	var buttons [][]Button
	for _, acc := range h.Accounts {
		label := strings.TrimSpace(acc.Label)
		if label == "" {
			continue
		}
		token := SetGetNSCallbackPayload(GetNSCallbackPayload{AccountLabel: label})
		buttons = append(buttons, []Button{{
			Text:         label,
			CallbackData: fmt.Sprintf("getns_select|%s", token),
		}})
	}

	if len(buttons) == 0 {
		h.sendText("未配置可用的 Cloudflare 账号，无法添加域名。")
		return
	}

	if err := h.Sender.SendWithButtons(context.Background(), h.getNSPromptText(), buttons); err != nil {
		h.sendText(fmt.Sprintf("发送账号选择失败: %v", err))
	}
}

func (h *CommandHandler) handlePendingGetNSInput(msgText string, userID int64) bool {
	req, ok := GetPendingGetNSInput(userID)
	if !ok {
		return false
	}

	if req.Stage == GetNSInputBlockCountries {
		countries, err := parseGetNSBlockCountriesInput(msgText)
		if err != nil {
			h.sendText(BuildGetNSBlockCountriesPrompt(req, err.Error()))
			return true
		}
		if len(countries) == 0 {
			h.sendText(BuildGetNSBlockCountriesPrompt(req, "启用安全规则时国家/地区代码不能为空"))
			return true
		}
		req.BlockCountries = countries
		req.Stage = GetNSInputDomains
		SetPendingGetNSInput(userID, req)
		h.sendText(h.getNSInputPrompt(req.AccountLabel, getNSPostInitOptionsFromRequest(req)))
		return true
	}

	domains, parseErrors := parseGetNSDomainsInput(msgText)
	if len(domains) == 0 {
		h.sendText(h.getNSRetryPrompt(req.AccountLabel, getNSPostInitOptionsFromRequest(req), parseErrors))
		return true
	}

	acc := h.getAccountByLabel(req.AccountLabel)
	if acc == nil {
		ClearPendingGetNSInput(userID)
		h.sendText(fmt.Sprintf("未找到账号 %s，已取消本次 /getns 操作。", req.AccountLabel))
		return true
	}

	result := h.processGetNSBatch(*acc, domains, getNSPostInitOptionsFromRequest(req))
	result.ParseErrors = append(result.ParseErrors, parseErrors...)
	if !result.HasInputErrors() {
		ClearPendingGetNSInput(userID)
	}

	h.sendText(result.Summary())
	return true
}

func (h *CommandHandler) processGetNSBatch(selected config.CF, rawDomains []string, postInitOpts getNSPostInitOptions) getNSBatchResult {
	domains, parseErrors := parseGetNSDomainsInput(strings.Join(rawDomains, "\n"))
	result := getNSBatchResult{
		TargetAccount: selected.Label,
		ParseErrors:   parseErrors,
	}
	ctx := context.Background()
	cfPacer := newBatchAPIPacerWithInterval(getNSCreateZoneInterval)
	var registrarTasks []getNSRegistrarSyncTask
	var featureTasks []getNSFeatureInitTask

	for _, domain := range domains {
		if acc, zone, err := h.findZone(domain); err == nil {
			item := getNSDomainResult{
				Domain:       zone.Name,
				AccountLabel: acc.Label,
			}
			if rt := reminder.DefaultRuntime(); rt != nil {
				rt.RecordDomainChange(ctx, reminder.DomainChange{Domain: zone.Name, Source: acc.Label, IsCF: true, ZoneID: zone.ID, Status: zone.Status, Paused: zone.Paused})
			}
			h.queueGetNSFeatureInit(*acc, zone.Name, zone.ID, postInitOpts, &result, &featureTasks)
			h.queueGetNSRegistrarSync(domain, zone.NameServers, &result, &registrarTasks)
			result.Existing = append(result.Existing, item)
			continue
		} else if !errors.Is(err, cfclient.ErrZoneNotFound) {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", domain, err))
			continue
		}

		if err := cfPacer.Wait(ctx); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: 创建 Zone 前等待失败: %v", domain, err))
			continue
		}

		zone, provisionResult, err := h.createOrProvisionGetNSZone(ctx, selected, domain)
		if err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", domain, err))
			continue
		}
		if provisionResult != nil {
			h.queueGetNSFeatureInit(selected, provisionResult.Domain, provisionResult.ZoneID, postInitOpts, &result, &featureTasks)
		} else {
			h.queueGetNSFeatureInit(selected, zone.Name, zone.ID, postInitOpts, &result, &featureTasks)
		}

		item := getNSDomainResult{
			Domain:       zone.Name,
			AccountLabel: selected.Label,
		}
		if rt := reminder.DefaultRuntime(); rt != nil {
			rt.RecordDomainChange(ctx, reminder.DomainChange{Domain: zone.Name, Source: selected.Label, IsCF: true, ZoneID: zone.ID, Status: zone.Status, Paused: zone.Paused})
		}
		h.queueGetNSRegistrarSync(domain, zone.NameServers, &result, &registrarTasks)
		result.Created = append(result.Created, item)
	}
	if len(registrarTasks) > 0 {
		h.startGetNSRegistrarSyncTask(registrarTasks)
	}
	if len(featureTasks) > 0 {
		h.startGetNSFeatureInitBatch(featureTasks)
	}

	return result
}

func (h *CommandHandler) createOrProvisionGetNSZone(ctx context.Context, selected config.CF, domain string) (cfclient.ZoneDetail, *cfclient.ProvisionResult, error) {
	if provisioner, ok := h.CFClient.(cfclient.Provisioner); ok {
		result, err := provisioner.ProvisionCloudflareZone(ctx, selected, domain, cfclient.ProvisionOptions{
			AccountID:           selected.AccountID,
			BlockCountries:      nil,
			EnableSpeed:         false,
			EnableRUM:           false,
			ExtraZoneSettings:   config.ExtraZoneSettings(),
			CreateZoneIfMissing: true,
		})
		if err != nil {
			return cfclient.ZoneDetail{}, nil, err
		}
		return cfclient.ZoneDetail{
			ID:          result.ZoneID,
			Name:        result.Domain,
			NameServers: append([]string(nil), result.NameServers...),
		}, result, nil
	}

	zone, err := h.CFClient.CreateZone(ctx, selected, domain)
	return zone, nil, err
}

func (h *CommandHandler) queueGetNSRegistrarSync(domain string, nameServers []string, result *getNSBatchResult, tasks *[]getNSRegistrarSyncTask) {
	if len(nameServers) == 0 {
		result.ManualNS = append(result.ManualNS, fmt.Sprintf("- %s\n  未获取到 NS", domain))
		return
	}
	if h.RegistrarManager == nil {
		result.ManualNS = append(result.ManualNS, fmt.Sprintf("- %s\n  %s", domain, strings.Join(nameServers, "\n  ")))
		return
	}
	*tasks = append(*tasks, getNSRegistrarSyncTask{
		Domain:      domain,
		NameServers: append([]string(nil), nameServers...),
	})
	result.RegistrarSyncQueued = append(result.RegistrarSyncQueued, domain)
}

func (h *CommandHandler) queueGetNSFeatureInit(account config.CF, domain string, zoneID string, opts getNSPostInitOptions, result *getNSBatchResult, tasks *[]getNSFeatureInitTask) {
	if !opts.Any() {
		return
	}
	domain = strings.TrimSpace(domain)
	zoneID = strings.TrimSpace(zoneID)
	if domain == "" || zoneID == "" {
		result.Failed = append(result.Failed, fmt.Sprintf("%s: Cloudflare 初始化缺少 Zone ID", domain))
		return
	}

	result.PostInitQueued = append(result.PostInitQueued, domain)
	if opts.EnableSecurity || opts.EnableSpeed || opts.EnableCache {
		*tasks = append(*tasks, getNSFeatureInitTask{
			Account: account,
			Domain:  domain,
			ZoneID:  zoneID,
			Options: opts,
		})
	}
	if opts.EnableRUM {
		h.startCloudflarePostInitTask(account, domain, zoneID, cfProvisionCommandOptions{
			Domain:    domain,
			EnableRUM: true,
		})
	}
}

func (h *CommandHandler) startGetNSFeatureInitBatch(tasks []getNSFeatureInitTask) {
	manager, ok := h.CFClient.(cloudflareFeatureManager)
	if !ok {
		h.sendText("当前 Cloudflare 客户端不支持 /getns 规则初始化。")
		return
	}
	grouped := make(map[string][]getNSFeatureInitTask)
	labels := make([]string, 0)
	for _, task := range tasks {
		label := strings.TrimSpace(task.Account.Label)
		if label == "" {
			label = task.Account.AccountID
		}
		if _, ok := grouped[label]; !ok {
			labels = append(labels, label)
		}
		grouped[label] = append(grouped[label], task)
	}
	sort.Strings(labels)

	go func() {
		var wg sync.WaitGroup
		var mu sync.Mutex
		var managed []cfclient.FeatureManageResult
		var failed []string

		for _, label := range labels {
			accountTasks := append([]getNSFeatureInitTask(nil), grouped[label]...)
			wg.Add(1)
			go func(accountTasks []getNSFeatureInitTask) {
				defer wg.Done()
				pacer := newBatchAPIPacerWithInterval(getNSFeatureInitInterval)
				ctx := context.Background()
				for _, task := range accountTasks {
					if err := pacer.Wait(ctx); err != nil {
						mu.Lock()
						failed = append(failed, fmt.Sprintf("%s: 等待 Cloudflare 初始化失败: %v", task.Domain, err))
						mu.Unlock()
						continue
					}
					item := manager.ManageZoneFeatures(ctx, task.Account, task.Domain, task.ZoneID, getNSFeatureManageOptions(task.Account, task.Options))
					mu.Lock()
					managed = append(managed, item)
					mu.Unlock()
				}
			}(accountTasks)
		}
		wg.Wait()
		sort.Slice(managed, func(i, j int) bool {
			return managed[i].Domain < managed[j].Domain
		})
		sort.Strings(failed)
		h.sendText(formatGetNSFeatureInitBatchResult(managed, failed))
	}()
}

func getNSFeatureManageOptions(account config.CF, opts getNSPostInitOptions) cfclient.FeatureManageOptions {
	featureOpts := cfclient.FeatureManageOptions{
		AccountID: account.AccountID,
		Action:    "enable",
		Security:  opts.EnableSecurity,
		Speed:     opts.EnableSpeed,
		Cache:     opts.EnableCache,
	}
	if opts.EnableSecurity {
		featureOpts.BlockCountries = append([]string(nil), opts.BlockCountries...)
	}
	return featureOpts
}

func formatGetNSFeatureInitBatchResult(results []cfclient.FeatureManageResult, failed []string) string {
	var sb strings.Builder
	hasErrors := len(failed) > 0
	for _, result := range results {
		if len(result.Errors) > 0 {
			hasErrors = true
			break
		}
	}
	if hasErrors {
		sb.WriteString("⚠️ /getns Cloudflare 初始化完成但有异常\n\n")
	} else {
		sb.WriteString("✅ /getns Cloudflare 初始化完成\n\n")
	}

	sb.WriteString(fmt.Sprintf("已处理: %d", len(results)))
	for i, result := range results {
		if i >= 40 {
			sb.WriteString(fmt.Sprintf("\n- ... 其余 %d 个域名略", len(results)-i))
			break
		}
		sb.WriteString(fmt.Sprintf("\n- %s | 安全:%s | 速度:%s | 缓存:%s",
			normalizeDisplayValue(result.Domain),
			normalizeDisplayValue(result.SecurityRuleStatus),
			compactSpeedStatus(result.SpeedStatus),
			normalizeDisplayValue(result.CacheRuleStatus)))
	}

	var warnings []string
	var errorsList []string
	for _, result := range results {
		for _, item := range result.Warnings {
			warnings = append(warnings, fmt.Sprintf("%s: %s", result.Domain, item))
		}
		for _, item := range result.Errors {
			errorsList = append(errorsList, fmt.Sprintf("%s: %s", result.Domain, item))
		}
	}
	errorsList = append(errorsList, failed...)
	sort.Strings(warnings)
	sort.Strings(errorsList)

	if len(warnings) > 0 {
		sb.WriteString("\n\n提示:")
		for i, item := range warnings {
			if i >= 20 {
				sb.WriteString(fmt.Sprintf("\n- ... 其余 %d 条提示略", len(warnings)-i))
				break
			}
			sb.WriteString("\n- " + item)
		}
	}
	if len(errorsList) > 0 {
		sb.WriteString("\n\n错误：")
		for i, item := range errorsList {
			if i >= 20 {
				sb.WriteString(fmt.Sprintf("\n- ... 其余 %d 条错误略", len(errorsList)-i))
				break
			}
			sb.WriteString("\n- " + item)
		}
	}
	return sb.String()
}

func (h *CommandHandler) startGetNSRegistrarSyncTask(tasks []getNSRegistrarSyncTask) {
	if len(tasks) == 0 || h.RegistrarManager == nil {
		return
	}
	copied := make([]getNSRegistrarSyncTask, 0, len(tasks))
	for _, task := range tasks {
		if strings.TrimSpace(task.Domain) == "" {
			continue
		}
		copied = append(copied, getNSRegistrarSyncTask{
			Domain:      strings.TrimSpace(task.Domain),
			NameServers: append([]string(nil), task.NameServers...),
		})
	}
	if len(copied) == 0 {
		return
	}
	go func() {
		result := h.runGetNSRegistrarSyncBatch(context.Background(), copied)
		h.sendText(result.Summary())
	}()
}

func (h *CommandHandler) runGetNSRegistrarSyncBatch(ctx context.Context, tasks []getNSRegistrarSyncTask) getNSRegistrarSyncResult {
	var result getNSRegistrarSyncResult
	pacer := newBatchAPIPacerWithInterval(500 * time.Millisecond)
	for _, task := range tasks {
		if err := pacer.Wait(ctx); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: 等待同步失败: %v", task.Domain, err))
			continue
		}
		registrar, err := h.syncRegistrarNameServers(task.Domain, task.NameServers)
		if err != nil {
			result.ManualNS = append(result.ManualNS, formatGetNSRegistrarSyncManual(task.Domain, task.NameServers, err))
			continue
		}
		result.Synced = append(result.Synced, fmt.Sprintf("%s -> %s (%s)", task.Domain, registrar.Label, registrar.Type))
	}
	return result
}

func formatGetNSRegistrarSyncManual(domain string, nameServers []string, err error) string {
	manual := fmt.Sprintf("- %s\n  %s", domain, strings.Join(nameServers, "\n  "))
	if errors.Is(err, registrarclient.ErrDomainNotFound) {
		return manual + "\n  注册商未找到该域名，无法自动同步，请手动设置 NS。"
	}
	if errors.Is(err, registrarclient.ErrRegistrarRateLimited) {
		return manual + fmt.Sprintf("\n  注册商 API 限流，NS 自动同步未完成。限流账号是自动扫描经过的注册商账号，不一定是该域名所属账号。请按以上 NS 手动设置，或稍后重试自动同步。详情: %v", err)
	}
	return manual + fmt.Sprintf("\n  注册商平台/API 异常，自动同步失败: %v", err)
}

func compactSpeedStatus(status map[string]string) string {
	if len(status) == 0 {
		return "skipped"
	}
	okCount := 0
	failed := 0
	skipped := 0
	for _, value := range status {
		value = strings.TrimSpace(value)
		if value == "enabled" || value == "already_enabled" || value == "already_exists" {
			okCount++
			continue
		}
		if strings.HasPrefix(value, "failed:") {
			failed++
			continue
		}
		if strings.HasPrefix(value, "skipped") {
			skipped++
		}
	}
	if failed == 0 && skipped == 0 {
		return fmt.Sprintf("ok %d/%d", okCount, len(status))
	}
	if failed == 0 {
		return fmt.Sprintf("ok %d/%d skipped %d", okCount, len(status), skipped)
	}
	return fmt.Sprintf("ok %d/%d skipped %d failed %d", okCount, len(status), skipped, failed)
}

func parseGetNSPostInitArgs(args []string) ([]string, getNSPostInitOptions, error) {
	opts := defaultGetNSPostInitOptions()
	clean := make([]string, 0, len(args))
	for _, arg := range args {
		key, value, ok := strings.Cut(strings.TrimSpace(arg), "=")
		if !ok {
			clean = append(clean, arg)
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "security", "waf":
			enabled, err := parseOnOff(value)
			if err != nil {
				return clean, opts, fmt.Errorf("security 参数错误：%v", err)
			}
			opts.EnableSecurity = enabled
		case "speed":
			enabled, err := parseOnOff(value)
			if err != nil {
				return clean, opts, fmt.Errorf("speed 参数错误：%v", err)
			}
			opts.EnableSpeed = enabled
		case "cache":
			enabled, err := parseOnOff(value)
			if err != nil {
				return clean, opts, fmt.Errorf("cache 参数错误：%v", err)
			}
			opts.EnableCache = enabled
		case "rum":
			enabled, err := parseOnOff(value)
			if err != nil {
				return clean, opts, fmt.Errorf("rum 参数错误：%v", err)
			}
			opts.EnableRUM = enabled
		case "init":
			enabled, err := parseOnOff(value)
			if err != nil {
				return clean, opts, fmt.Errorf("init 参数错误：%v", err)
			}
			opts.EnableSecurity = enabled
			opts.EnableSpeed = enabled
			opts.EnableCache = enabled
		case "block", "blocks", "country", "countries":
			if isNoneValue(value) {
				opts.BlockCountries = nil
				opts.EnableSecurity = false
				continue
			}
			countries, err := cfclient.NormalizeCountryCodes([]string{value})
			if err != nil {
				return clean, opts, fmt.Errorf("block 参数错误：%v", err)
			}
			opts.BlockCountries = countries
			if len(countries) > 0 {
				opts.EnableSecurity = true
			}
		default:
			clean = append(clean, arg)
		}
	}
	return clean, opts, nil
}

func newGetNSInputRequest(accountLabel string, opts getNSPostInitOptions) GetNSInputRequest {
	return GetNSInputRequest{
		AccountLabel:   accountLabel,
		Stage:          GetNSInputDomains,
		EnableSecurity: opts.EnableSecurity,
		EnableSpeed:    opts.EnableSpeed,
		EnableCache:    opts.EnableCache,
		EnableRUM:      opts.EnableRUM,
		BlockCountries: append([]string(nil), opts.BlockCountries...),
	}
}

func getNSPostInitOptionsFromRequest(req GetNSInputRequest) getNSPostInitOptions {
	return getNSPostInitOptions{
		EnableSecurity: req.EnableSecurity,
		EnableSpeed:    req.EnableSpeed,
		EnableCache:    req.EnableCache,
		EnableRUM:      req.EnableRUM,
		BlockCountries: append([]string(nil), req.BlockCountries...),
	}
}

func parseGetNSBlockCountriesInput(input string) ([]string, error) {
	input = strings.TrimSpace(input)
	if input == "" || strings.EqualFold(input, "default") || strings.EqualFold(input, "1") {
		return cfclient.NormalizeCountryCodes(config.DefaultBlockCountries())
	}
	if isNoneValue(input) {
		return nil, nil
	}
	return cfclient.NormalizeCountryCodes([]string{input})
}

func formatGetNSPostInitOptions(opts getNSPostInitOptions) string {
	if !opts.Any() {
		return "关闭（仅创建 Zone 并同步 NS）"
	}
	parts := make([]string, 0, 4)
	if opts.EnableSecurity {
		suffix := ""
		if len(opts.BlockCountries) > 0 {
			suffix = "(" + strings.Join(opts.BlockCountries, ",") + ")"
		}
		parts = append(parts, "安全规则"+suffix)
	}
	if opts.EnableSpeed {
		parts = append(parts, "速度推荐")
	}
	if opts.EnableCache {
		parts = append(parts, "缓存规则")
	}
	if opts.EnableRUM {
		parts = append(parts, "RUM")
	}
	return strings.Join(parts, "、")
}

func BuildGetNSBlockCountriesPrompt(req GetNSInputRequest, errText string) string {
	var sb strings.Builder
	if strings.TrimSpace(errText) != "" {
		sb.WriteString("国家/地区代码格式错误: " + errText + "\n\n")
	}
	sb.WriteString("/getns 已开启安全规则初始化，需要指定要拦截的国家/地区代码。\n")
	defaultCountries := config.DefaultBlockCountries()
	if len(defaultCountries) > 0 {
		sb.WriteString("发送 1 使用配置默认: " + strings.Join(defaultCountries, ",") + "\n")
	}
	sb.WriteString("请输入 ISO 3166-1 alpha-2 代码，逗号分隔，例如 CN,RU,KP。")
	return sb.String()
}

func BuildGetNSInputPrompt(accountLabel string, req GetNSInputRequest) string {
	return fmt.Sprintf("已选择账号 %s。\n初始化：%s\n请直接发送要添加的域名，支持多行、空格、逗号或分号分隔。\n示例：\nexample.com\nexample.net", accountLabel, formatGetNSPostInitOptions(getNSPostInitOptionsFromRequest(req)))
}

func BuildGetNSInitOptionsView(accountLabel string) IPListPage {
	token := func(security bool, speed bool, cache bool) string {
		return SetGetNSCallbackPayload(GetNSCallbackPayload{
			AccountLabel:   accountLabel,
			EnableSecurity: security,
			EnableSpeed:    speed,
			EnableCache:    cache,
		})
	}
	msg := fmt.Sprintf("已选择账号 %s。\n请选择 /getns 创建 Zone 后是否执行初始化；默认建议只创建 Zone 并同步 NS。", accountLabel)
	return IPListPage{
		Message: msg,
		Buttons: [][]Button{
			{{Text: "仅创建 Zone/同步 NS", CallbackData: fmt.Sprintf("getns_init|%s", token(false, false, false))}},
			{
				{Text: "开启安全规则", CallbackData: fmt.Sprintf("getns_init|%s", token(true, false, false))},
				{Text: "开启速度推荐", CallbackData: fmt.Sprintf("getns_init|%s", token(false, true, false))},
			},
			{
				{Text: "开启缓存规则", CallbackData: fmt.Sprintf("getns_init|%s", token(false, false, true))},
				{Text: "安全+速度+缓存", CallbackData: fmt.Sprintf("getns_init|%s", token(true, true, true))},
			},
		},
	}
}

func (h *CommandHandler) parseGetNSDomainsAndAccount(args []string) ([]string, *config.CF, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}

	last := strings.TrimSpace(args[len(args)-1])
	if acc := h.getAccountByLabel(last); acc != nil {
		return args[:len(args)-1], acc, nil
	}

	return args, nil, nil
}

func (h *CommandHandler) getNSPromptText() string {
	if len(h.Accounts) == 0 {
		return "未配置可用的 Cloudflare 账号，无法添加域名。"
	}

	var sb strings.Builder
	sb.WriteString("请选择要添加域名的 Cloudflare 账号：\n")
	for _, a := range h.Accounts {
		if strings.TrimSpace(a.Label) == "" {
			continue
		}
		sb.WriteString("- " + a.Label + "\n")
	}
	sb.WriteString("\n选择账号后可选择是否执行安全规则、速度推荐、缓存规则初始化。")
	return sb.String()
}

func (h *CommandHandler) getNSInputPrompt(accountLabel string, opts getNSPostInitOptions) string {
	return fmt.Sprintf("已选择账号 %s。\n初始化：%s\n请直接发送要添加的域名，支持多行、空格、逗号或分号分隔。\n示例：\nexample.com\nexample.net", accountLabel, formatGetNSPostInitOptions(opts))
}

func (h *CommandHandler) getNSRetryPrompt(accountLabel string, opts getNSPostInitOptions, errs []string) string {
	var sb strings.Builder
	if len(errs) > 0 {
		sb.WriteString("以下域名未识别：\n")
		for _, item := range errs {
			sb.WriteString("- " + item + "\n")
		}
		sb.WriteString("\n")
	}
	sb.WriteString(h.getNSInputPrompt(accountLabel, opts))
	return strings.TrimSpace(sb.String())
}

func parseGetNSDomainsInput(input string) ([]string, []string) {
	fields := strings.FieldsFunc(input, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';'
	})

	seen := make(map[string]struct{})
	domains := make([]string, 0, len(fields))
	var errs []string

	for _, raw := range fields {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}

		domain, err := extractDomainOrHost(token)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", token, err))
			continue
		}

		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}

	if len(domains) == 0 && len(errs) == 0 {
		errs = append(errs, "输入为空")
	}

	return domains, errs
}

func (h *CommandHandler) syncRegistrarNameServers(domain string, nameServers []string) (config.Registrar, error) {
	if h.RegistrarManager == nil {
		return config.Registrar{}, fmt.Errorf("未配置注册商")
	}
	if len(nameServers) == 0 {
		return config.Registrar{}, fmt.Errorf("未获取到 NS")
	}
	return h.RegistrarManager.SetNameServersForDomain(context.Background(), domain, nameServers)
}

func (h *CommandHandler) setRegistrarNameServers(domain string, nameServers []string) {
	registrar, err := h.syncRegistrarNameServers(domain, nameServers)
	if err != nil {
		h.sendText(fmt.Sprintf("同步注册商 NS 失败: %v", err))
		return
	}
	h.sendText(fmt.Sprintf("已同步 NS 到注册商账号 %s (%s)。", registrar.Label, registrar.Type))
}
