package telegram

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
		ResetOriginSSLSelection(h.operator.ID)
	}
	if h.operator == nil {
		h.sendText(h.originSSLPromptText())
		return
	}
	h.sendOriginSSLTargetSelector(h.operator.ID)
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

func (h *CommandHandler) handlePendingOriginSSLInput(msgText string, userID int64) bool {
	req, ok := GetPendingOriginSSLInput(userID)
	if !ok {
		return false
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
	sb.WriteString("生成 Cloudflare Origin CA 源站证书（15年）。\n")
	sb.WriteString("Cloudflare 账号会按域名自动识别，只需要多选 AWS 目标，再输入一个或多个主域名。\n\n")
	sb.WriteString("兼容直接命令：/ssl example.com example.net us-aws sg-aws\n")
	sb.WriteString("说明：每个域名固定签发 domain.com + *.domain.com\n\n")
	sb.WriteString("可选 AWS 目标：\n")
	for _, alias := range sortedAWSTargetAliases() {
		target := config.Cfg.AWSTargets[alias]
		sb.WriteString(fmt.Sprintf("- %s (%s)\n", alias, target.Region))
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
