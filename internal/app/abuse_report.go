package app

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"DomainC/cfclient"
	"DomainC/config"
	"DomainC/telegram"
)

type AbuseReportService struct {
	CFClient  cfclient.Client
	Accounts  []config.CF
	Sender    telegram.Sender
	CacheFile string
	PerPage   int
	MaxPages  int
}

type AbuseReportCache struct {
	Version    int                             `json:"version"`
	LastScanAt time.Time                       `json:"last_scan_at,omitempty"`
	Reports    map[string]AbuseReportCacheItem `json:"reports"`
}

type AbuseReportCacheItem struct {
	Key         string    `json:"key"`
	ID          string    `json:"id,omitempty"`
	Source      string    `json:"source,omitempty"`
	AccountID   string    `json:"account_id,omitempty"`
	Domain      string    `json:"domain,omitempty"`
	ReportType  string    `json:"report_type,omitempty"`
	Status      string    `json:"status,omitempty"`
	Mitigation  string    `json:"mitigation,omitempty"`
	Title       string    `json:"title,omitempty"`
	Summary     string    `json:"summary,omitempty"`
	Date        time.Time `json:"date,omitempty"`
	FirstSeenAt time.Time `json:"first_seen_at,omitempty"`
	LastSeenAt  time.Time `json:"last_seen_at,omitempty"`
	NotifiedAt  time.Time `json:"notified_at,omitempty"`
}

type abuseScanError struct {
	Source string
	Err    error
}

func (s *AbuseReportService) RunDaily(ctx context.Context) error {
	if s == nil || s.CFClient == nil || s.Sender == nil {
		return ErrMissingDependencies
	}
	if len(s.Accounts) == 0 {
		return errors.New("no cloudflare accounts configured")
	}

	now := time.Now()
	cache, err := loadAbuseReportCache(s.cachePath())
	if err != nil {
		return err
	}

	newReports := make([]cfclient.AbuseReportInfo, 0)
	scanErrors := make([]abuseScanError, 0)
	for _, acc := range s.Accounts {
		reports, err := s.CFClient.ListAbuseReports(ctx, acc, cfclient.AbuseReportListOptions{PerPage: s.perPage(), MaxPages: s.maxPages()})
		if err != nil {
			scanErrors = append(scanErrors, abuseScanError{Source: acc.Label, Err: err})
			log.Printf("[abuse_report] scan_account_failed source=%s err=%v", acc.Label, err)
			continue
		}
		log.Printf("[abuse_report] scan_account_done source=%s reports=%d", acc.Label, len(reports))
		for _, report := range reports {
			key := abuseReportKey(report)
			item, existed := cache.Reports[key]
			if !existed {
				item = AbuseReportCacheItem{Key: key, FirstSeenAt: now}
			}
			fillAbuseCacheItem(&item, report, now)
			cache.Reports[key] = item
			if item.NotifiedAt.IsZero() {
				newReports = append(newReports, report)
			}
		}
	}
	cache.LastScanAt = now

	if len(newReports) == 0 {
		if err := saveAbuseReportCache(s.cachePath(), cache); err != nil {
			return err
		}
		if len(scanErrors) > 0 {
			log.Printf("[abuse_report] scan_done new=0 errors=%d", len(scanErrors))
		} else {
			log.Printf("[abuse_report] scan_done new=0")
		}
		return nil
	}

	sortAbuseReports(newReports)
	msg := FormatAbuseReportMessage(newReports, scanErrors, now)
	if err := s.Sender.Send(ctx, msg); err != nil {
		_ = saveAbuseReportCache(s.cachePath(), cache)
		return err
	}

	reportPath, cleanup, err := BuildAbuseReportHTML(newReports, scanErrors, now)
	if err != nil {
		log.Printf("[abuse_report] build_html_failed err=%v", err)
		reportPath, cleanup, err = BuildAbuseReportCSV(newReports, now)
		if err != nil {
			log.Printf("[abuse_report] build_csv_failed err=%v", err)
		} else {
			defer cleanup()
			caption := fmt.Sprintf("%s: Cloudflare 新增滥用报告 %d 条，HTML 生成失败，已降级 CSV", now.Format("2006-01-02"), len(newReports))
			if err := s.Sender.SendDocumentPath(ctx, reportPath, caption); err != nil {
				_ = saveAbuseReportCache(s.cachePath(), cache)
				return err
			}
		}
	} else {
		defer cleanup()
		caption := fmt.Sprintf("%s: Cloudflare 新增滥用报告 %d 条，详情见 HTML 报告", now.Format("2006-01-02"), len(newReports))
		if err := s.Sender.SendDocumentPath(ctx, reportPath, caption); err != nil {
			_ = saveAbuseReportCache(s.cachePath(), cache)
			return err
		}
	}

	for _, report := range newReports {
		key := abuseReportKey(report)
		item := cache.Reports[key]
		item.NotifiedAt = now
		cache.Reports[key] = item
	}
	if err := saveAbuseReportCache(s.cachePath(), cache); err != nil {
		return err
	}
	log.Printf("[abuse_report] scan_done new=%d errors=%d", len(newReports), len(scanErrors))
	return nil
}

func (s *AbuseReportService) cachePath() string {
	if strings.TrimSpace(s.CacheFile) != "" {
		return strings.TrimSpace(s.CacheFile)
	}
	return "abuse_report_cache.json"
}

func (s *AbuseReportService) perPage() int {
	if s.PerPage <= 0 {
		return 50
	}
	if s.PerPage > 100 {
		return 100
	}
	return s.PerPage
}

func (s *AbuseReportService) maxPages() int {
	if s.MaxPages <= 0 {
		return 5
	}
	if s.MaxPages > 20 {
		return 20
	}
	return s.MaxPages
}

func FormatAbuseReportMessage(reports []cfclient.AbuseReportInfo, scanErrors []abuseScanError, now time.Time) string {
	var sb strings.Builder
	sb.WriteString("【Cloudflare 滥用报告提醒】")
	sb.WriteString(fmt.Sprintf("\n发现新的滥用报告: %d 条", len(reports)))
	sb.WriteString(fmt.Sprintf("\n扫描时间: %s", now.Format("2006-01-02 15:04:05")))
	sb.WriteString("\n\n这代表 Cloudflare 收到了针对这些域名的投诉或举报。")
	sb.WriteString("不一定说明域名已经违规，但需要尽快检查对应站点、落地页、跳转链和最近投放内容。")

	accountCounts := map[string]int{}
	typeCounts := map[string]int{}
	riskCounts := map[string]int{}
	for _, report := range reports {
		accountCounts[displayAbuseValue(report.AccountLabel, "未知账号")]++
		typeCounts[humanAbuseType(report.ReportType)]++
		riskCounts[abuseRiskLevel(report)]++
	}
	if len(riskCounts) > 0 {
		sb.WriteString("\n\n风险分布:")
		for _, key := range []string{"高", "中", "低"} {
			if count := riskCounts[key]; count > 0 {
				sb.WriteString(fmt.Sprintf("\n- %s风险: %d 条", key, count))
			}
		}
	}
	if len(accountCounts) > 0 {
		sb.WriteString("\n\n按账号统计:")
		keys := sortedStringKeys(accountCounts)
		for _, key := range keys {
			sb.WriteString(fmt.Sprintf("\n- %s: %d 条", key, accountCounts[key]))
		}
	}
	if len(typeCounts) > 0 {
		sb.WriteString("\n\n按报告类型统计:")
		keys := sortedStringKeys(typeCounts)
		for _, key := range keys {
			sb.WriteString(fmt.Sprintf("\n- %s: %d 条", key, typeCounts[key]))
		}
	}

	if len(scanErrors) > 0 {
		sb.WriteString(fmt.Sprintf("\n\n扫描异常账号: %d 个", len(scanErrors)))
		for i, item := range scanErrors {
			if i >= 5 {
				sb.WriteString(fmt.Sprintf("\n- 还有 %d 个账号异常，详见容器日志", len(scanErrors)-i))
				break
			}
			sb.WriteString(fmt.Sprintf("\n- %s: %s", displayAbuseValue(item.Source, "未知账号"), compactAbuseText(item.Err.Error(), 120)))
		}
	}

	sb.WriteString("\n\n重点报告解读:")
	limit := len(reports)
	if limit > 5 {
		limit = 5
	}
	for i := 0; i < limit; i++ {
		report := reports[i]
		insight := explainAbuseReport(report)
		sb.WriteString(fmt.Sprintf("\n\n%d. %s", i+1, displayAbuseValue(report.Domain, "未识别域名")))
		sb.WriteString(fmt.Sprintf("\n   账号: %s", displayAbuseValue(report.AccountLabel, "未知账号")))
		sb.WriteString(fmt.Sprintf("\n   风险: %s", insight.RiskLevel))
		sb.WriteString(fmt.Sprintf("\n   类型: %s", insight.TypeLabel))
		sb.WriteString(fmt.Sprintf("\n   白话说明: %s", compactAbuseText(insight.PlainSummary, 180)))
		if insight.PossibleCause != "" {
			sb.WriteString(fmt.Sprintf("\n   可能原因: %s", compactAbuseText(insight.PossibleCause, 180)))
		}
		if insight.Action != "" {
			sb.WriteString(fmt.Sprintf("\n   建议处理: %s", compactAbuseText(insight.Action, 180)))
		}
		if strings.TrimSpace(report.Mitigation) != "" {
			sb.WriteString(fmt.Sprintf("\n   Cloudflare处理: %s", humanAbuseMitigation(report.Mitigation)))
		}
	}
	if len(reports) > limit {
		sb.WriteString(fmt.Sprintf("\n\n其余 %d 条请查看 HTML 附件。", len(reports)-limit))
	} else {
		sb.WriteString("\n\n完整原因、证据 URL、原始摘要和建议动作请查看 HTML 附件。")
	}
	return sb.String()
}

type abuseReportInsight struct {
	RiskLevel     string
	TypeLabel     string
	PlainSummary  string
	PossibleCause string
	Action        string
	Evidence      string
}

func BuildAbuseReportHTML(reports []cfclient.AbuseReportInfo, scanErrors []abuseScanError, now time.Time) (string, func(), error) {
	file, err := os.CreateTemp("", fmt.Sprintf("cf_abuse_reports_%s_*.html", now.Format("20060102_150405")))
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }

	accountCounts := map[string]int{}
	typeCounts := map[string]int{}
	riskCounts := map[string]int{}
	for _, report := range reports {
		accountCounts[displayAbuseValue(report.AccountLabel, "未知账号")]++
		typeCounts[humanAbuseType(report.ReportType)]++
		riskCounts[abuseRiskLevel(report)]++
	}

	var sb strings.Builder
	sb.WriteString("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
	sb.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	sb.WriteString("<title>Cloudflare 滥用报告</title>")
	sb.WriteString(`<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",Arial,sans-serif;margin:0;background:#f5f7fb;color:#182033;line-height:1.55}.wrap{max-width:1280px;margin:0 auto;padding:24px}.header{background:#111827;color:white;border-radius:18px;padding:22px 26px;margin-bottom:18px}.header h1{margin:0 0 8px;font-size:26px}.header p{margin:4px 0;color:#d1d5db}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}.card{background:white;border-radius:14px;padding:16px;border:1px solid #e5e7eb;box-shadow:0 1px 3px rgba(15,23,42,.06)}.card .num{font-size:26px;font-weight:800;margin-top:4px}.card .label{color:#64748b}.section{background:white;border:1px solid #e5e7eb;border-radius:16px;padding:18px;margin:16px 0;box-shadow:0 1px 3px rgba(15,23,42,.04)}.section h2{font-size:20px;margin:0 0 12px}.tip{background:#fff7ed;border:1px solid #fed7aa;border-radius:12px;padding:12px 14px;color:#7c2d12}.risk-high{color:#b91c1c;font-weight:700}.risk-mid{color:#b45309;font-weight:700}.risk-low{color:#047857;font-weight:700}.pill{display:inline-block;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:700;background:#eef2ff;color:#3730a3}.table-wrap{overflow:auto;border:1px solid #e5e7eb;border-radius:14px}table{width:100%;border-collapse:collapse;background:white;min-width:1180px}th,td{border-bottom:1px solid #e5e7eb;padding:10px 12px;text-align:left;vertical-align:top}th{background:#f8fafc;font-weight:700;white-space:nowrap}tr:hover{background:#f8fafc}.muted{color:#64748b}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;font-size:12px}.url{word-break:break-all}.summary{max-width:360px}.action{max-width:360px}.raw{white-space:pre-wrap;background:#0b1020;color:#e5e7eb;border-radius:10px;padding:12px;max-height:360px;overflow:auto;font-size:12px}details{margin-top:8px}summary{cursor:pointer;color:#2563eb;font-weight:600}.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px}.list{margin:0;padding-left:18px}.footer{color:#64748b;font-size:12px;margin-top:18px}
</style></head><body><div class="wrap">`)
	sb.WriteString("<div class=\"header\"><h1>Cloudflare 滥用报告</h1>")
	sb.WriteString(fmt.Sprintf("<p>生成时间：%s</p>", escapeHTML(now.Format("2006-01-02 15:04:05"))))
	sb.WriteString("<p>这份报告用于把 Cloudflare 后台的滥用投诉翻译成可排查的事项。它不等于最终判定违规，但需要尽快确认。</p></div>")

	sb.WriteString("<div class=\"cards\">")
	sb.WriteString(metricCard("新增报告", fmt.Sprintf("%d", len(reports))))
	sb.WriteString(metricCard("涉及账号", fmt.Sprintf("%d", len(accountCounts))))
	sb.WriteString(metricCard("高风险", fmt.Sprintf("%d", riskCounts["高"])))
	sb.WriteString(metricCard("中风险", fmt.Sprintf("%d", riskCounts["中"])))
	sb.WriteString("</div>")

	sb.WriteString("<div class=\"section\"><h2>怎么理解这类报告？</h2>")
	sb.WriteString("<div class=\"tip\">Cloudflare 收到外部用户、机构或自动系统对域名的投诉后，会在这里生成报告。常见原因包括：钓鱼仿冒、恶意跳转、欺诈广告落地页、恶意软件、垃圾内容或被盗用的页面。建议先检查报告域名当前访问页面、最近 DNS 变更、跳转链、广告素材和源站日志。</div>")
	sb.WriteString("</div>")

	sb.WriteString("<div class=\"section\"><h2>统计汇总</h2><div class=\"grid2\"><div><b>按账号</b><ul class=\"list\">")
	for _, key := range sortedStringKeys(accountCounts) {
		sb.WriteString(fmt.Sprintf("<li>%s：%d 条</li>", escapeHTML(key), accountCounts[key]))
	}
	sb.WriteString("</ul></div><div><b>按类型</b><ul class=\"list\">")
	for _, key := range sortedStringKeys(typeCounts) {
		sb.WriteString(fmt.Sprintf("<li>%s：%d 条</li>", escapeHTML(key), typeCounts[key]))
	}
	sb.WriteString("</ul></div></div>")
	if len(scanErrors) > 0 {
		sb.WriteString("<h3>扫描异常账号</h3><ul class=\"list\">")
		for _, item := range scanErrors {
			sb.WriteString(fmt.Sprintf("<li>%s：%s</li>", escapeHTML(displayAbuseValue(item.Source, "未知账号")), escapeHTML(compactAbuseText(item.Err.Error(), 220))))
		}
		sb.WriteString("</ul>")
	}
	sb.WriteString("</div>")

	sb.WriteString("<div class=\"section\"><h2>报告明细与排查建议</h2><div class=\"table-wrap\"><table><thead><tr>")
	for _, h := range []string{"风险", "账号", "域名", "白话说明", "可能原因", "建议处理", "报告信息", "证据/详情"} {
		sb.WriteString("<th>" + escapeHTML(h) + "</th>")
	}
	sb.WriteString("</tr></thead><tbody>")
	for _, report := range reports {
		insight := explainAbuseReport(report)
		riskClass := "risk-low"
		if insight.RiskLevel == "高" {
			riskClass = "risk-high"
		} else if insight.RiskLevel == "中" {
			riskClass = "risk-mid"
		}
		date := "未返回"
		if !report.Date.IsZero() {
			date = report.Date.Format("2006-01-02 15:04:05")
		}
		rawJSON := abuseRawJSON(report.Raw)
		sb.WriteString("<tr>")
		sb.WriteString(fmt.Sprintf("<td><span class=\"%s\">%s</span></td>", riskClass, escapeHTML(insight.RiskLevel)))
		sb.WriteString(fmt.Sprintf("<td>%s</td>", escapeHTML(displayAbuseValue(report.AccountLabel, "未知账号"))))
		sb.WriteString(fmt.Sprintf("<td><b>%s</b><br><span class=\"muted mono\">%s</span></td>", escapeHTML(displayAbuseValue(report.Domain, "未识别域名")), escapeHTML(firstNonEmpty(report.ID, abuseReportKey(report)))))
		sb.WriteString(fmt.Sprintf("<td class=\"summary\">%s<br><span class=\"pill\">%s</span></td>", escapeHTML(insight.PlainSummary), escapeHTML(insight.TypeLabel)))
		sb.WriteString(fmt.Sprintf("<td class=\"summary\">%s</td>", escapeHTML(insight.PossibleCause)))
		sb.WriteString(fmt.Sprintf("<td class=\"action\">%s</td>", escapeHTML(insight.Action)))
		sb.WriteString("<td>")
		sb.WriteString(fmt.Sprintf("日期：%s<br>状态：%s<br>Cloudflare处理：%s", escapeHTML(date), escapeHTML(humanAbuseStatus(report.Status)), escapeHTML(humanAbuseMitigation(report.Mitigation))))
		if report.Reporter != "" {
			sb.WriteString("<br>举报方：" + escapeHTML(report.Reporter))
		}
		sb.WriteString("</td>")
		sb.WriteString("<td class=\"url\">")
		if len(report.URLs) > 0 {
			for _, u := range report.URLs {
				sb.WriteString(escapeHTML(u) + "<br>")
			}
		} else {
			sb.WriteString("<span class=\"muted\">接口未返回证据 URL</span>")
		}
		if report.Title != "" || report.Summary != "" {
			sb.WriteString("<details><summary>查看原始摘要</summary>")
			if report.Title != "" {
				sb.WriteString("<b>标题：</b>" + escapeHTML(report.Title) + "<br>")
			}
			if report.Summary != "" {
				sb.WriteString("<b>摘要：</b>" + escapeHTML(report.Summary))
			}
			sb.WriteString("</details>")
		}
		if rawJSON != "" {
			sb.WriteString("<details><summary>查看 Cloudflare 原始字段</summary><pre class=\"raw\">" + escapeHTML(rawJSON) + "</pre></details>")
		}
		sb.WriteString("</td></tr>")
	}
	sb.WriteString("</tbody></table></div></div>")
	sb.WriteString("<div class=\"footer\">说明：风险等级是工具根据报告类型、状态、Cloudflare 缓解动作和报告内容自动归纳，最终以人工排查结果为准。</div>")
	sb.WriteString("</div></body></html>")

	if _, err := file.WriteString(sb.String()); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func explainAbuseReport(report cfclient.AbuseReportInfo) abuseReportInsight {
	typeLabel := humanAbuseType(report.ReportType)
	risk := abuseRiskLevel(report)
	domain := displayAbuseValue(report.Domain, "该域名")
	status := humanAbuseStatus(report.Status)
	mitigation := humanAbuseMitigation(report.Mitigation)
	rawHint := abuseRawHint(report)

	plain := fmt.Sprintf("%s 收到了 Cloudflare 的滥用投诉，当前状态是“%s”。", domain, status)
	if typeLabel != "未识别类型" {
		plain = fmt.Sprintf("%s 被举报为“%s”，当前状态是“%s”。", domain, typeLabel, status)
	}
	if mitigation != "未返回" {
		plain += fmt.Sprintf(" Cloudflare 侧处理状态：“%s”。", mitigation)
	}

	possible := "优先检查该域名的首页、落地页、跳转链、最近新增 DNS 记录、广告投放素材和源站访问日志。"
	action := "确认是否存在异常页面或恶意跳转；如确认误报，准备站点截图、业务说明和清理记录，通过 Cloudflare 后台申诉或标记已缓解。"

	lower := strings.ToLower(strings.Join([]string{report.ReportType, report.Title, report.Summary, rawHint}, " "))
	switch {
	case strings.Contains(lower, "phish") || strings.Contains(lower, "钓鱼"):
		possible = "举报方认为页面可能在仿冒品牌、诱导登录、收集账号密码或支付信息。"
		action = "立即打开报告 URL 核对页面；检查是否有仿冒登录框、充值页、客服链接、短链或异常跳转；必要时先暂停相关记录或下线落地页。"
	case strings.Contains(lower, "malware") || strings.Contains(lower, "virus") || strings.Contains(lower, "恶意"):
		possible = "举报方认为页面、下载文件或跳转链可能传播恶意软件、木马、病毒或高风险安装包。"
		action = "检查下载链接、安装包、第三方 JS、跳转链和源站文件；替换或删除可疑文件后再申诉。"
	case strings.Contains(lower, "spam") || strings.Contains(lower, "垃圾"):
		possible = "举报方认为该域名可能涉及垃圾内容、垃圾邮件、批量推广或滥发链接。"
		action = "检查站点内容、推广渠道、邮件发送记录和外链投放；清理异常内容并保留处理证据。"
	case strings.Contains(lower, "copyright") || strings.Contains(lower, "dmca") || strings.Contains(lower, "版权"):
		possible = "举报方可能认为页面存在版权、商标、素材或品牌侵权内容。"
		action = "检查页面素材、品牌词、Logo、文案和下载内容；如有侵权风险先替换或下线。"
	case strings.Contains(lower, "child") || strings.Contains(lower, "csam"):
		possible = "该类型高度敏感，可能涉及严重违法或高危内容。"
		action = "立即停止相关服务访问并升级给负责人处理；保留日志，按合规流程核查和处置。"
	case strings.Contains(lower, "gen") || strings.TrimSpace(report.ReportType) == "":
		possible = "Cloudflare 返回的是通用滥用类型，接口没有直接给出更细分类。常见原因仍可能是钓鱼、仿冒、恶意跳转、欺诈广告或违规内容。"
		action = "以附件里的证据 URL、原始摘要和 Cloudflare 后台详情为准，逐个打开域名核查页面内容、跳转目标和最近变更。"
	}
	if len(report.URLs) > 0 {
		possible += fmt.Sprintf(" 报告中包含 %d 个证据 URL，建议优先核查这些地址。", len(report.URLs))
	}
	if rawHint != "" && !strings.Contains(possible, rawHint) {
		possible += " 接口补充信息：" + compactAbuseText(rawHint, 180)
	}
	return abuseReportInsight{RiskLevel: risk, TypeLabel: typeLabel, PlainSummary: plain, PossibleCause: possible, Action: action, Evidence: strings.Join(report.URLs, "\n")}
}

func humanAbuseType(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return "未识别类型"
	}
	lower := strings.ToLower(v)
	switch {
	case lower == "gen" || lower == "general":
		return "通用滥用报告（GEN）"
	case strings.Contains(lower, "phish"):
		return "网络钓鱼/仿冒"
	case strings.Contains(lower, "malware") || strings.Contains(lower, "virus"):
		return "恶意软件/病毒"
	case strings.Contains(lower, "spam"):
		return "垃圾内容/垃圾推广"
	case strings.Contains(lower, "copyright") || strings.Contains(lower, "dmca"):
		return "版权/品牌投诉"
	case strings.Contains(lower, "child") || strings.Contains(lower, "csam"):
		return "严重敏感内容"
	case strings.Contains(lower, "abuse"):
		return "滥用投诉"
	default:
		return v
	}
}

func humanAbuseStatus(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return "未返回"
	}
	lower := strings.ToLower(v)
	switch lower {
	case "accepted":
		return "Cloudflare 已受理/接受"
	case "new", "open":
		return "新建/待处理"
	case "closed", "resolved":
		return "已关闭/已解决"
	case "rejected":
		return "已拒绝"
	case "pending":
		return "处理中/等待处理"
	default:
		return v
	}
}

func humanAbuseMitigation(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		return "未返回"
	}
	lower := strings.ToLower(v)
	if strings.Contains(lower, "active") || strings.Contains(lower, "活动") {
		return v + "（Cloudflare 已有处理动作处于活动中）"
	}
	return v
}

func abuseRiskLevel(report cfclient.AbuseReportInfo) string {
	lower := strings.ToLower(strings.Join([]string{report.ReportType, report.Title, report.Summary, report.Status, report.Mitigation, abuseRawHint(report)}, " "))
	if strings.Contains(lower, "child") || strings.Contains(lower, "csam") || strings.Contains(lower, "malware") || strings.Contains(lower, "phish") || strings.Contains(lower, "钓鱼") || strings.Contains(lower, "active") {
		return "高"
	}
	if strings.Contains(lower, "accepted") || strings.Contains(lower, "gen") || strings.Contains(lower, "spam") || strings.Contains(lower, "copyright") || strings.Contains(lower, "dmca") {
		return "中"
	}
	return "低"
}

func abuseRawHint(report cfclient.AbuseReportInfo) string {
	if len(report.Raw) == 0 {
		return ""
	}
	keys := []string{"reason", "category", "type", "report_type", "abuse_type", "title", "summary", "description", "message", "detail", "status", "mitigation", "action", "actions", "evidence", "notes"}
	parts := make([]string, 0)
	seen := map[string]struct{}{}
	collectRawStrings(report.Raw, keys, seen, &parts, 8)
	return compactAbuseText(strings.Join(parts, "；"), 500)
}

func collectRawStrings(raw map[string]any, keys []string, seen map[string]struct{}, out *[]string, max int) {
	if len(*out) >= max {
		return
	}
	keySet := map[string]struct{}{}
	for _, key := range keys {
		keySet[strings.ToLower(key)] = struct{}{}
	}
	for key, value := range raw {
		if len(*out) >= max {
			return
		}
		if _, ok := keySet[strings.ToLower(key)]; ok {
			text := compactAbuseText(stringFromAnyForAbuse(value), 220)
			if text != "" {
				entry := key + ": " + text
				if _, exists := seen[entry]; !exists {
					seen[entry] = struct{}{}
					*out = append(*out, entry)
				}
			}
		}
		if child, ok := value.(map[string]any); ok {
			collectRawStrings(child, keys, seen, out, max)
		}
		if arr, ok := value.([]any); ok {
			for _, item := range arr {
				if child, ok := item.(map[string]any); ok {
					collectRawStrings(child, keys, seen, out, max)
				}
			}
		}
	}
}

func stringFromAnyForAbuse(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	case []any:
		parts := make([]string, 0, len(x))
		for _, item := range x {
			if text := stringFromAnyForAbuse(item); text != "" {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		for _, key := range []string{"title", "name", "type", "value", "status", "description", "message", "url"} {
			if text := stringFromAnyForAbuse(x[key]); text != "" {
				return text
			}
		}
		return ""
	default:
		return ""
	}
}

func abuseRawJSON(raw map[string]any) string {
	if len(raw) == 0 {
		return ""
	}
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}

func sortedStringKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func metricCard(label, value string) string {
	return fmt.Sprintf("<div class=\"card\"><div class=\"label\">%s</div><div class=\"num\">%s</div></div>", escapeHTML(label), escapeHTML(value))
}

func escapeHTML(value string) string {
	return html.EscapeString(strings.TrimSpace(value))
}
func BuildAbuseReportCSV(reports []cfclient.AbuseReportInfo, now time.Time) (string, func(), error) {
	file, err := os.CreateTemp("", fmt.Sprintf("cf_abuse_reports_%s_*.csv", now.Format("20060102_150405")))
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	cleanup := func() { _ = os.Remove(path) }

	if _, err := file.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	writer := csv.NewWriter(file)
	_ = writer.Write([]string{"账号平台", "报告ID", "日期", "域名", "报告类型", "状态", "Cloudflare缓解措施", "标题", "摘要", "报告URL", "Reporter", "AccountID"})
	for _, report := range reports {
		date := ""
		if !report.Date.IsZero() {
			date = report.Date.Format(time.RFC3339)
		}
		_ = writer.Write([]string{
			report.AccountLabel,
			firstNonEmpty(report.ID, abuseReportKey(report)),
			date,
			report.Domain,
			report.ReportType,
			report.Status,
			report.Mitigation,
			report.Title,
			report.Summary,
			strings.Join(report.URLs, "\n"),
			report.Reporter,
			report.AccountID,
		})
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		file.Close()
		cleanup()
		return "", func() {}, err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return "", func() {}, err
	}
	return path, cleanup, nil
}

func loadAbuseReportCache(path string) (AbuseReportCache, error) {
	cache := AbuseReportCache{Version: 1, Reports: map[string]AbuseReportCacheItem{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cache, nil
		}
		return cache, fmt.Errorf("读取滥用报告缓存失败: %w", err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return cache, nil
	}
	if err := json.Unmarshal(data, &cache); err != nil {
		return cache, fmt.Errorf("解析滥用报告缓存失败: %w", err)
	}
	if cache.Reports == nil {
		cache.Reports = map[string]AbuseReportCacheItem{}
	}
	if cache.Version == 0 {
		cache.Version = 1
	}
	return cache, nil
}

func saveAbuseReportCache(path string, cache AbuseReportCache) error {
	if strings.TrimSpace(path) == "" {
		path = "abuse_report_cache.json"
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建滥用报告缓存目录失败: %w", err)
		}
	}
	cache.Version = 1
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化滥用报告缓存失败: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("写入滥用报告缓存失败: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("替换滥用报告缓存失败: %w", err)
	}
	return nil
}

func fillAbuseCacheItem(item *AbuseReportCacheItem, report cfclient.AbuseReportInfo, now time.Time) {
	item.ID = report.ID
	item.Source = report.AccountLabel
	item.AccountID = report.AccountID
	item.Domain = report.Domain
	item.ReportType = report.ReportType
	item.Status = report.Status
	item.Mitigation = report.Mitigation
	item.Title = report.Title
	item.Summary = report.Summary
	item.Date = report.Date
	if item.FirstSeenAt.IsZero() {
		item.FirstSeenAt = now
	}
	item.LastSeenAt = now
}

func abuseReportKey(report cfclient.AbuseReportInfo) string {
	source := strings.TrimSpace(report.AccountLabel)
	if source == "" {
		source = strings.TrimSpace(report.AccountID)
	}
	id := strings.TrimSpace(report.ID)
	if id != "" {
		return source + ":" + id
	}
	base := strings.Join([]string{
		source,
		strings.TrimSpace(report.Domain),
		strings.TrimSpace(report.ReportType),
		report.Date.Format(time.RFC3339Nano),
		strings.TrimSpace(report.Title),
		strings.TrimSpace(report.Summary),
		strings.Join(report.URLs, ","),
	}, "|")
	sum := sha256.Sum256([]byte(base))
	return source + ":sha256:" + hex.EncodeToString(sum[:])[:16]
}

func sortAbuseReports(reports []cfclient.AbuseReportInfo) {
	sort.SliceStable(reports, func(i, j int) bool {
		if !reports[i].Date.Equal(reports[j].Date) {
			return reports[i].Date.After(reports[j].Date)
		}
		if reports[i].AccountLabel != reports[j].AccountLabel {
			return reports[i].AccountLabel < reports[j].AccountLabel
		}
		return reports[i].Domain < reports[j].Domain
	})
}

func displayAbuseValue(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func compactAbuseText(value string, max int) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if max <= 0 || len([]rune(value)) <= max {
		return value
	}
	runes := []rune(value)
	return string(runes[:max]) + "..."
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
