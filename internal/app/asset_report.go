package app

import (
	"encoding/csv"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"time"

	"DomainC/reminder"
)

type assetReportRow struct {
	Source           string
	AccountCount     string
	Domain           string
	ResourceType     string
	ResourceName     string
	Expiry           string
	DaysLeft         string
	Status           string
	CertType         string
	CertID           string
	Issuer           string
	Subject          string
	Hostnames        string
	LastRefreshAt    string
	LastRefreshError string
}

// AssetSummary 汇总当前本地缓存中的资产规模，用于无到期日报摘要。
type AssetSummary struct {
	TotalDomains        int
	TotalAccountLinks   int
	MultiAccountDomains int
	TotalCertificates   int
	SourceCounts        []AssetSourceCount
}

// AssetSourceCount 表示单个账户平台下的域名和证书数量。
type AssetSourceCount struct {
	Source         string
	Domains        int
	Certificates   int
	UnknownDomains int
}

func BuildAssetSummary(store *reminder.Store) (AssetSummary, error) {
	if store == nil {
		return AssetSummary{}, ErrMissingDependencies
	}
	records, err := store.ListActive()
	if err != nil {
		return AssetSummary{}, err
	}

	bySource := map[string]*AssetSourceCount{}
	summary := AssetSummary{TotalDomains: len(records)}
	for _, rec := range records {
		accounts := reminder.RecordAccounts(rec)
		if len(accounts) == 0 {
			accounts = []reminder.AccountRecord{{Source: displaySource(rec.Source)}}
		}
		if len(accounts) > 1 {
			summary.MultiAccountDomains++
		}
		summary.TotalCertificates += len(rec.Certificates)
		for _, acc := range accounts {
			source := displaySource(acc.Source)
			item := bySource[source]
			if item == nil {
				item = &AssetSourceCount{Source: source}
				bySource[source] = item
			}
			item.Domains++
			item.Certificates += len(rec.Certificates)
			if acc.Unknown || strings.TrimSpace(acc.Status) == reminder.StatusUnknownAccount {
				item.UnknownDomains++
			}
			summary.TotalAccountLinks++
		}
	}

	for _, item := range bySource {
		summary.SourceCounts = append(summary.SourceCounts, *item)
	}
	sort.Slice(summary.SourceCounts, func(i, j int) bool {
		if summary.SourceCounts[i].Domains == summary.SourceCounts[j].Domains {
			return summary.SourceCounts[i].Source < summary.SourceCounts[j].Source
		}
		return summary.SourceCounts[i].Domains > summary.SourceCounts[j].Domains
	})
	return summary, nil
}

func BuildAssetReportFile(store *reminder.Store, alerts []reminder.Alert, alertDays int, now time.Time) (path string, caption string, cleanup func(), err error) {
	cleanup = func() {}
	if store == nil {
		return "", "", cleanup, ErrMissingDependencies
	}
	alertDays = reminder.EffectiveAlertDays(alertDays)
	if now.IsZero() {
		now = time.Now()
	}

	var rows []assetReportRow
	var title string
	var subtitle string
	var filenamePrefix string
	if len(alerts) == 0 {
		title = "域名与证书资产日报"
		subtitle = fmt.Sprintf("今日没有域名续费或 SSL 证书到期资源；以下为当前缓存中的全部资产数据。提醒阈值：到期前 %d 天。", alertDays)
		filenamePrefix = "asset_reminder_all"
		rows, err = buildAllAssetRows(store, now)
		caption = fmt.Sprintf("%s：无到期资源，详见全量资产 CSV", now.Format("2006-01-02"))
	} else {
		domainCount, certCount := countAssetAlerts(alerts)
		title = "域名与证书到期提醒"
		subtitle = fmt.Sprintf("发现临近到期/已到期资源 %d 项，其中域名续费 %d 个，SSL 证书 %d 个。提醒阈值：到期前 %d 天。", len(alerts), domainCount, certCount, alertDays)
		filenamePrefix = "asset_reminder_due"
		rows, err = buildDueAssetRows(store, alerts, now)
		caption = fmt.Sprintf("%s：到期资源 %d 项，详见附件", now.Format("2006-01-02"), len(alerts))
	}
	if err != nil {
		return "", "", cleanup, err
	}

	if len(alerts) == 0 {
		csvPath, csvErr := writeAssetCSVReport(filenamePrefix, rows, now)
		if csvErr == nil {
			return csvPath, caption, func() { _ = os.Remove(csvPath) }, nil
		}
		reportPath, htmlErr := writeAssetHTMLReport(filenamePrefix, title, subtitle, rows, now)
		if htmlErr != nil {
			return "", "", cleanup, fmt.Errorf("生成 CSV 附件失败: %v; 生成 HTML 附件失败: %w", csvErr, htmlErr)
		}
		return reportPath, caption + "（CSV 生成失败，已降级为 HTML）", func() { _ = os.Remove(reportPath) }, nil
	}

	reportPath, err := writeAssetHTMLReport(filenamePrefix, title, subtitle, rows, now)
	if err == nil {
		return reportPath, caption, func() { _ = os.Remove(reportPath) }, nil
	}

	csvPath, csvErr := writeAssetCSVReport(filenamePrefix, rows, now)
	if csvErr != nil {
		return "", "", cleanup, fmt.Errorf("生成 HTML 附件失败: %v; 生成 CSV 附件失败: %w", err, csvErr)
	}
	return csvPath, caption + "（HTML 生成失败，已降级为 CSV）", func() { _ = os.Remove(csvPath) }, nil
}

func buildAllAssetRows(store *reminder.Store, now time.Time) ([]assetReportRow, error) {
	records, err := store.ListActive()
	if err != nil {
		return nil, err
	}
	rows := make([]assetReportRow, 0, len(records)*2)
	for _, rec := range records {
		rows = append(rows, domainRowFromRecord(rec, now))
		for _, cert := range rec.Certificates {
			rows = append(rows, certRowFromRecord(rec, cert, now))
		}
	}
	sortAssetRows(rows)
	return rows, nil
}

func buildDueAssetRows(store *reminder.Store, alerts []reminder.Alert, now time.Time) ([]assetReportRow, error) {
	cache, err := store.Load()
	if err != nil {
		return nil, err
	}
	records := map[string]*reminder.Record{}
	for key, rec := range cache.Records {
		if rec != nil {
			records[key] = rec
		}
	}

	rows := make([]assetReportRow, 0, len(alerts))
	for _, alert := range alerts {
		row := alertRow(alert)
		if rec := records[reminder.RecordKey(alert.Source, alert.Domain)]; rec != nil {
			row.Source = displaySource(reminder.RecordSourceDisplay(*rec))
			row.AccountCount = accountCountText(*rec)
			row.LastRefreshAt = rec.LastRefreshAt
			row.LastRefreshError = rec.LastRefreshError
			if row.Status == "" {
				row.Status = recordStatus(*rec)
			}
		}
		rows = append(rows, row)
	}
	sortAssetRows(rows)
	return rows, nil
}

func domainRowFromRecord(rec reminder.Record, now time.Time) assetReportRow {
	row := assetReportRow{
		Source:           displaySource(reminder.RecordSourceDisplay(rec)),
		AccountCount:     accountCountText(rec),
		Domain:           rec.Domain,
		ResourceType:     "域名续费",
		ResourceName:     "域名注册/续费",
		Expiry:           displayValue(rec.DomainExpiry),
		Status:           recordStatus(rec),
		LastRefreshAt:    rec.LastRefreshAt,
		LastRefreshError: rec.LastRefreshError,
	}
	if t, ok := reminder.ParseTimeValue(rec.DomainExpiry); ok {
		row.DaysLeft = formatDaysLeft(reminder.DaysUntil(t, now))
	}
	return row
}

func certRowFromRecord(rec reminder.Record, cert reminder.CertificateRecord, now time.Time) assetReportRow {
	row := assetReportRow{
		Source:           displaySource(reminder.RecordSourceDisplay(rec)),
		AccountCount:     accountCountText(rec),
		Domain:           rec.Domain,
		ResourceType:     "SSL 证书",
		ResourceName:     certificateDisplayName(cert),
		Expiry:           displayDateTime(cert.NotAfter),
		CertType:         displayCertType(cert.Type),
		CertID:           cert.ID,
		Issuer:           compactIssuer(cert.Issuer),
		Subject:          cert.Subject,
		Hostnames:        strings.Join(cert.Hostnames, ", "),
		Status:           recordStatus(rec),
		LastRefreshAt:    rec.LastRefreshAt,
		LastRefreshError: rec.LastRefreshError,
	}
	if t, ok := reminder.ParseTimeValue(cert.NotAfter); ok {
		row.DaysLeft = formatDaysLeft(reminder.DaysUntil(t, now))
	}
	return row
}

func alertRow(alert reminder.Alert) assetReportRow {
	row := assetReportRow{
		Source:       displaySource(alert.Source),
		AccountCount: "1",
		Domain:       alert.Domain,
		Expiry:       alert.Expiry.Format("2006-01-02 15:04:05"),
		DaysLeft:     formatDaysLeft(alert.DaysLeft),
		Status:       "待处理",
		CertType:     displayCertType(alert.CertType),
		CertID:       alert.CertID,
		Issuer:       compactIssuer(alert.Issuer),
		Subject:      alert.Subject,
		Hostnames:    strings.Join(alert.Hostnames, ", "),
		ResourceName: strings.TrimSpace(alert.Description),
	}
	if row.ResourceName == "" {
		row.ResourceName = "SSL 证书"
	}
	if alert.Type == reminder.AlertTypeDomainExpiry {
		row.ResourceType = "域名续费"
		row.ResourceName = "域名注册/续费"
		row.Expiry = alert.Expiry.Format("2006-01-02")
	} else {
		row.ResourceType = "SSL 证书"
	}
	return row
}

func writeAssetHTMLReport(prefix string, title string, subtitle string, rows []assetReportRow, now time.Time) (string, error) {
	file, err := os.CreateTemp("", fmt.Sprintf("%s_%s_*.html", prefix, now.Format("20060102")))
	if err != nil {
		return "", err
	}
	defer file.Close()

	var sb strings.Builder
	sb.WriteString("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
	sb.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	sb.WriteString("<title>")
	sb.WriteString(html.EscapeString(title))
	sb.WriteString("</title>")
	sb.WriteString(`<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,"Noto Sans SC",sans-serif;margin:24px;background:#f7f7f8;color:#1f2937;}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:20px;box-shadow:0 1px 2px rgba(0,0,0,.04);}
h1{font-size:22px;margin:0 0 8px;}p{margin:6px 0 16px;color:#4b5563;}table{width:100%;border-collapse:collapse;background:#fff;font-size:14px;}th,td{border:1px solid #e5e7eb;padding:8px 10px;text-align:left;vertical-align:top;}th{background:#f3f4f6;position:sticky;top:0;}tr:nth-child(even){background:#fafafa;}.muted{color:#6b7280}.warn{font-weight:600;color:#b45309}.err{color:#b91c1c;}.nowrap{white-space:nowrap;}.scroll{overflow:auto;max-height:78vh;}
</style></head><body><div class="card">`)
	sb.WriteString("<h1>")
	sb.WriteString(html.EscapeString(title))
	sb.WriteString("</h1><p>")
	sb.WriteString(html.EscapeString(subtitle))
	sb.WriteString("</p><p class=\"muted\">生成时间：")
	sb.WriteString(html.EscapeString(now.Format("2006-01-02 15:04:05")))
	sb.WriteString("</p>")
	if len(rows) == 0 {
		sb.WriteString("<p class=\"muted\">缓存中暂无可展示资产。</p>")
	} else {
		sb.WriteString("<div class=\"scroll\"><table><thead><tr>")
		for _, h := range assetReportHeaders() {
			sb.WriteString("<th>")
			sb.WriteString(html.EscapeString(h))
			sb.WriteString("</th>")
		}
		sb.WriteString("</tr></thead><tbody>")
		for _, row := range rows {
			sb.WriteString("<tr>")
			for i, v := range rowValues(row) {
				className := ""
				if i == 6 && (strings.Contains(v, "已过期") || strings.Contains(v, "今天到期")) {
					className = " class=\"warn nowrap\""
				} else if i == 14 && strings.TrimSpace(v) != "" {
					className = " class=\"err\""
				} else if i == 5 || i == 6 || i == 13 {
					className = " class=\"nowrap\""
				}
				sb.WriteString("<td")
				sb.WriteString(className)
				sb.WriteString(">")
				sb.WriteString(html.EscapeString(v))
				sb.WriteString("</td>")
			}
			sb.WriteString("</tr>")
		}
		sb.WriteString("</tbody></table></div>")
	}
	sb.WriteString("</div></body></html>")
	if _, err := file.WriteString(sb.String()); err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}

func writeAssetCSVReport(prefix string, rows []assetReportRow, now time.Time) (string, error) {
	if now.IsZero() {
		now = time.Now()
	}
	file, err := os.CreateTemp("", fmt.Sprintf("%s_%s_*.csv", prefix, now.Format("20060102")))
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	writer := csv.NewWriter(file)
	if err := writer.Write(assetReportHeaders()); err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	for _, row := range rows {
		if err := writer.Write(rowValues(row)); err != nil {
			_ = os.Remove(file.Name())
			return "", err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}

func assetReportHeaders() []string {
	return []string{
		"账户平台", "账户数", "域名", "资源类型", "资源名称", "到期时间", "剩余时间", "状态",
		"证书类型", "证书ID", "签发方", "证书主体", "证书域名", "最后刷新时间", "刷新错误",
	}
}

func rowValues(row assetReportRow) []string {
	return []string{
		row.Source,
		row.AccountCount,
		row.Domain,
		row.ResourceType,
		row.ResourceName,
		row.Expiry,
		row.DaysLeft,
		row.Status,
		row.CertType,
		row.CertID,
		row.Issuer,
		row.Subject,
		row.Hostnames,
		row.LastRefreshAt,
		row.LastRefreshError,
	}
}

func sortAssetRows(rows []assetReportRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Source != rows[j].Source {
			return rows[i].Source < rows[j].Source
		}
		if rows[i].Domain != rows[j].Domain {
			return rows[i].Domain < rows[j].Domain
		}
		if rows[i].ResourceType != rows[j].ResourceType {
			return rows[i].ResourceType < rows[j].ResourceType
		}
		return rows[i].Expiry < rows[j].Expiry
	})
}

func displaySource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "未标记"
	}
	return source
}

func displayValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "未知"
	}
	return value
}

func displayDateTime(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "未知"
	}
	if t, ok := reminder.ParseTimeValue(value); ok {
		return t.Format("2006-01-02 15:04:05")
	}
	return value
}

func displayCertType(typ string) string {
	switch strings.TrimSpace(typ) {
	case reminder.CertTypeCFOrigin:
		return "Cloudflare Origin CA"
	case reminder.CertTypeServed:
		return "当前访问证书"
	case "":
		return ""
	default:
		return typ
	}
}

func certificateDisplayName(cert reminder.CertificateRecord) string {
	switch cert.Type {
	case reminder.CertTypeCFOrigin:
		return "Cloudflare Origin CA 源站证书"
	case reminder.CertTypeServed:
		issuer := strings.ToLower(cert.Issuer)
		if strings.Contains(issuer, "cloudflare") {
			return "当前访问证书/Cloudflare 边缘证书"
		}
		return "当前访问证书/三方签发证书"
	default:
		return "SSL 证书"
	}
}

func accountCountText(rec reminder.Record) string {
	count := len(reminder.RecordAccounts(rec))
	if count <= 0 {
		return "1"
	}
	return fmt.Sprintf("%d", count)
}

func recordStatus(rec reminder.Record) string {
	var parts []string
	accounts := reminder.RecordAccounts(rec)
	if rec.PendingRefresh {
		parts = append(parts, "待补全")
	}
	if rec.IsCF {
		parts = append(parts, "Cloudflare")
	}
	if len(accounts) > 1 {
		parts = append(parts, "多账户")
	}
	var unknown []string
	for _, acc := range accounts {
		if acc.Unknown || strings.TrimSpace(acc.Status) == reminder.StatusUnknownAccount {
			unknown = append(unknown, acc.Source)
		}
	}
	if len(unknown) > 0 {
		parts = append(parts, "未知账户:"+strings.Join(unknown, ","))
	}
	status := strings.TrimSpace(rec.Status)
	if status != "" && status != reminder.StatusUnknownAccount && !strings.Contains(status, "多账户") && !strings.Contains(status, "部分未知账户") {
		parts = append(parts, status)
	}
	if rec.Paused {
		parts = append(parts, "paused")
	}
	if len(parts) == 0 {
		return "已缓存"
	}
	return strings.Join(parts, "/")
}
