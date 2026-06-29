package app

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

	reportPath, cleanup, err := BuildAbuseReportCSV(newReports, now)
	if err != nil {
		log.Printf("[abuse_report] build_csv_failed err=%v", err)
	} else {
		defer cleanup()
		caption := fmt.Sprintf("%s: Cloudflare 新增滥用报告 %d 条", now.Format("2006-01-02"), len(newReports))
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

	accountCounts := map[string]int{}
	for _, report := range reports {
		accountCounts[displayAbuseValue(report.AccountLabel, "未知账号")]++
	}
	if len(accountCounts) > 0 {
		sb.WriteString("\n\n按账号统计:")
		keys := make([]string, 0, len(accountCounts))
		for k := range accountCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			sb.WriteString(fmt.Sprintf("\n- %s: %d 条", key, accountCounts[key]))
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

	sb.WriteString("\n\n报告摘要:")
	limit := len(reports)
	if limit > 10 {
		limit = 10
	}
	for i := 0; i < limit; i++ {
		report := reports[i]
		sb.WriteString(fmt.Sprintf("\n\n%d. 域名: %s", i+1, displayAbuseValue(report.Domain, "未识别")))
		sb.WriteString(fmt.Sprintf("\n   账号: %s", displayAbuseValue(report.AccountLabel, "未知账号")))
		sb.WriteString(fmt.Sprintf("\n   报告ID: %s", displayAbuseValue(report.ID, abuseReportKey(report))))
		if !report.Date.IsZero() {
			sb.WriteString(fmt.Sprintf("\n   日期: %s", report.Date.Format("2006-01-02 15:04:05")))
		}
		sb.WriteString(fmt.Sprintf("\n   类型: %s", displayAbuseValue(report.ReportType, "未识别")))
		if strings.TrimSpace(report.Status) != "" {
			sb.WriteString(fmt.Sprintf("\n   状态: %s", report.Status))
		}
		if strings.TrimSpace(report.Mitigation) != "" {
			sb.WriteString(fmt.Sprintf("\n   Cloudflare 缓解措施: %s", compactAbuseText(report.Mitigation, 120)))
		}
		summary := firstNonEmpty(report.Title, report.Summary)
		if strings.TrimSpace(summary) != "" {
			sb.WriteString(fmt.Sprintf("\n   摘要: %s", compactAbuseText(summary, 180)))
		}
		if len(report.URLs) > 0 {
			sb.WriteString(fmt.Sprintf("\n   URL: %s", compactAbuseText(strings.Join(report.URLs, ", "), 180)))
		}
	}
	if len(reports) > limit {
		sb.WriteString(fmt.Sprintf("\n\n其余 %d 条请查看附件 CSV。", len(reports)-limit))
	} else {
		sb.WriteString("\n\n详细字段请查看附件 CSV。")
	}
	return sb.String()
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
