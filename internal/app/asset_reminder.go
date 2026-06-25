package app

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"DomainC/reminder"
	"DomainC/telegram"
)

type AssetReminderService struct {
	Runtime   *reminder.Runtime
	Sender    telegram.Sender
	AlertDays int
}

func (s *AssetReminderService) RunDaily(ctx context.Context) error {
	if s == nil || s.Runtime == nil || s.Sender == nil {
		return ErrMissingDependencies
	}
	now := time.Now()
	alertDays := reminder.EffectiveAlertDays(s.AlertDays)
	if err := s.Runtime.RefreshCandidates(ctx, alertDays, now); err != nil {
		log.Printf("[reminder] refresh_candidates_failed err=%v", err)
	}
	alerts, err := s.Runtime.DueAlerts(alertDays, now)
	if err != nil {
		return err
	}

	summary, err := BuildAssetSummary(s.Runtime.Store())
	if err != nil {
		return err
	}

	reportPath, caption, cleanup, err := BuildAssetReportFile(s.Runtime.Store(), alerts, alertDays, now)
	if err != nil {
		return err
	}
	defer cleanup()

	msg := FormatAssetDailyMessageWithSummary(alerts, summary, alertDays, now)
	if err := s.Sender.Send(ctx, msg); err != nil {
		return err
	}
	if strings.TrimSpace(reportPath) != "" {
		if err := s.Sender.SendDocumentPath(ctx, reportPath, caption); err != nil {
			return err
		}
	}
	return s.Runtime.MarkAlertsSent(alerts, now)
}

func FormatAssetDailyMessage(alerts []reminder.Alert, alertDays int, now time.Time) string {
	return FormatAssetDailyMessageWithSummary(alerts, AssetSummary{}, alertDays, now)
}

func FormatAssetDailyMessageWithSummary(alerts []reminder.Alert, summary AssetSummary, alertDays int, now time.Time) string {
	alertDays = reminder.EffectiveAlertDays(alertDays)
	domainCount, certCount := countAssetAlerts(alerts)

	var sb strings.Builder
	sb.WriteString("【到期提醒日报】")
	sb.WriteString(fmt.Sprintf("\n提醒阈值: 到期前 %d 天", alertDays))
	sb.WriteString(fmt.Sprintf("\n检查日期: %s", now.Format("2006-01-02")))

	if len(alerts) == 0 {
		sb.WriteString("\n\n今日没有域名续费或 SSL 证书到期资源。")
		sb.WriteString(fmt.Sprintf("\n当前缓存域名: %d 个", summary.TotalDomains))
		if summary.TotalAccountLinks > 0 && summary.TotalAccountLinks != summary.TotalDomains {
			sb.WriteString(fmt.Sprintf("；账户归属: %d 条", summary.TotalAccountLinks))
		}
		if summary.MultiAccountDomains > 0 {
			sb.WriteString(fmt.Sprintf("；多账户域名: %d 个", summary.MultiAccountDomains))
		}
		if summary.TotalCertificates > 0 {
			sb.WriteString(fmt.Sprintf("；SSL 证书记录: %d 条", summary.TotalCertificates))
		}
		if len(summary.SourceCounts) > 0 {
			sb.WriteString("\n\n按账户平台统计:")
			for _, item := range summary.SourceCounts {
				sb.WriteString(fmt.Sprintf("\n- %s: %d 个域名", displaySource(item.Source), item.Domains))
				if item.UnknownDomains > 0 {
					sb.WriteString(fmt.Sprintf("（未知账户 %d 个）", item.UnknownDomains))
				}
				if item.Certificates > 0 {
					sb.WriteString(fmt.Sprintf("，%d 条证书记录", item.Certificates))
				}
			}
		}
		sb.WriteString("\n\n详细全量资产 CSV 请参阅附件。")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("\n\n发现临近到期/已到期资源: %d 项", len(alerts)))
	sb.WriteString(fmt.Sprintf("\n- 域名续费到期: %d 个", domainCount))
	sb.WriteString(fmt.Sprintf("\n- SSL 证书到期: %d 个", certCount))
	sb.WriteString("\n详细到期清单请参阅附件。")
	return sb.String()
}

// FormatAssetAlerts 保留给旧测试或外部调用；现在每日通知使用 FormatAssetDailyMessage。
func FormatAssetAlerts(alerts []reminder.Alert, alertDays int, now time.Time) string {
	return FormatAssetDailyMessage(alerts, alertDays, now)
}

func countAssetAlerts(alerts []reminder.Alert) (domainCount int, certCount int) {
	for _, alert := range alerts {
		switch alert.Type {
		case reminder.AlertTypeDomainExpiry:
			domainCount++
		case reminder.AlertTypeCertificate:
			certCount++
		}
	}
	return domainCount, certCount
}

func formatDaysLeft(days int) string {
	if days > 0 {
		return fmt.Sprintf("%d 天", days)
	}
	if days == 0 {
		return "今天到期"
	}
	return fmt.Sprintf("已过期 %d 天", -days)
}

func compactIssuer(issuer string) string {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return ""
	}
	parts := strings.Split(issuer, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "CN=") && len(part) > 3 {
			return strings.TrimPrefix(part, "CN=")
		}
	}
	if len(issuer) > 80 {
		return issuer[:80] + "..."
	}
	return issuer
}
