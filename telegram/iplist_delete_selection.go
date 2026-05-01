package telegram

import (
	"context"
	"fmt"
	"strings"
	"time"

	"DomainC/cfclient"
	"DomainC/config"
)

type IPListDeleteResult struct {
	AccountLabel string
	Success      []IPListDeleteItem
	Failed       []string
}

func (r IPListDeleteResult) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("✅ IP 白名单删除完成\n账号: %s\n成功: %d", r.AccountLabel, len(r.Success)))
	if len(r.Failed) > 0 {
		sb.WriteString(fmt.Sprintf("\n失败: %d", len(r.Failed)))
		for _, item := range r.Failed {
			sb.WriteString("\n- " + item)
		}
	}
	return sb.String()
}

func ProcessIPListDeleteItems(ctx context.Context, client cfclient.Client, account config.CF, items []IPListDeleteItem) IPListDeleteResult {
	result := IPListDeleteResult{AccountLabel: account.Label}
	if client == nil {
		client = cfclient.NewClient()
	}

	pacer := newBatchAPIPacerWithInterval(1200 * time.Millisecond)
	for _, item := range items {
		if err := pacer.Wait(ctx); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: 等待执行失败: %v", item.IP, err))
			continue
		}

		if err := deleteCustomListItemWithRetry(ctx, client, account, item); err != nil {
			result.Failed = append(result.Failed, fmt.Sprintf("%s: %v", item.IP, err))
			continue
		}
		result.Success = append(result.Success, item)
	}
	return result
}

func deleteCustomListItemWithRetry(ctx context.Context, client cfclient.Client, account config.CF, item IPListDeleteItem) error {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		_, err := client.DeleteCustomListItem(ctx, account, item.ListID, item.ItemID)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableCloudflareError(err) || attempt == 2 {
			break
		}

		timer := time.NewTimer(time.Duration(attempt+1) * 3 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

func isRetryableCloudflareError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "429") ||
		strings.Contains(msg, "rate limit") ||
		strings.Contains(msg, "too many requests") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "temporary") ||
		strings.Contains(msg, "temporarily") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "internal server error") ||
		strings.Contains(msg, " 500") ||
		strings.Contains(msg, " 502") ||
		strings.Contains(msg, " 503") ||
		strings.Contains(msg, " 504")
}
